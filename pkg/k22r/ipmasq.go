/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package k22r

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"
)

const (
	linkLocalCIDR = "169.254.0.0/16"
)

var (
	// name of nat chain for iptables masquerade rules
	masqChain   = utiliptables.Chain("IP-MASQ-K22R")
	randomFully = false
)

// MasqConfig object
type MasqConfig struct {
	NonMasqueradeCIDRs []string `json:"nonMasqueradeCIDRs"`
	CidrLimit          int      `json:"cidrLimit"`
	MasqLinkLocal      bool     `json:"masqLinkLocal"`
	MasqLinkLocalIPv6  bool     `json:"masqLinkLocalIPv6"`
	ResyncInterval     Duration `json:"resyncInterval"`
}

// Duration - Go's JSON unmarshaler can't handle time.ParseDuration syntax when unmarshaling into time.Duration, so we do it here
type Duration time.Duration

// NewMasqConfig returns a MasqConfig with default values
func NewMasqConfig(masqAllReservedRanges bool) *MasqConfig {
	// RFC 1918 defines the private ip address space as 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	nonMasq := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

	if masqAllReservedRanges {
		nonMasq = append(nonMasq,
			"100.64.0.0/10",   // RFC 6598
			"192.0.0.0/24",    // RFC 6890
			"192.0.2.0/24",    // RFC 5737
			"192.88.99.0/24",  // RFC 7526
			"198.18.0.0/15",   // RFC 6815
			"198.51.100.0/24", // RFC 5737
			"203.0.113.0/24",  // RFC 5737
			"240.0.0.0/4")     // RFC 5735, Former Class E range obsoleted by RFC 3232
	}

	return &MasqConfig{
		NonMasqueradeCIDRs: nonMasq,
		CidrLimit:          64,
		MasqLinkLocal:      false,
		ResyncInterval:     Duration(60 * time.Second),
	}
}

// MasqDaemon object
type MasqDaemon struct {
	config   *MasqConfig
	iptables utiliptables.Interface
}

// NewMasqDaemon returns a MasqDaemon with default values, including an initialized utiliptables.Interface
func NewMasqDaemon(c *MasqConfig) *MasqDaemon {
	execer := utilexec.New()
	protocolv4 := utiliptables.ProtocolIPv4
	iptables := utiliptables.New(execer, protocolv4)
	return &MasqDaemon{
		config:   c,
		iptables: iptables,
	}
}

// Run ...
func (m *MasqDaemon) Run() {
	// Periodically resync to reconfigure or heal from any rule decay
	for {
		func() {
			defer time.Sleep(time.Duration(m.config.ResyncInterval))

			// resync rules
			if err := m.syncMasqRules(); err != nil {
				log.Fatalf("error syncing masquerade rules: %v", err)
				return
			}

		}()
	}
}

func (m *MasqDaemon) syncMasqRules() error {
	// make sure our custom chain for non-masquerade exists
	if _, err := m.iptables.EnsureChain(utiliptables.TableNAT, masqChain); err != nil {
		return err
	}

	// ensure that any non-local in POSTROUTING jumps to masqChain
	if err := m.ensurePostroutingJump(); err != nil {
		return err
	}

	// build up lines to pass to iptables-restore
	lines := bytes.NewBuffer(nil)
	writeLine(lines, "*nat")
	writeLine(lines, utiliptables.MakeChainLine(masqChain)) // effectively flushes masqChain atomically with rule restore

	// link-local CIDR is always non-masquerade
	if !m.config.MasqLinkLocal {
		writeNonMasqRule(lines, linkLocalCIDR)
	}

	// non-masquerade for user-provided CIDRs
	for _, cidr := range m.config.NonMasqueradeCIDRs {
		if !isIPv6CIDR(cidr) {
			writeNonMasqRule(lines, cidr)
		}
	}

	// masquerade all other traffic that is not bound for a --dst-type LOCAL destination
	writeMasqRule(lines)

	writeLine(lines, "COMMIT")

	fmt.Println(lines)

	if err := m.iptables.RestoreAll(lines.Bytes(), utiliptables.NoFlushTables, utiliptables.NoRestoreCounters); err != nil {
		return err
	}
	return nil
}

// NOTE(mtaufen): iptables requires names to be <= 28 characters, and somehow prepending "-m comment --comment " to this string makes it think this condition is violated
// Feel free to dig around in iptables and see if you can figure out exactly why; I haven't had time to fully trace how it parses and handle subcommands.
// If you want to investigate, get the source via `git clone git://git.netfilter.org/iptables.git`, `git checkout v1.4.21` (the version I've seen this issue on,
// though it may also happen on others), and start with `git grep XT_EXTENSION_MAXNAMELEN`.
const postRoutingMasqChainCommentFormat = "\"ip-masq-k22r: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom %s chain\""

func postroutingJumpComment() string {
	return fmt.Sprintf(postRoutingMasqChainCommentFormat, masqChain)
}

func (m *MasqDaemon) ensurePostroutingJump() error {
	if _, err := m.iptables.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPostrouting,
		"-m", "comment", "--comment", postroutingJumpComment(),
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", string(masqChain)); err != nil {
		return fmt.Errorf("failed to ensure that %s chain %s jumps to MASQUERADE: %v", utiliptables.TableNAT, masqChain, err)
	}
	return nil
}

const nonMasqRuleComment = `-m comment --comment "ip-masq-k22r: local traffic is not subject to MASQUERADE"`

func writeNonMasqRule(lines *bytes.Buffer, cidr string) {
	writeRule(lines, utiliptables.Append, masqChain, nonMasqRuleComment, "-d", cidr, "-j", "RETURN")
}

const masqRuleComment = `-m comment --comment "ip-masq-k22r: outbound traffic is subject to MASQUERADE (must be last in chain)"`

func writeMasqRule(lines *bytes.Buffer) {
	args := []string{masqRuleComment, "-j", "MASQUERADE"}
	if randomFully {
		args = append(args, "--random-fully")
	}
	writeRule(lines, utiliptables.Append, masqChain, args...)
}

// Similar syntax to utiliptables.Interface.EnsureRule, except you don't pass a table
// (you must write these rules under the line with the table name)
func writeRule(lines *bytes.Buffer, position utiliptables.RulePosition, chain utiliptables.Chain, args ...string) {
	fullArgs := append([]string{string(position), string(chain)}, args...)
	writeLine(lines, fullArgs...)
}

// Join all words with spaces, terminate with newline and write to buf.
func writeLine(lines *bytes.Buffer, words ...string) {
	lines.WriteString(strings.Join(words, " ") + "\n")
}

// isIPv6CIDR checks if the provided cidr block belongs to ipv6 family.
// If cidr belongs to ipv6 family, return true else it returns false
// which means the cidr belongs to ipv4 family
func isIPv6CIDR(cidr string) bool {
	ip, _, _ := net.ParseCIDR(cidr)
	return isIPv6(ip.String())
}

// isIPv6 checks if the provided ip belongs to ipv6 family.
// If ip belongs to ipv6 family, return true else it returns false
// which means the ip belongs to ipv4 family
func isIPv6(ip string) bool {
	return net.ParseIP(ip).To4() == nil
}
