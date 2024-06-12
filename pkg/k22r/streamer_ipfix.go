package k22r

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CN-TU/go-flows/flows"
	_ "github.com/CN-TU/go-flows/modules/exporters/ipfix"
	_ "github.com/CN-TU/go-flows/modules/features/iana"
	_ "github.com/CN-TU/go-flows/modules/features/nta"
	_ "github.com/CN-TU/go-flows/modules/features/operations"
	_ "github.com/CN-TU/go-flows/modules/features/staging"
	_ "github.com/CN-TU/go-flows/modules/keys/time"
	_ "github.com/CN-TU/go-flows/modules/sources/libpcap"
	"github.com/CN-TU/go-flows/packet"
	"github.com/CN-TU/go-ipfix"
	"github.com/autonubil/k22r/pkg/build"
	"github.com/autonubil/k22r/pkg/utils"
	"github.com/autonubil/k22r/pkg/zapsentry"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const DEFAULT_COLLECTOR = "elastiflow.opsanio.svc" // TODO: LOCALHOST
const DEFAULT_OBJSERVATION_ID = 8
const DEFAULT_OBJSERVATION_NAME = "kubernetes"

var DEFAULT_FEATURES = []string{"sourceIPAddress", "destinationIPAddress", "sourceTransportPort", "destinationTransportPort", "protocolIdentifier", "destinationMacAddress", "sourceMacAddress", "flowDirection", "flowStartMilliseconds", "flowEndMilliseconds", "flowEndReason", "octetDeltaCount", "packetDeltaCount", "minimumTTL", "maximumTTL"}
var DEFAULT_KEY_FEATURES = []string{"sourceIPAddress", "destinationIPAddress", "sourceTransportPort", "destinationTransportPort", "protocolIdentifier"}

// NatsIngester pseudo ingestor to dump results
type IpfixStreamer struct {
	Config    *IpfixStreamerConfig
	Verbose   bool
	k8sIface  *net.Interface
	nodeIface *net.Interface
	cancel    chan interface{}
}

// IpfixStreamerConfig configuration for the IpfixStreamer Plugin
type IpfixStreamerConfig struct {
	Collector             string `yaml:"collector"`
	CollectorPort         uint16 `yaml:"collector_port"`
	ObservationDomainId   uint64 `yaml:"observation_domain_id"`
	ObservationDomainName string `yaml:"observation_domain_name"`
	InterfaceName         string `yaml:"interface"`
	Interval              uint16 `yaml:"interval"`
	ExpireWindow          bool   `yaml:"expire_window"`

	ActiveTimeout   flows.DateTimeSeconds `yaml:"active_timeout"`
	IdleTimeout     flows.DateTimeSeconds `yaml:"idle_timeout"`
	Bidirectional   bool                  `yaml:"bidirectional"`
	AllowZero       bool                  `yaml:"allow_zero"`
	ControlFeatures []string              `yaml:"control_features"`
	FilterFeatures  []string              `yaml:"filter_features"`
}

func loadConfig(cfgFile string) (*IpfixStreamerConfig, error) {
	config := &IpfixStreamerConfig{}
	yamlFile, err := os.ReadFile(cfgFile)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, config)
	if err != nil {
		return nil, err
	}

	zapsentry.InitWithSecondStream(build.Info.Release(), "")
	return config, nil
}

// Configure initialize the ingester from configuration
func NewIpfixStreamer(cfgFile string, verbose bool) (*IpfixStreamer, error) {
	config, err := loadConfig(cfgFile)
	if err != nil {
		return nil, err
	}
	s := &IpfixStreamer{
		Config:  config,
		Verbose: verbose,
	}

	if s.Config.Collector == "" {
		s.Config.Collector = DEFAULT_COLLECTOR
	}

	names, err := net.DefaultResolver.LookupHost(context.Background(), s.Config.Collector)
	if err != nil || len(names) == 0 {
		return nil, fmt.Errorf("could not resolve collector ip: %s", err.Error())
	}
	s.Config.Collector = names[0]

	if s.Config.CollectorPort == 0 {
		s.Config.CollectorPort = 4739
	}

	if s.Config.Interval == 0 {
		s.Config.Interval = 1
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	k8sNodeName := os.Getenv("K8S_NODE_NAME")
	var k8sNodeAddr net.IP
	if k8sNodeName != "" {
		k8sNodeIPs, err := net.LookupHost(k8sNodeName)
		if err == nil {
			for _, nodeIp := range k8sNodeIPs {
				addr := net.ParseIP(nodeIp)
				if addr == nil {
					continue
				}
				if addr.IsGlobalUnicast() {
					k8sNodeAddr = addr
					utils.Logger.Info("detected kubernetes node ip", zap.Stringer("ip", k8sNodeAddr))
				}

			}
		}
	}

	for _, iface := range interfaces {
		if iface.Name == "lo" {
			utils.Logger.Info("ignoring loopback interface", zap.String("interface", iface.Name))
			continue
		}
		if iface.Flags != iface.Flags|net.FlagUp {
			utils.Logger.Info("ignoring down interface", zap.String("interface", iface.Name))
			continue
		}
		if strings.HasPrefix(iface.Name, "usb") || strings.HasPrefix(iface.Name, "veth") || strings.HasPrefix(iface.Name, "docker") || strings.HasPrefix(iface.Name, "tun") || strings.HasPrefix(iface.Name, "br-") {
			utils.Logger.Info("ignoring special interface", zap.String("interface", iface.Name))
			continue
		}

		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 {
			if k8sNodeAddr.IsGlobalUnicast() {
				k8sMatch := false
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					default:
						continue
					}
					utils.Logger.Info("checking interface for k8s node ip", zap.String("interface", iface.Name), zap.Stringer("ip", ip))
					if k8sNodeAddr.Equal(ip) {
						k8sMatch = true
						break
					}
				}
				if k8sMatch {
					if s.k8sIface == nil {
						s.k8sIface = &iface
					}
					utils.Logger.Info("detected k8s node interface", zap.String("candidate", iface.Name), zap.Any("interface", s.k8sIface))
				}
			}
			if strings.HasPrefix(iface.Name, "cni") {
				s.k8sIface = &iface
				utils.Logger.Info("detected cni interface", zap.String("candidate", iface.Name), zap.Any("interface", s.k8sIface))
				break
			}
			if s.k8sIface == nil {
				s.k8sIface = &iface
				utils.Logger.Info("detected first elegible interface", zap.String("candidate", iface.Name), zap.Any("interface", s.k8sIface))
			}
			if s.Config.InterfaceName == iface.Name {
				s.k8sIface = &iface
			}
		} else {
			utils.Logger.Info("ignoring interface without addresses", zap.String("interface", iface.Name))
		}
	}

	if s.k8sIface == nil {
		return nil, errors.New("could not autodetect interface to meter")
	}

	if s.Config.ObservationDomainId == 0 {
		s.Config.ObservationDomainId = DEFAULT_OBJSERVATION_ID
	}
	if s.Config.ObservationDomainName == "" {
		s.Config.ObservationDomainName = DEFAULT_OBJSERVATION_NAME
	}
	ipfix.LoadIANASpec()
	return s, nil
}

func (s *IpfixStreamer) Stop() error {
	if s.cancel != nil {
		s.cancel <- s
		return nil
	}

	return fmt.Errorf("streamer not started")
}

func (s *IpfixStreamer) Start() error {
	var err error

	var sources packet.Sources
	var exp flows.Exporter
	_, exp, err = flows.MakeExporter("ipfix_stream", []string{fmt.Sprintf("%s:%d", s.Config.Collector, s.Config.CollectorPort), strconv.Itoa(int(s.Config.ObservationDomainId))})
	if err != nil {
		return fmt.Errorf("error creating exporter '%s': %s", "ipfix", err)
	}
	exp.Init()
	var src packet.Source

	_, src, err = packet.MakeSource("libpcap", []string{"-live", "-promisc", s.k8sIface.Name})
	if err != nil {
		return fmt.Errorf("error creating source '%s': %s", "libpcap", err)
	}

	sources.Append(src)

	// SEE: https://github.com/CN-TU/go-flows/blob/master/run.go#L189
	numProcessing := uint(4) //  Number of parallel processing tables
	flowExpire := 100

	maxPacket := 1500
	autoGC := false
	var opts flows.FlowOptions
	var recordList flows.RecordListMaker
	var labels packet.Labels
	// var control, filter, key []string
	// var bidirectional, allowZero bool
	var filters packet.Filters
	// features, control, filter, key, bidirectional, allowZero, opts = decodeSimple(s.Config.Preprocessor, 0)

	pipeline, err := flows.MakeExportPipeline([]flows.Exporter{exp}, flows.SortTypeNone, numProcessing)
	if err != nil {
		return fmt.Errorf("failed to create pipeline: %s", err.Error())
	}
	features := make([]interface{}, 0)

	for _, defaultFeature := range DEFAULT_FEATURES {
		features = append(features, defaultFeature)
	}
	// append interface features

	features = append(features, registerUint64Feature("flowActiveTimeout", uint64(s.Config.ActiveTimeout)))
	features = append(features, registerUint64Feature("flowIdleTimeout", uint64(s.Config.IdleTimeout)))

	features = append(features, registerStringFeature("interfaceName", s.k8sIface.Name))
	features = append(features, registerUint64Feature("ingressInterface", uint64(s.k8sIface.Index)))
	/* Sent with each package
	if s.Config.ObservationDomainId > 0 {
		features = append(features, registerUint64Feature("observationDomainId", s.Config.ObservationDomainId))
	}
	*/
	if s.Config.ObservationDomainName != "" {
		features = append(features, registerStringFeature("observationDomainName", s.Config.ObservationDomainName))
	}

	// features = tst
	err = recordList.AppendRecord(features, s.Config.ControlFeatures, s.Config.FilterFeatures, pipeline, s.Verbose)
	if err != nil {
		return fmt.Errorf("error configuring features %s", err)
	}
	// flows.ListFeatures(os.Stdout)

	opts.WindowExpiry = s.Config.ExpireWindow
	opts.SortOutput = flows.SortTypeNone
	opts.ActiveTimeout = flows.DateTimeNanoseconds(s.Config.ActiveTimeout) * flows.SecondsInNanoseconds
	opts.IdleTimeout = flows.DateTimeNanoseconds(s.Config.IdleTimeout) * flows.SecondsInNanoseconds
	opts.TCPExpiry = false
	opts.PerPacket = false
	keyselector := packet.MakeDynamicKeySelector(DEFAULT_KEY_FEATURES, s.Config.Bidirectional, s.Config.AllowZero)

	flowtable := packet.NewFlowTable(int(numProcessing), recordList, packet.NewFlow, opts,
		flows.DateTimeNanoseconds(flowExpire)*flows.SecondsInNanoseconds, keyselector, autoGC)

	engine := packet.NewEngine(int(maxPacket), flowtable, filters, sources, labels)

	utils.Logger.Info("ipfix started", zap.String("source", s.k8sIface.Name), zap.String("target", s.Config.Collector))
	recordList.Init()

	// recordList.CallGraph(os.Stdout)

	var stopped flows.DateTimeNanoseconds
	go func() {
		stopped = engine.Run()
		engine.Finish()
		flowtable.EOF(stopped)
		recordList.Flush()
		exp.Finish()
	}()

	done := false
	for !done {
		select {
		case <-s.cancel:
			engine.Stop()
			done = true
		case <-time.After(30 * time.Second):
			/*
				packetStats := engine.PacketStats
				stats := flowtable.GetStats()
				utils.Logger.Info("stats", zap.Any("packets", packetStats), zap.Any("tables", stats))
			*/
		}
	}

	s.cancel <- nil
	close(s.cancel)
	s.cancel = nil
	utils.Logger.Info("done streaming")
	return err
}
