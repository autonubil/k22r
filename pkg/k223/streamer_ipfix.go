package k22r

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
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
const DEFAULT_COMMUNITY = "42"

// NatsIngester pseudo ingestor to dump results
type IpfixStreamer struct {
	Config  *IpfixStreamerConfig
	Verbose bool
	cancel  chan interface{}
}

// IpfixStreamerConfig configuration for the IpfixStreamer Plugin
type IpfixStreamerConfig struct {
	Community     string `yaml:"community"`
	Collector     string `yaml:"collector"`
	CollectorPort uint16 `yaml:"collector_port"`
	Interface     string `yaml:"interface"`
	Interval      uint16 `yaml:"interval"`
	ExpireWindow  bool   `yaml:"expire_window"`

	ActiveTimeout   flows.DateTimeSeconds `yaml:"active_timeout"`
	IdleTimeout     flows.DateTimeSeconds `yaml:"idle_timeout"`
	Bidirectional   bool                  `yaml:"bidirectional"`
	AllowZero       bool                  `yaml:"allow_zero"`
	Features        []interface{}         `yaml:"features"`
	KeyFeatures     []string              `yaml:"key_features"`
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

	if s.Config.Community == "" {
		s.Config.Community = DEFAULT_COMMUNITY
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

	if s.Config.Interface == "" {
		for _, iface := range interfaces {
			if iface.Name == "lo" {
				continue
			}
			if iface.Flags != iface.Flags|net.FlagUp {
				continue
			}
			if strings.HasPrefix(iface.Name, "usb") || strings.HasPrefix(iface.Name, "veth") || strings.HasPrefix(iface.Name, "cni") || strings.HasPrefix(iface.Name, "docker") || strings.HasPrefix(iface.Name, "tun") || strings.HasPrefix(iface.Name, "br-") {
				continue
			}

			addrs, err := iface.Addrs()
			if err == nil && len(addrs) > 0 {
				s.Config.Interface = iface.Name
				break
			}
		}
	}

	if s.Config.Interface == "" {
		return nil, errors.New("could not autodetect interface to meter")
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

func decodeOneFeature(feature interface{}) interface{} {
	switch feature := feature.(type) {
	case []interface{}:
		ret := make([]interface{}, len(feature))
		for i, elem := range feature {
			ret[i] = decodeOneFeature(elem)
		}
		return ret
	case map[string]interface{}:
		var k, v interface{}
		found := false
		for k, v = range feature {
			if !found {
				found = true
			} else {
				log.Fatalf("Only one key allowed in calls (unexpected %s)\n", k)
			}
		}
		if args, ok := v.([]interface{}); !ok {
			log.Fatalf("Call arguments must be an array (unexpected %s)\n", v)
		} else {
			return decodeOneFeature(append([]interface{}{k}, args...))
		}
	case json.Number:
		if i, err := feature.Int64(); err == nil {
			return i
		} else if f, err := feature.Float64(); err == nil {
			return f
		} else {
			log.Fatalf("Can't decode %s!\n", feature.String())
		}
	}
	return feature
}

func decodeFeatures(features interface{}) (ret []interface{}) {
	if features, ok := features.([]interface{}); ok {
		ret = make([]interface{}, len(features))
		for i, elem := range features {
			ret[i] = decodeOneFeature(elem)
		}
		return
	}
	log.Fatal("Feature list must be an array")
	return
}

func (s *IpfixStreamer) Start() error {
	var err error

	var sources packet.Sources
	var exp flows.Exporter
	_, exp, err = flows.MakeExporter("ipfix_stream", []string{fmt.Sprintf("%s:%d", s.Config.Collector, s.Config.CollectorPort), "42"})
	if err != nil {
		return fmt.Errorf("error creating exporter '%s': %s", "ipfix", err)
	}
	exp.Init()
	var src packet.Source

	_, src, err = packet.MakeSource("libpcap", []string{"-live", "-promisc", s.Config.Interface})
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
	features := decodeFeatures(s.Config.Features)
	err = recordList.AppendRecord(features, s.Config.ControlFeatures, s.Config.FilterFeatures, pipeline, s.Verbose)
	if err != nil {
		return fmt.Errorf("error configuring features %s", err)
	}

	opts.WindowExpiry = s.Config.ExpireWindow
	opts.SortOutput = flows.SortTypeNone
	opts.ActiveTimeout = flows.DateTimeNanoseconds(s.Config.ActiveTimeout) * flows.SecondsInNanoseconds
	opts.IdleTimeout = flows.DateTimeNanoseconds(s.Config.IdleTimeout) * flows.SecondsInNanoseconds
	opts.TCPExpiry = false
	opts.PerPacket = false
	keyselector := packet.MakeDynamicKeySelector(s.Config.KeyFeatures, s.Config.Bidirectional, s.Config.AllowZero)

	flowtable := packet.NewFlowTable(int(numProcessing), recordList, packet.NewFlow, opts,
		flows.DateTimeNanoseconds(flowExpire)*flows.SecondsInNanoseconds, keyselector, autoGC)

	engine := packet.NewEngine(int(maxPacket), flowtable, filters, sources, labels)

	utils.Logger.Info("ipfix started", zap.String("source", s.Config.Interface), zap.String("target", s.Config.Collector))
	recordList.Init()

	// flows.ListFeatures(os.Stdout)
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
		case <-time.After(15 * time.Second):
			engine.PrintStats(os.Stdout)
			flowtable.PrintStats(os.Stdout)
		}
	}

	s.cancel <- nil
	close(s.cancel)

	close(s.cancel)
	s.cancel = nil
	utils.Logger.Info("done streaming")
	return err
}
