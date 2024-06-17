package cmd

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/CN-TU/go-ipfix"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/autonubil/k22r/pkg/build"
	k22r "github.com/autonubil/k22r/pkg/k22r"
	"github.com/autonubil/k22r/pkg/utils"
	"github.com/autonubil/k22r/pkg/zapsentry"
)

var (
	// Build build information
	collector             string
	debug                 bool
	observationDomainName string
	groupName             string
	observationDomainId   uint64
	activeTimeout         uint64
	idleTimeout           uint64
	exporterIp            string
)

var (
	prometheusPort    int32
	prometheusEnabled bool
	prometheusDump    bool
)

func writePrometheusDump() {
	now := time.Now()
	prometheus.WriteToTextfile(fmt.Sprintf("prometheus-%02d-%02d-%04d.txt", now.Day(), now.Month(), now.Year()), prometheus.DefaultGatherer)
}

var (
	cpuprofile   string
	memprofile   string
	blockprofile bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "k22r",
	Short: "KubernetesIpfixExporter",
	Long:  `export k8s cluster internal ip traffic as ipfix`,
	Run: func(cmd *cobra.Command, args []string) {
		// Profiling
		if cpuprofile != "" {
			f, err := os.Create(cpuprofile)
			if err != nil {
				log.Fatal("could not create CPU profile: ", err)
			}
			defer f.Close() // error handling omitted for example
			if err := pprof.StartCPUProfile(f); err != nil {
				log.Fatal("could not start CPU profile: ", err)
			}
			defer pprof.StopCPUProfile()
		}

		// prometheus
		if prometheusEnabled {
			http.Handle("/metrics", promhttp.Handler())
			go http.ListenAndServe(fmt.Sprintf(":%d", prometheusPort), nil)
			if prometheusDump {
				defer writePrometheusDump()
			}
		}
		// /RUN
		streamer := k22r.NewIpfixStreamer()
		if collector != "" {
			streamer.Config.Collector = collector
		}

		if observationDomainId > 0 {
			streamer.Config.ObservationDomainId = observationDomainId
		}
		if activeTimeout > 0 {
			streamer.Config.ActiveTimeout = ipfix.DateTimeSeconds(activeTimeout)
		}
		if idleTimeout > 0 {
			streamer.Config.IdleTimeout = ipfix.DateTimeSeconds(idleTimeout)
		}
		if observationDomainName != "" {
			streamer.Config.ObservationDomainName = observationDomainName
		}
		if groupName != "" {
			streamer.Config.GroupName = groupName
		}
		if exporterIp != "" {
			streamer.Config.ExporterIp = exporterIp
		}

		err := streamer.Init()
		if err != nil {
			utils.Logger.Fatal("could not initialize: ", zap.Error(err))
		}

		err = streamer.Start()
		if err != nil {
			utils.Logger.Fatal("streaming failed: ", zap.Error(err))
		}

		utils.Logger.Info("k22r shutdown", zap.Any("build", build.Info))

		if memprofile != "" {
			f, err := os.Create(memprofile)
			if err != nil {
				log.Fatal("could not create memory profile: ", err)
			}
			defer f.Close() // error handling omitted for example
			runtime.GC()    // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				log.Fatal("could not write memory profile: ", err)
			}
		}
		if blockprofile || debug {
			runtime.SetBlockProfileRate(1)
			runtime.SetMutexProfileFraction(1)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func envOrDefault(name string, dflt string) string {
	val := os.Getenv(name)
	if val != "" {
		return val
	}
	return dflt
}

func init() {
	flags := rootCmd.PersistentFlags()

	id := os.Getenv("K22R_OBSERVATION_DOMAIN_ID")
	var defaultId uint64 = 8
	if id != "" {
		if v, ok := strconv.Atoi(id); ok == nil {
			defaultId = uint64(v)
		}
	}

	var dit = uint64(0)
	it := os.Getenv("K22R_IDLE_TIMEOUT")
	if it != "" {
		if v, ok := strconv.Atoi(it); ok == nil {
			dit = uint64(v)
		}
	}
	var dat = uint64(0)
	at := os.Getenv("K22R_ACTIVE_TIMEOUT")
	if at != "" {
		if v, ok := strconv.Atoi(at); ok == nil {
			dat = uint64(v)
		}
	}

	flags.BoolVarP(&debug, "debug", "d", false, "Execute in debug mode")

	flags.StringVarP(&collector, "collector", "t", os.Getenv("K22R_COLLECTOR"), "IPFIX target collector address")
	flags.Uint64VarP(&observationDomainId, "observationDomainId", "i", defaultId, "Observation domain identifier")
	flags.StringVarP(&observationDomainName, "observationDomainName", "n", os.Getenv("K22R_OBSERVATION_DOMAIN_NAME"), "Observation domain name")
	flags.StringVarP(&groupName, "groupName", "g", os.Getenv("K22R_GROUP_NAME"), "Group name (useful for distinguishing clusters)")
	flags.StringVarP(&exporterIp, "exporterIp", "e", os.Getenv("K22R_EXPORTER_IP"), "Exporter IP address")

	flags.Uint64VarP(&activeTimeout, "activeTimeout", "a", dat, "Active flow timeout duration in seconds")
	flags.Uint64VarP(&idleTimeout, "idleTimeout", "d", dit, "Idle flow timeout duration in seconds")

	flags.StringVar(&cpuprofile, "cpuprofile", "", "Write CPU profile to the specified file")
	flags.StringVar(&memprofile, "memprofile", "", "Write memory profile to the specified file")
	flags.BoolVar(&blockprofile, "blockprofile", false, "Enable blocking profile")

	flags.Int32Var(&prometheusPort, "prometheus-port", 9943, "Port for Prometheus metrics")
	flags.BoolVar(&prometheusEnabled, "prometheus-enabled", true, "Enable Prometheus metrics export")
	flags.BoolVar(&prometheusDump, "prometheus-dump", false, "Dump Prometheus metrics after execution")

	cobra.OnInitialize(initModule)
}

func initModule() {
	var err error
	if debug {
		utils.Logger, err = zapsentry.NewDevelopment() // zap.Fields(zap.Any("build", Build))
	} else {
		utils.Logger, err = zapsentry.NewProduction()
	}

	if err != nil {
		panic(err)
	}
	defer utils.Logger.Sync()
	utils.Logger.Info("k22r startup", zap.Any("build", build.Info))
}
