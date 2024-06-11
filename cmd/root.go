package cmd

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/autonubil/k22r/pkg/build"
	k22r "github.com/autonubil/k22r/pkg/k223"
	"github.com/autonubil/k22r/pkg/utils"
	"github.com/autonubil/k22r/pkg/zapsentry"
)

var (
	// Build build information
	cfgFile   string
	collector string
	debug     bool
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
		// RUN

		utils.Logger.Info("k22r shutdown", zap.Any("build", build.Info))
		// /RUN
		streamer, err := k22r.NewIpfixStreamer(cfgFile, debug)
		if err != nil {
			log.Fatal("could not initialize: ", err)
		}
		if collector != "" {
			streamer.Config.Collector = collector
		}
		streamer.Start()

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

	flags.BoolVarP(&debug, "debug", "d", false, "Execute in debug mode")
	flags.StringVarP(&cfgFile, "config", "c", envOrDefault("K22R_CONFIG", "config/k22r.yml"), "Configuration file to use")
	flags.StringVarP(&collector, "collector", "t", os.Getenv("K22R_COLLECTOR"), "override collector from config")

	flags.StringVar(&cpuprofile, "cpuprofile", "", "write cpu profile to `file`")
	flags.StringVar(&memprofile, "memprofile", "", "write memory profile to `file`")
	flags.BoolVar(&blockprofile, "blockprofile", false, "gather blocking information")

	flags.Int32Var(&prometheusPort, "prometheus-port", 9843, "prometheus metrics are publish here ")
	flags.BoolVar(&prometheusEnabled, "prometheus-enabled", true, "export prometheus metrics")
	flags.BoolVar(&prometheusDump, "prometheus-dump", false, "dump prometheus metrics after run")

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
