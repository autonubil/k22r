module github.com/autonubil/k22r

go 1.22.0

toolchain go1.22.4

replace github.com/CN-TU/go-flows v0.0.0-20230313083432-9f5628c12456 => github.com/autonubil/go-flows v0.0.0-20240612202638-da4b6383d0e1

replace github.com/CN-TU/go-ipfix => github.com/autonubil/go-ipfix v0.0.0-20240712135853-087c615e8fe6

require (
	github.com/CN-TU/go-flows v0.0.0-20230313083432-9f5628c12456
	github.com/CN-TU/go-ipfix v0.0.0-20240611191116-e1d5a30c73c3
	github.com/getsentry/sentry-go v0.28.1
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.19.1
	github.com/spf13/cobra v1.8.1
	go.uber.org/zap v1.27.0
	k8s.io/kubernetes v1.30.2
	k8s.io/utils v0.0.0-20240711033017-18e509b52bc8
)

require (
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	k8s.io/apimachinery v0.30.2 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/google/gopacket v1.1.19
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
