module github.com/autonubil/k22r

go 1.22.0

// replace github.com/CN-TU/go-flows v0.0.0-20230313083432-9f5628c12456 => /home/czeumer/src/github.com/autonubil/go-flows

// replace github.com/CN-TU/go-ipfix v0.0.0-20190708151352-9d85a86dd266 => /home/czeumer/src/github.com/autonubil/go-ipfix

replace github.com/CN-TU/go-flows v0.0.0-20230313083432-9f5628c12456 => github.com/autonubil/go-flows v0.0.0-20240612154634-aa40bf9a596c

// replace github.com/CN-TU/go-ipfix v0.0.0-20190708151352-9d85a86dd266 => github.com/autonubil/go-ipfix v0.0.0-20240611060248-9b4d9b50d438

require (
	github.com/CN-TU/go-flows v0.0.0-20230313083432-9f5628c12456
	github.com/CN-TU/go-ipfix v0.0.0-20240611191116-e1d5a30c73c3
	github.com/getsentry/sentry-go v0.28.1
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.19.1
	github.com/spf13/cobra v1.8.0
	go.uber.org/zap v1.27.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.54.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
