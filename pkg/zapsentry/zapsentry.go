package zapsentry

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	sentry "github.com/getsentry/sentry-go"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var maxErrorDepth = 5

var BeforeSend = func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
	if hint != nil {
		if data, ok := hint.Data.(map[string]interface{}); ok {
			event.Extra, _ = data["fields"].(map[string]interface{})
		}
		if hint.OriginalException != nil {
			err := hint.OriginalException
			for i := 0; i < maxErrorDepth && err != nil; i++ {
				stackErr := errors.WithStack(err)
				trace := sentry.ExtractStacktrace(stackErr)
				if len(trace.Frames) > 3 {
					trace.Frames = trace.Frames[0 : len(trace.Frames)-4]
				}
				event.Exception = append(event.Exception, sentry.Exception{
					Value:      err.Error(),
					Type:       reflect.TypeOf(err).String(),
					Stacktrace: trace,
				})
				switch previous := err.(type) {
				case interface{ Unwrap() error }:
					err = previous.Unwrap()
				case interface{ Cause() error }:
					err = previous.Cause()
				default:
					err = nil
				}
			}
		}
	}
	if event.Transaction == "" {
		event.Transaction = "Zap.Logger"
	}
	return event
}

type SentryCore struct {
	innerCore         zapcore.Core
	minimumLevel      zapcore.Level
	mustHaveException bool
}

func getUserFromJWT(tokenPath string, user *sentry.User) error {
	rawToken, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(string(rawToken), claims, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	if err != nil {
		return err
	}

	if k8s, ok := claims["kubernetes.io"]; ok {
		if pod, ok := k8s.(map[string]interface{})["pod"]; ok {
			if pidID, ok := pod.(map[string]interface{})["uid"]; ok {
				user.ID = pidID.(string)
			}
			if podName, ok := pod.(map[string]interface{})["name"]; ok {
				user.Username = podName.(string)
				return nil
			}
		}
	}
	return fmt.Errorf("name not resolved")
}

func getEnvironmentFromCert(certName string) string {
	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile(certName)
	if err != nil {
		return "kubernetes"
	}
	block, _ := pem.Decode([]byte(caCert))
	if block == nil {
		return "kubernetes"
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "kubernetes"
	}
	return strings.Split(cert.Subject.CommonName, " - ")[0]
}

func InitWithSecondStream(release string, secondStream string) {
	options := sentry.ClientOptions{
		Release:    release,
		BeforeSend: BeforeSend,
		Integrations: func(integrations []sentry.Integration) []sentry.Integration {
			var filteredIntegrations []sentry.Integration
			for _, integration := range integrations {
				if integration.Name() == "Modules" {
					continue
				}
				filteredIntegrations = append(filteredIntegrations, integration)
			}
			return filteredIntegrations
		},
		Debug: false,
	}
	if _, err := os.Stat("/run/secrets/kubernetes.io/serviceaccount/ca.crt"); err == nil {
		options.Environment = getEnvironmentFromCert("/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	}
	if secondStream != "" {
		options.Transport = NewDoubleTransport(secondStream)
	}

	sentry.Init(options)
	func() {
		// capture panics
		defer sentry.Recover()
	}()
}
func Init(release string) {
	InitWithSecondStream(release, "")
}

var prodConfig = zap.Config{
	Level:            zap.NewAtomicLevelAt(zap.InfoLevel),
	Development:      true,
	Encoding:         "console",
	EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
	OutputPaths:      []string{"stderr"},
	ErrorOutputPaths: []string{"stderr"},
}

func NewProduction(options ...zap.Option) (*zap.Logger, error) {
	options = append(options, zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return NewWrappedCore(core, zapcore.WarnLevel, false)
	}))

	return prodConfig.Build(options...)
}

var debugConfig = zap.Config{
	Level:            zap.NewAtomicLevelAt(zap.DebugLevel),
	Development:      true,
	Encoding:         "console",
	EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
	OutputPaths:      []string{"stderr"},
	ErrorOutputPaths: []string{"stderr"},
}

func NewDevelopment(options ...zap.Option) (*zap.Logger, error) {
	options = append(options, zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return NewWrappedCore(core, zapcore.WarnLevel, false)
	}))
	return debugConfig.Build(options...)
}

func NewWrappedCore(innerCore zapcore.Core, minimumLevel zapcore.Level, mustHaveException bool) zapcore.Core {
	return SentryCore{innerCore, minimumLevel, mustHaveException}
}

func (c SentryCore) Enabled(level zapcore.Level) bool {
	result := c.innerCore.Enabled(level)
	return result
}

func (c SentryCore) With(fld []zapcore.Field) zapcore.Core { return c.innerCore.With(fld) }

func (c SentryCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if ent.Level > -1 {
		ce = ce.AddCore(ent, c)
	}
	return c.innerCore.Check(ent, ce)
}

func (c SentryCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	hub := sentry.CurrentHub()
	client, scope := hub.Client(), hub.Scope()
	if client == nil || scope == nil {
		return nil
	}
	if entry.Level < c.minimumLevel {
		return nil
	}

	data := make(map[string]interface{})
	flds := make(map[string]interface{})
	switch entry.Level {
	case zapcore.DebugLevel:
		scope.SetLevel(sentry.LevelDebug)
	case zapcore.InfoLevel:
		scope.SetLevel(sentry.LevelInfo)
	case zapcore.WarnLevel:
		scope.SetLevel(sentry.LevelWarning)
	case zapcore.ErrorLevel:
		scope.SetLevel(sentry.LevelError)
	case zapcore.PanicLevel:
		scope.SetLevel(sentry.LevelError)
	case zapcore.DPanicLevel:
		scope.SetLevel(sentry.LevelError)
	case zapcore.FatalLevel:
		scope.SetLevel(sentry.LevelFatal)
	default:
		scope.SetLevel(sentry.LevelDebug)
	}
	data["zapEntry"] = entry
	data["fields"] = flds
	hint := &sentry.EventHint{
		Data: data,
	}

	sentryUser := sentry.User{}
	_, err := os.Stat("/run/secrets/kubernetes.io/serviceaccount/token")
	if err == nil {
		err = getUserFromJWT("/run/secrets/kubernetes.io/serviceaccount/token", &sentryUser)
	}

	if err != nil {
		user, err := user.Current()
		if err == nil {
			sentryUser.Username = user.Username
			sentryUser.ID = user.Uid
		} else {
			sentryUser.Username = "N/A"
		}
	}

	scope.SetUser(sentryUser)

	hasException := false
	for _, fld := range fields {
		if fld.Interface != nil {
			if fld.Type == zapcore.ErrorType {
				hint.OriginalException = fld.Interface.(error)
				hint.RecoveredException = sentry.Exception{}
				hasException = true
			} else if fld.Type == zapcore.StringerType {
				flds[fld.Key] = fld.Interface.(fmt.Stringer).String()
			} else {
				flds[fld.Key] = fld.Interface
			}
		} else {
			switch fld.Type {
			case zapcore.StringType:
				flds[fld.Key] = fld.String
			default:
				flds[fld.Key] = fld.Integer
			}
		}
	}

	if entry.LoggerName == "" {
		entry.LoggerName = filepath.Base(os.Args[0])
	}

	if !c.mustHaveException || hasException {
		client.CaptureMessage(entry.Message, hint, scope)
	}
	if hasException {
		client.Flush(1 * time.Second)
	}

	return nil
}

func (c SentryCore) Sync() error { return c.innerCore.Sync() }

type DoubleTransport struct {
	url              string
	wrappedTransport *sentry.HTTPTransport
	secondTransport  *sentry.HTTPTransport
}

func (t *DoubleTransport) SendEvent(event *sentry.Event) {
	// forward to default tansport
	t.wrappedTransport.SendEvent(event)
	if t.url != "" {
		t.secondTransport.SendEvent(event)
	}

}

func (t *DoubleTransport) Flush(timeout time.Duration) bool {
	// forward to default tansport
	t.wrappedTransport.Flush(timeout)
	if t.url != "" {
		t.secondTransport.Flush(timeout)
	}
	return true
}

func (t *DoubleTransport) Configure(options sentry.ClientOptions) {
	// forward to default tansport
	t.wrappedTransport.Configure(options)
	if t.url != "" {
		options.Dsn = t.url
		t.secondTransport.Configure(options)
	}
}

func NewDoubleTransport(secondTransport string) *DoubleTransport {
	if secondTransport != "" {
		return &DoubleTransport{
			url:              secondTransport,
			wrappedTransport: sentry.NewHTTPTransport(),
			secondTransport:  sentry.NewHTTPTransport(),
		}
	}
	return &DoubleTransport{
		wrappedTransport: sentry.NewHTTPTransport(),
	}
}
