package utils

import (
	"log"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

var Logger *zap.Logger

var ScannerLogger *zap.Logger
var PostprocessorLogger *zap.Logger
var IngestLogger *zap.Logger

var reLogPat1 = regexp.MustCompile(`^\d{4}\/\d{2}\/\d{2}\s*\d{2}:\d{2}:\d{2}\s([^:]+):\s+(.*)`)

// CustomLogger is a custom logger that implements the io.Writer interface
type CustomLogger struct {
}

// Write implements the io.Writer interface for CustomLogger
func (cl *CustomLogger) Write(p []byte) (n int, err error) {
	matches := reLogPat1.FindAllSubmatch(p, -1)
	if len(matches) > 0 {
		lvl := string(matches[0][1])
		msg := strings.TrimSpace(string(matches[0][2]))
		if lvl == "Warning" {
			Logger.WithOptions(zap.AddCallerSkip(3), zap.AddStacktrace(zap.ErrorLevel)).Log(zap.WarnLevel, msg)
		} else if lvl == "Error" {
			Logger.WithOptions(zap.AddCallerSkip(3)).Log(zap.ErrorLevel, msg)
		} else {
			Logger.WithOptions(zap.AddCallerSkip(3)).Info(msg)
		}
		return len(p), nil
	}

	Logger.WithOptions(zap.AddCallerSkip(4)).Info(strings.TrimSpace(string(p)))
	return len(p), nil
}

func init() {
	var err error
	Logger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}
	ScannerLogger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}
	IngestLogger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}
	PostprocessorLogger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}

	customLogger := &CustomLogger{}

	// Redirect the default logger to use the custom logger
	log.SetOutput(customLogger)
}
