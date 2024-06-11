package utils

import (
	"log"

	"go.uber.org/zap"
)

var Logger *zap.Logger

var ScannerLogger *zap.Logger
var PostprocessorLogger *zap.Logger
var IngestLogger *zap.Logger

// CustomLogger is a custom logger that implements the io.Writer interface
type CustomLogger struct {
}

// Write implements the io.Writer interface for CustomLogger
func (cl *CustomLogger) Write(p []byte) (n int, err error) {
	Logger.WithOptions(zap.AddCallerSkip(4)).Info(string(p))
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
