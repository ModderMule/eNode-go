package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var currentLevel int32 = int32(LevelInfo)
var atomicLevel = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = newLogger()
var sugar = logger.Sugar()
var tableLogger = newTableLogger()
var tableSugar = tableLogger.Sugar()
var outputMu sync.Mutex
var logFileHandle *os.File

func ParseLevel(value string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level %q", value)
	}
}

func SetLevel(level Level) {
	atomic.StoreInt32(&currentLevel, int32(level))
	atomicLevel.SetLevel(toZapLevel(level))
}

func SetLevelFromString(value string) error {
	level, err := ParseLevel(value)
	if err != nil {
		return err
	}
	SetLevel(level)
	return nil
}

func SetOutputFile(path string) error {
	outputMu.Lock()
	defer outputMu.Unlock()

	if logFileHandle != nil {
		_ = logFileHandle.Close()
		logFileHandle = nil
	}

	if strings.TrimSpace(path) != "" {
		dir := filepath.Dir(path)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		logFileHandle = f
	}

	rebuildLoggers()
	return nil
}

func enabled(level Level) bool {
	return Level(atomic.LoadInt32(&currentLevel)) <= level
}

func Debugf(format string, args ...any) {
	if enabled(LevelDebug) {
		sugar.Debugf(format, args...)
	}
}

func DebugTablef(format string, args ...any) {
	if enabled(LevelDebug) {
		tableSugar.Debugf(format, args...)
	}
}

func Infof(format string, args ...any) {
	if enabled(LevelInfo) {
		sugar.Infof(format, args...)
	}
}

func Warnf(format string, args ...any) {
	if enabled(LevelWarn) {
		sugar.Warnf(format, args...)
		recent.add(LevelWarn, format, args)
	}
}

func Errorf(format string, args ...any) {
	if enabled(LevelError) {
		sugar.Errorf(format, args...)
		recent.add(LevelError, format, args)
	}
}

func Fatalf(format string, args ...any) {
	sugar.Fatalf(format, args...)
}

func newLogger() *zap.Logger {
	return newLoggerWithSyncer(currentSyncer())
}

func newLoggerWithSyncer(ws zapcore.WriteSyncer) *zap.Logger {
	encoderCfg := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		MessageKey:     "msg",
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
	}
	core := zapcore.NewCore(zapcore.NewConsoleEncoder(encoderCfg), ws, atomicLevel)
	return zap.New(core)
}

func newTableLogger() *zap.Logger {
	return newTableLoggerWithSyncer(currentSyncer())
}

func newTableLoggerWithSyncer(ws zapcore.WriteSyncer) *zap.Logger {
	encoderCfg := zapcore.EncoderConfig{
		MessageKey: "msg",
	}
	core := zapcore.NewCore(zapcore.NewConsoleEncoder(encoderCfg), ws, atomicLevel)
	return zap.New(core)
}

func currentSyncer() zapcore.WriteSyncer {
	stdout := zapcore.AddSync(os.Stdout)
	if logFileHandle == nil {
		return stdout
	}
	return zapcore.NewMultiWriteSyncer(stdout, zapcore.AddSync(logFileHandle))
}

func rebuildLoggers() {
	logger = newLoggerWithSyncer(currentSyncer())
	sugar = logger.Sugar()
	tableLogger = newTableLoggerWithSyncer(currentSyncer())
	tableSugar = tableLogger.Sugar()
}

func toZapLevel(level Level) zapcore.Level {
	switch level {
	case LevelDebug:
		return zapcore.DebugLevel
	case LevelWarn:
		return zapcore.WarnLevel
	case LevelError:
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}
