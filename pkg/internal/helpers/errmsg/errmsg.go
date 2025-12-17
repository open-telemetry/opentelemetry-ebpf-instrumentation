// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package errmsg

import (
	"errors"
	"log/slog"
)

// LoggableError is an error that can be logged at a different level than the default one
type LoggableError struct {
	LogLevel slog.Level
	Cause    error
}

func (e LoggableError) Error() string {
	return e.Cause.Error()
}

// Log will log the error with a message at the given level. If the error is of LoggableError
// type, the LogLevel field will be used instead of the defaultLevel parameter.
func Log(logger *slog.Logger, defaultLevel slog.Level, err error, message string) {
	level := defaultLevel
	le := LoggableError{}
	if errors.As(err, &le) {
		level = le.LogLevel
	}
	switch level {
	case slog.LevelInfo:
		logger.Info(message, "error", err)
	case slog.LevelDebug:
		logger.Debug(message, "error", err)
	case slog.LevelError:
		logger.Error(message, "error", err)
	default:
		logger.Warn(message, "error", err)
	}
}
