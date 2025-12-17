// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package errmsg

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoggableError_Log(t *testing.T) {
	for _, tc := range []slog.Level{
		slog.LevelInfo, slog.LevelDebug, slog.LevelError, slog.LevelWarn,
	} {
		t.Run(tc.String(), func(t *testing.T) {
			logs := bytes.Buffer{}
			logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))
			err := LoggableError{Cause: errors.New("cause_error"), LogLevel: tc}
			Log(logger, slog.LevelDebug, err, "test_msg")

			loggedLine := logs.String()
			assert.Contains(t, loggedLine, "msg=test_msg")
			assert.Contains(t, loggedLine, "error=cause_error")
			assert.Contains(t, loggedLine, "level="+tc.String())
		})
	}
}

func TestLog_CommonError(t *testing.T) {
	for _, tc := range []slog.Level{
		slog.LevelInfo, slog.LevelDebug, slog.LevelError, slog.LevelWarn,
	} {
		t.Run(tc.String(), func(t *testing.T) {
			logs := bytes.Buffer{}
			logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))
			Log(logger, tc, errors.New("cause_error"), "test_msg")

			loggedLine := logs.String()
			assert.Contains(t, loggedLine, "msg=test_msg")
			assert.Contains(t, loggedLine, "error=cause_error")
			assert.Contains(t, loggedLine, "level="+tc.String())
		})
	}
}
