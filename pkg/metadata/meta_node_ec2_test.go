// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/aws/smithy-go/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEC2SDKLoggerLevels(t *testing.T) {
	for _, tc := range []struct {
		name    string
		min     slog.Level
		class   logging.Classification
		format  string
		args    []any
		want    []string
		wantLog bool
	}{
		{
			name:    "warn",
			min:     slog.LevelInfo,
			class:   logging.Warn,
			format:  "falling back to IMDSv1: %s",
			args:    []any{"403"},
			want:    []string{"level=WARN", "falling back to IMDSv1: 403", "component=meta.NodeMeta.ec2"},
			wantLog: true,
		},
		{
			name:   "debug suppressed at info",
			min:    slog.LevelInfo,
			class:  logging.Debug,
			format: "request %s",
			args:   []any{"PUT"},
		},
		{
			name:    "debug kept",
			min:     slog.LevelDebug,
			class:   logging.Debug,
			format:  "request %s",
			args:    []any{"PUT"},
			want:    []string{"level=DEBUG", "request PUT", "component=meta.NodeMeta.ec2"},
			wantLog: true,
		},
		{
			name:    "other classification is info",
			min:     slog.LevelInfo,
			class:   "INFO",
			format:  "other %d",
			args:    []any{1},
			want:    []string{"level=INFO", "other 1"},
			wantLog: true,
		},
		{
			name:   "warn suppressed at error",
			min:    slog.LevelError,
			class:  logging.Warn,
			format: "falling back to IMDSv1: %s",
			args:   []any{"403"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: tc.min}))
			ec2SDKLogger(logger.With("component", "meta.NodeMeta.ec2")).Logf(tc.class, tc.format, tc.args...)
			got := buf.String()
			if !tc.wantLog {
				assert.Empty(t, got)
				return
			}
			for _, want := range tc.want {
				assert.Contains(t, got, want)
			}
		})
	}
}

func TestEC2SDKLoggerContext(t *testing.T) {
	handler := &ctxRecordHandler{level: slog.LevelInfo}
	logger := ec2SDKLogger(slog.New(handler))

	logger.Logf(logging.Warn, "without operation context")
	require.Equal(t, context.Background(), handler.ctx)

	cancelCtx, cancel := context.WithCancel(t.Context())
	child := context.WithValue(cancelCtx, ec2LogCtxKey{}, "detect")
	cancel()
	logging.WithContext(child, logger).Logf(logging.Warn, "from detect")
	require.Equal(t, "detect", handler.ctx.Value(ec2LogCtxKey{}))
	require.ErrorIs(t, handler.ctx.Err(), context.Canceled)

	logger.Logf(logging.Warn, "still without operation context")
	require.Equal(t, context.Background(), handler.ctx)
}

type ec2LogCtxKey struct{}

type ctxRecordHandler struct {
	level slog.Level
	ctx   context.Context
}

func (h *ctxRecordHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *ctxRecordHandler) Handle(ctx context.Context, _ slog.Record) error {
	h.ctx = ctx
	return nil
}

func (h *ctxRecordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *ctxRecordHandler) WithGroup(string) slog.Handler { return h }
