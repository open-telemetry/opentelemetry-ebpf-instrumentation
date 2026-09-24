// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package klogbridge

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"
)

type recordHandler struct {
	mu      sync.Mutex
	level   *slog.LevelVar
	records []slog.Record
}

func (h *recordHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *recordHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *recordHandler) snapshot() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(h.records))
	copy(out, h.records)
	return out
}

func (h *recordHandler) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = nil
}

func (h *recordHandler) messages() map[string]slog.Level {
	out := make(map[string]slog.Level)
	for _, r := range h.snapshot() {
		out[r.Message] = r.Level
	}
	return out
}

func TestInstallLevelMappings(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var lvl slog.LevelVar
	lvl.Set(slog.LevelInfo)
	handler := &recordHandler{level: &lvl}
	slog.SetDefault(slog.New(handler))

	Install()
	// Idempotent: a second call must not panic or reconfigure.
	Install()

	t.Run("info keeps Info and filters legacy V", func(t *testing.T) {
		handler.reset()
		lvl.Set(slog.LevelInfo)
		syncKlogVerbosity()

		klog.Background().Info("structured probe")
		klog.Info("legacy info probe")
		klog.V(4).Info("verbose probe")
		klog.Warning("warn at info")

		got := handler.messages()
		require.Contains(t, got, "structured probe")
		assert.Equal(t, slog.LevelInfo, got["structured probe"])
		require.Contains(t, got, "legacy info probe")
		assert.Equal(t, slog.LevelInfo, got["legacy info probe"])
		assert.NotContains(t, got, "verbose probe", "legacy V(4) must stay gated by klog -v while Debug is off")
		require.Contains(t, got, "warn at info")
		assert.Equal(t, slog.LevelWarn, got["warn at info"])
	})

	t.Run("warn keeps Warning and drops Info", func(t *testing.T) {
		handler.reset()
		lvl.Set(slog.LevelWarn)
		syncKlogVerbosity()

		klog.Warning("warn probe")
		klog.Info("info should drop")
		klog.Background().Info("structured info should drop")

		got := handler.messages()
		require.Contains(t, got, "warn probe")
		assert.Equal(t, slog.LevelWarn, got["warn probe"])
		assert.NotContains(t, got, "info should drop")
		assert.NotContains(t, got, "structured info should drop")
	})

	t.Run("debug surfaces legacy V", func(t *testing.T) {
		handler.reset()
		lvl.Set(slog.LevelDebug)
		syncKlogVerbosity()

		klog.V(4).Info("verbose at debug")
		klog.Background().V(4).Info("structured verbose at debug")

		got := handler.messages()
		require.Contains(t, got, "verbose at debug")
		// Legacy V lines share klog Info severity, so they arrive as Info once -v allows them.
		assert.Equal(t, slog.LevelInfo, got["verbose at debug"])
		require.Contains(t, got, "structured verbose at debug")
		assert.Equal(t, slog.LevelDebug, got["structured verbose at debug"])
	})
}

func TestParseKlogBuffer(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		level slog.Level
		msg   string
	}{
		{
			name:  "warning",
			in:    "W0827 12:00:00.000000   1 file.go:1] hello warn\n",
			level: slog.LevelWarn,
			msg:   "hello warn",
		},
		{
			name:  "info",
			in:    "I0827 12:00:00.000000   1 file.go:1] hello info\n",
			level: slog.LevelInfo,
			msg:   "hello info",
		},
		{
			name:  "error",
			in:    "E0827 12:00:00.000000   1 file.go:1] hello err\n",
			level: slog.LevelError,
			msg:   "hello err",
		},
		{
			name:  "fatal",
			in:    "F0827 12:00:00.000000   1 file.go:1] hello fatal\n",
			level: slog.LevelError,
			msg:   "hello fatal",
		},
		{
			name:  "empty",
			in:    "",
			level: slog.LevelInfo,
			msg:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, msg := parseKlogBuffer([]byte(tt.in))
			assert.Equal(t, tt.level, level)
			assert.Equal(t, tt.msg, msg)
		})
	}
}
