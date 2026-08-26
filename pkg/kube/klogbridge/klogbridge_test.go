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
	level   slog.Level
	records []slog.Record
}

func (h *recordHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
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

func TestInstallRoutesKlogThroughSlog(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	handler := &recordHandler{level: slog.LevelInfo}
	slog.SetDefault(slog.New(handler))

	Install()
	// Idempotent: a second call must not panic or reconfigure.
	Install()

	klog.Background().Info("probe")
	klog.V(4).Info("verbose probe")

	records := handler.snapshot()
	require.NotEmpty(t, records, "expected Info-level klog message to reach slog")

	var foundProbe bool
	for _, r := range records {
		assert.GreaterOrEqual(t, r.Level, slog.LevelInfo)
		if r.Message == "probe" {
			foundProbe = true
		}
		assert.NotEqual(t, "verbose probe", r.Message, "V(4) should be filtered at Info level")
	}
	assert.True(t, foundProbe, "expected message %q in slog records", "probe")
}
