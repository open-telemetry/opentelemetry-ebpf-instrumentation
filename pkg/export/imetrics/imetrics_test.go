// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestIsBuiltinNoopReporter(t *testing.T) {
	t.Run("noop reporter value", func(t *testing.T) {
		assert.True(t, IsBuiltinNoopReporter(NoopReporter{}))
	})

	t.Run("noop reporter pointer", func(t *testing.T) {
		assert.True(t, IsBuiltinNoopReporter(&NoopReporter{}))
	})

	t.Run("prometheus reporter", func(t *testing.T) {
		reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, prometheus.NewRegistry())
		assert.False(t, IsBuiltinNoopReporter(reporter))
	})

	t.Run("noop embedder is not builtin noop", func(t *testing.T) {
		reporter := &noopEmbeddingReporter{}
		assert.False(t, IsBuiltinNoopReporter(reporter))
	})

	t.Run("nil reporter", func(t *testing.T) {
		assert.False(t, IsBuiltinNoopReporter(nil))
	})
}

type noopEmbeddingReporter struct {
	NoopReporter
}

func (n *noopEmbeddingReporter) BpfProbeStats(_, _, _ string, _ uint64, _ float64) {}
