// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestBPFCollectorEnabled(t *testing.T) {
	cfg := &PrometheusConfig{}
	mpCfg := &perapp.MetricsConfig{}

	t.Run("disabled without reporter", func(t *testing.T) {
		assert.False(t, bpfCollectorEnabled(cfg, mpCfg, nil))
	})

	t.Run("disabled with noop reporter", func(t *testing.T) {
		assert.False(t, bpfCollectorEnabled(cfg, mpCfg, imetrics.NoopReporter{}))
	})

	t.Run("disabled with noop reporter pointer", func(t *testing.T) {
		assert.False(t, bpfCollectorEnabled(cfg, mpCfg, &imetrics.NoopReporter{}))
	})

	t.Run("enabled with prometheus internal reporter", func(t *testing.T) {
		internalMetrics := imetrics.NewPrometheusReporter(
			&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Millisecond},
			nil,
			prometheus.NewRegistry(),
		)

		assert.True(t, bpfCollectorEnabled(cfg, mpCfg, internalMetrics))
	})

	t.Run("enabled with prometheus manager-backed reporter", func(t *testing.T) {
		internalMetrics := imetrics.NewPrometheusReporter(
			&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Millisecond},
			&connector.PrometheusManager{},
			nil,
		)

		assert.True(t, bpfCollectorEnabled(cfg, mpCfg, internalMetrics))
	})

	t.Run("disabled with zero-interval prometheus reporter", func(t *testing.T) {
		internalMetrics := imetrics.NewPrometheusReporter(
			&imetrics.InternalMetricsConfig{},
			nil,
			prometheus.NewRegistry(),
		)

		assert.False(t, bpfCollectorEnabled(cfg, mpCfg, internalMetrics))
	})
}

func TestBPFMetricsCollectsInternalMetricsForPrometheusReporter(t *testing.T) {
	registry := prometheus.NewRegistry()
	internalMetrics := imetrics.NewPrometheusReporter(
		&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Millisecond},
		nil,
		registry,
	)
	ctxInfo := &global.ContextInfo{Metrics: internalMetrics}

	originalNewBPFCollector := newBPFCollectorFn
	originalNewInternalBPFCollector := newInternalBPFCollectorFn
	t.Cleanup(func() {
		newBPFCollectorFn = originalNewBPFCollector
		newInternalBPFCollectorFn = originalNewInternalBPFCollector
	})

	newInternalBPFCollectorFn = func(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.MetricsConfig) *BPFCollector {
		return &BPFCollector{
			promCfg:         cfg,
			commonCfg:       mpCfg,
			internalMetrics: ctxInfo.Metrics,
			ctxInfo:         ctxInfo,
			probeMetrics: func() []ProbeMetrics {
				return []ProbeMetrics{{
					probeType: "kprobe",
					probeName: "tcp_connect",
					probeID:   "7",
					latency:   0.25,
					count:     1,
				}}
			},
			mapMetrics: func() []BpfMapMetrics {
				return []BpfMapMetrics{{
					mapType:    "hash",
					mapName:    "connections",
					mapID:      "3",
					maxEntries: 16,
					entries:    4,
				}}
			},
		}
	}

	runFn, err := BPFMetrics(ctxInfo, &PrometheusConfig{}, &perapp.MetricsConfig{})(context.Background())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runFn(ctx)

	require.Eventually(t, func() bool {
		probeMetric := gatheredMetric(t, registry, "obi_bpf_probe_latency_seconds", map[string]string{
			"probe_id":   "7",
			"probe_type": "kprobe",
			"probe_name": "tcp_connect",
		})
		mapEntriesMetric := gatheredMetric(t, registry, "obi_bpf_map_entries_total", map[string]string{
			"map_id":   "3",
			"map_name": "connections",
			"map_type": "hash",
		})
		mapMaxEntriesMetric := gatheredMetric(t, registry, "obi_bpf_map_max_entries_total", map[string]string{
			"map_id":   "3",
			"map_name": "connections",
			"map_type": "hash",
		})

		if probeMetric == nil || mapEntriesMetric == nil || mapMaxEntriesMetric == nil {
			return false
		}

		return probeMetric.GetHistogram().GetSampleCount() >= 1 &&
			mapEntriesMetric.GetGauge().GetValue() == 4 &&
			mapMaxEntriesMetric.GetGauge().GetValue() == 16
	}, time.Second, 10*time.Millisecond)
}

func TestBPFMetricsCollectsInternalMetricsWhenPrometheusEndpointEnabled(t *testing.T) {
	registry := prometheus.NewRegistry()
	internalMetrics := imetrics.NewPrometheusReporter(
		&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Millisecond},
		nil,
		registry,
	)
	ctxInfo := &global.ContextInfo{Metrics: internalMetrics}
	cfg := &PrometheusConfig{Port: 1}
	mpCfg := &perapp.MetricsConfig{Features: export.FeatureEBPF}

	originalNewBPFCollector := newBPFCollectorFn
	originalNewInternalBPFCollector := newInternalBPFCollectorFn
	t.Cleanup(func() {
		newBPFCollectorFn = originalNewBPFCollector
		newInternalBPFCollectorFn = originalNewInternalBPFCollector
	})

	var promCollector *BPFCollector
	newBPFCollectorFn = func(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.MetricsConfig) *BPFCollector {
		var collected bool
		promCollector = &BPFCollector{
			promCfg:         cfg,
			commonCfg:       mpCfg,
			internalMetrics: ctxInfo.Metrics,
			promConnect:     &connector.PrometheusManager{},
			ctxInfo:         ctxInfo,
			log:             slog.With("component", "prom.BPFCollector"),
			probeLatencyDesc: prometheus.NewDesc(
				prometheus.BuildFQName("bpf", "probe", "latency_seconds"),
				"Latency of the probe in seconds",
				[]string{"probe_id", "probe_type", "probe_name"},
				nil,
			),
			mapSizeDesc: prometheus.NewDesc(
				prometheus.BuildFQName("bpf", "map", "entries_total"),
				"Number of entries in the map",
				[]string{"map_id", "map_name", "map_type", "max_entries"},
				nil,
			),
			probeMetrics: func() []ProbeMetrics {
				count := uint64(0)
				if !collected {
					count = 1
					collected = true
				}
				return []ProbeMetrics{{
					probeType: "kprobe",
					probeName: "tcp_connect",
					probeID:   "7",
					latency:   0.25,
					count:     count,
					program: &BPFProgram{
						runTime:  250 * time.Millisecond,
						runCount: 1,
					},
				}}
			},
			mapMetrics: func() []BpfMapMetrics {
				return []BpfMapMetrics{{
					mapType:    "hash",
					mapName:    "connections",
					mapID:      "3",
					maxEntries: 16,
					entries:    4,
				}}
			},
		}
		return promCollector
	}

	newInternalBPFCollectorFn = func(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.MetricsConfig) *BPFCollector {
		var collected bool
		return &BPFCollector{
			promCfg:         cfg,
			commonCfg:       mpCfg,
			internalMetrics: ctxInfo.Metrics,
			ctxInfo:         ctxInfo,
			probeMetrics: func() []ProbeMetrics {
				count := uint64(0)
				if !collected {
					count = 1
					collected = true
				}
				return []ProbeMetrics{{
					probeType: "kprobe",
					probeName: "tcp_connect",
					probeID:   "7",
					latency:   0.25,
					count:     count,
				}}
			},
			mapMetrics: func() []BpfMapMetrics {
				return []BpfMapMetrics{{
					mapType:    "hash",
					mapName:    "connections",
					mapID:      "3",
					maxEntries: 16,
					entries:    4,
				}}
			},
		}
	}

	runFn, err := BPFMetrics(ctxInfo, cfg, mpCfg)(context.Background())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runFn(ctx)

	promMetricsCh := make(chan prometheus.Metric, 4)
	promCollector.Collect(promMetricsCh)
	close(promMetricsCh)

	promProbeMetricFound := false
	for metric := range promMetricsCh {
		var promProbeMetric dto.Metric
		require.NoError(t, metric.Write(&promProbeMetric))
		if promProbeMetric.GetHistogram() == nil {
			continue
		}
		require.Equal(t, uint64(1), promProbeMetric.GetHistogram().GetSampleCount())
		promProbeMetricFound = true
	}
	require.True(t, promProbeMetricFound)

	require.Eventually(t, func() bool {
		probeMetric := gatheredMetric(t, registry, "obi_bpf_probe_latency_seconds", map[string]string{
			"probe_id":   "7",
			"probe_type": "kprobe",
			"probe_name": "tcp_connect",
		})
		mapEntriesMetric := gatheredMetric(t, registry, "obi_bpf_map_entries_total", map[string]string{
			"map_id":   "3",
			"map_name": "connections",
			"map_type": "hash",
		})
		mapMaxEntriesMetric := gatheredMetric(t, registry, "obi_bpf_map_max_entries_total", map[string]string{
			"map_id":   "3",
			"map_name": "connections",
			"map_type": "hash",
		})

		if probeMetric == nil || mapEntriesMetric == nil || mapMaxEntriesMetric == nil {
			return false
		}

		return probeMetric.GetHistogram().GetSampleCount() >= 1 &&
			mapEntriesMetric.GetGauge().GetValue() == 4 &&
			mapMaxEntriesMetric.GetGauge().GetValue() == 16
	}, time.Second, 10*time.Millisecond)
}

func TestBPFMetricsDoesNotStartInternalCollectorForZeroIntervalReporter(t *testing.T) {
	ctxInfo := &global.ContextInfo{
		Metrics: imetrics.NewPrometheusReporter(
			&imetrics.InternalMetricsConfig{},
			nil,
			prometheus.NewRegistry(),
		),
	}
	cfg := &PrometheusConfig{Port: 1}
	mpCfg := &perapp.MetricsConfig{Features: export.FeatureEBPF}

	originalNewBPFCollector := newBPFCollectorFn
	originalNewInternalBPFCollector := newInternalBPFCollectorFn
	t.Cleanup(func() {
		newBPFCollectorFn = originalNewBPFCollector
		newInternalBPFCollectorFn = originalNewInternalBPFCollector
	})

	newBPFCollectorFn = func(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.MetricsConfig) *BPFCollector {
		return &BPFCollector{
			promCfg:         cfg,
			commonCfg:       mpCfg,
			internalMetrics: ctxInfo.Metrics,
			promConnect:     &connector.PrometheusManager{},
			ctxInfo:         ctxInfo,
		}
	}

	var internalCollectorStarted atomic.Bool
	newInternalBPFCollectorFn = func(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.MetricsConfig) *BPFCollector {
		return &BPFCollector{
			promCfg:         cfg,
			commonCfg:       mpCfg,
			internalMetrics: ctxInfo.Metrics,
			ctxInfo:         ctxInfo,
			probeMetrics: func() []ProbeMetrics {
				internalCollectorStarted.Store(true)
				return nil
			},
			mapMetrics: func() []BpfMapMetrics {
				internalCollectorStarted.Store(true)
				return nil
			},
		}
	}

	runFn, err := BPFMetrics(ctxInfo, cfg, mpCfg)(context.Background())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	require.NotPanics(t, func() {
		runFn(ctx)
	})

	time.Sleep(10 * time.Millisecond)
	assert.False(t, internalCollectorStarted.Load())
}

func gatheredMetric(t *testing.T, registry *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
	t.Helper()

	metrics, err := registry.Gather()
	require.NoError(t, err)

	for _, family := range metrics {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricLabelsMatch(metric, labels) {
				return metric
			}
		}
	}

	return nil
}

func metricLabelsMatch(metric *dto.Metric, labels map[string]string) bool {
	if len(metric.GetLabel()) != len(labels) {
		return false
	}

	for _, label := range metric.GetLabel() {
		if labels[label.GetName()] != label.GetValue() {
			return false
		}
	}

	return true
}
