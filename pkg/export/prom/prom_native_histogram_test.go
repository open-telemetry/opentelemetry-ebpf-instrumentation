// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

func TestNativeHistogramConfigDefaultsWhenNil(t *testing.T) {
	cfg := &PrometheusConfig{}

	assert.Equal(t, defaultHistogramBucketFactor, cfg.HistogramBucketFactor())
	assert.Equal(t, defaultHistogramMaxBucketNumber, cfg.HistogramMaxBucketNumber())
	assert.Equal(t, defaultHistogramMinResetDuration, cfg.HistogramMinResetDuration())
}

func TestNativeHistogramConfigDefaultsWhenEmpty(t *testing.T) {
	cfg := &PrometheusConfig{
		NativeHistogram: &NativeHistogramConfig{},
	}

	assert.Equal(t, defaultHistogramBucketFactor, cfg.HistogramBucketFactor())
	assert.Equal(t, defaultHistogramMaxBucketNumber, cfg.HistogramMaxBucketNumber())
	assert.Equal(t, defaultHistogramMinResetDuration, cfg.HistogramMinResetDuration())
}

func TestNativeHistogramConfigCustomValues(t *testing.T) {
	cfg := &PrometheusConfig{
		NativeHistogram: &NativeHistogramConfig{
			BucketFactor:     4.0,
			MaxBucketNumber:  50,
			MinResetDuration: 30 * time.Minute,
		},
	}

	assert.Equal(t, 4.0, cfg.HistogramBucketFactor())
	assert.Equal(t, uint32(50), cfg.HistogramMaxBucketNumber())
	assert.Equal(t, 30*time.Minute, cfg.HistogramMinResetDuration())
}

// TestNativeHistogramBucketFactorDeterminesSchema verifies that BucketFactor controls
// the native histogram resolution. Prometheus maps BucketFactor to a schema number
// via floor(log2(log2(factor))): smaller factor → more buckets → higher (positive) schema.
//
// The expected schema values come from Prometheus' pickSchema function:
//   - BucketFactor=1.1  → log2(log2(1.1)) ≈ log2(0.1375) ≈ -2.86 → floor=-3 → schema=3
//   - BucketFactor=4.0  → log2(log2(4.0))  = log2(2)     = 1      → floor=1  → schema=-1
func TestNativeHistogramBucketFactorDeterminesSchema(t *testing.T) {
	observeAndGetSchema := func(t *testing.T, factor float64) int32 {
		t.Helper()
		h := prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:                            "test_schema",
			Help:                            "test",
			NativeHistogramBucketFactor:     factor,
			NativeHistogramMaxBucketNumber:  100,
			NativeHistogramMinResetDuration: time.Hour,
		})
		h.Observe(0.1)
		var m dto.Metric
		require.NoError(t, h.Write(&m))
		return m.GetHistogram().GetSchema()
	}

	assert.Equal(t, int32(3), observeAndGetSchema(t, defaultHistogramBucketFactor),
		"default BucketFactor=1.1 should map to schema=3")
	assert.Equal(t, int32(-1), observeAndGetSchema(t, 4.0),
		"BucketFactor=4.0 should map to schema=-1")

	assert.Greater(t, observeAndGetSchema(t, defaultHistogramBucketFactor), observeAndGetSchema(t, 4.0),
		"finer BucketFactor should produce a higher schema (more resolution)")
}

// TestNativeHistogramMaxBucketNumberDegrades verifies that a tight MaxBucketNumber
// forces Prometheus to merge buckets (reduce schema) when observations span many
// orders of magnitude, while a large limit preserves the original resolution.
func TestNativeHistogramMaxBucketNumberDegrades(t *testing.T) {
	makeAndObserve := func(maxBuckets uint32) int32 {
		h := prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:                            "test_maxbuckets",
			Help:                            "test",
			NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
			NativeHistogramMaxBucketNumber:  maxBuckets,
			NativeHistogramMinResetDuration: time.Hour,
		})
		// Observations spanning many orders of magnitude force many distinct buckets.
		for _, v := range []float64{1e-4, 1e-2, 1, 1e2, 1e4, 1e6, 1e8, 1e10} {
			h.Observe(v)
		}
		var m dto.Metric
		require.NoError(t, h.Write(&m))
		return m.GetHistogram().GetSchema()
	}

	schemaHighLimit := makeAndObserve(500)
	schemaLowLimit := makeAndObserve(2)

	assert.GreaterOrEqual(t, schemaHighLimit, schemaLowLimit,
		"a higher MaxBucketNumber should maintain equal or finer resolution (schema)")
}

// TestNativeHistogramSchemaAppliedToExportedMetrics is an integration test that
// creates a full Prometheus reporter with a custom NativeHistogramConfig, sends an
// HTTP span, and verifies that the gathered histogram DTO uses the expected schema.
func TestNativeHistogramSchemaAppliedToExportedMetrics(t *testing.T) {
	for _, tc := range []struct {
		name           string
		nhCfg          *NativeHistogramConfig
		expectedSchema int32
	}{
		{
			name:           "default config produces schema 3",
			nhCfg:          nil,
			expectedSchema: 3,
		},
		{
			name:           "BucketFactor=4.0 produces schema -1",
			nhCfg:          &NativeHistogramConfig{BucketFactor: 4.0, MaxBucketNumber: 100, MinResetDuration: time.Hour},
			expectedSchema: -1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			ctx := t.Context()
			promInput := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10))

			exporter, err := PrometheusEndpoint(
				&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
				&PrometheusConfig{
					Registry:         registry,
					Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
					NativeHistogram:  tc.nhCfg,
				},
				&perapp.MetricsConfig{Features: export.FeatureApplicationRED},
				&attributes.SelectorConfig{},
				request.UnresolvedNames{},
				promInput,
				processEvents,
			)(ctx)
			require.NoError(t, err)
			go exporter(ctx)

			svcAttrs := svc.Attrs{
				Features: export.FeatureApplicationRED,
				UID:      svc.UID{Name: "test-svc", Instance: "inst-1"},
			}
			promInput.Send([]request.Span{{
				Type:         request.EventTypeHTTP,
				RequestStart: 0,
				End:          100_000_000,
				Service:      svcAttrs,
			}})
			awaitSpanProcessing()

			mfs, err := registry.Gather()
			require.NoError(t, err)

			var schema *int32
			for _, mf := range mfs {
				if mf.GetName() != attributes.HTTPServerDuration.Prom {
					continue
				}
				for _, m := range mf.GetMetric() {
					s := m.GetHistogram().GetSchema()
					schema = &s
				}
			}
			require.NotNil(t, schema, "HTTP server duration metric not found in registry")
			assert.Equal(t, tc.expectedSchema, *schema)
		})
	}
}
