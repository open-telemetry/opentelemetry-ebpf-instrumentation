// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

type countingMetricsReporter struct {
	imetrics.NoopReporter
	exports    atomic.Int64
	exportErrs atomic.Int64
}

func (c *countingMetricsReporter) OTELMetricExport(metrics int) { c.exports.Add(int64(metrics)) }
func (c *countingMetricsReporter) OTELMetricExportError(error)  { c.exportErrs.Add(1) }

func oneResourceMetric() *metricdata.ResourceMetrics {
	return &metricdata.ResourceMetrics{
		ScopeMetrics: []metricdata.ScopeMetrics{{
			Metrics: []metricdata.Metrics{{
				Name: "test",
				Data: metricdata.Sum[int64]{
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
					DataPoints:  []metricdata.DataPoint[int64]{{Value: 1}},
				},
			}},
		}},
	}
}

func TestMetricsExportInternalMetrics(t *testing.T) {
	t.Run("successful export is counted", func(t *testing.T) {
		coll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer coll.Close()

		base, err := otlpmetrichttp.New(context.Background(),
			otlpmetrichttp.WithEndpointURL(coll.URL+"/v1/metrics"),
			otlpmetrichttp.WithInsecure())
		require.NoError(t, err)
		t.Cleanup(func() { _ = base.Shutdown(context.Background()) })

		rep := &countingMetricsReporter{}
		wrapped := instrumentMetricsExporter(rep, base)

		require.NoError(t, wrapped.Export(context.Background(), oneResourceMetric()))
		assert.Positive(t, rep.exports.Load(), "a successful export must increment obi.otel.metric.exports")
		assert.Zero(t, rep.exportErrs.Load(), "a successful export must not increment obi.otel.metric.export.errors")
	})

	t.Run("failed export is counted", func(t *testing.T) {
		coll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		deadEndpoint := coll.URL
		coll.Close()

		base, err := otlpmetrichttp.New(context.Background(),
			otlpmetrichttp.WithEndpointURL(deadEndpoint+"/v1/metrics"),
			otlpmetrichttp.WithInsecure(),
			otlpmetrichttp.WithTimeout(500*time.Millisecond),
			otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}))
		require.NoError(t, err)
		t.Cleanup(func() { _ = base.Shutdown(context.Background()) })

		rep := &countingMetricsReporter{}
		wrapped := instrumentMetricsExporter(rep, base)

		require.Error(t, wrapped.Export(context.Background(), oneResourceMetric()))
		assert.Positive(t, rep.exportErrs.Load(), "a failed export must increment obi.otel.metric.export.errors")
		assert.Zero(t, rep.exports.Load(), "a failed export must not increment obi.otel.metric.exports")
	})
}
