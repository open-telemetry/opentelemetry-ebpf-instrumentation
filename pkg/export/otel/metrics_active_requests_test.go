// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/activerequests"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

type activeRequestTemporalityExporter struct {
	sdkmetric.Exporter
	temporality metricdata.Temporality
}

func (e activeRequestTemporalityExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return e.temporality
}

func activeRequestCount(service svc.Attrs, method string, value int64) activerequests.Count {
	return activerequests.Count{
		Service: service,
		Attributes: attribute.NewSet(
			attribute.String("http.request.method", method),
			attribute.String("url.scheme", "http"),
		),
		Value: value,
	}
}

func activeRequestValues(t *testing.T, metrics []metricdata.ResourceMetrics) map[string]int64 {
	t.Helper()
	values := map[string]int64{}
	for _, rm := range metrics {
		instance, ok := rm.Resource.Set().Value("service.instance.id")
		require.True(t, ok)
		require.Len(t, rm.ScopeMetrics, 1)
		require.Len(t, rm.ScopeMetrics[0].Metrics, 1)
		sum, ok := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Sum[int64])
		require.True(t, ok)
		assert.False(t, sum.IsMonotonic)
		for _, point := range sum.DataPoints {
			method, _ := point.Attributes.Value("http.request.method")
			scheme, _ := point.Attributes.Value("url.scheme")
			values[instance.AsString()+"/"+method.AsString()+"/"+scheme.AsString()] = point.Value
		}
	}
	return values
}

func TestHTTPActiveRequestsCountsAndTTL(t *testing.T) {
	mr := &MetricsReporter{
		cfg:      &otelcfg.MetricsConfig{TTL: time.Minute},
		exporter: activeRequestTemporalityExporter{temporality: metricdata.CumulativeTemporality},
	}
	state := activeRequestOTLPState{series: map[activeRequestSeriesKey]*activeRequestSeries{}}
	now := time.Unix(100, 0)
	service := svc.Attrs{UID: svc.UID{Name: "service", Instance: "one"}}
	other := svc.Attrs{UID: svc.UID{Name: "other", Instance: "two"}}

	metrics := state.resourceMetrics(mr, []activerequests.Count{
		activeRequestCount(service, "GET", 5),
		activeRequestCount(service, "POST", 1),
		activeRequestCount(other, "GET", 1),
	}, now)
	assert.Equal(t, map[string]int64{"one/GET/http": 5, "one/POST/http": 1, "two/GET/http": 1},
		activeRequestValues(t, metrics))

	now = now.Add(30 * time.Second)
	metrics = state.resourceMetrics(mr, []activerequests.Count{activeRequestCount(service, "GET", 1)}, now)
	assert.Equal(t, map[string]int64{"one/GET/http": 1, "one/POST/http": 0, "two/GET/http": 0},
		activeRequestValues(t, metrics))

	now = now.Add(31 * time.Second)
	metrics = state.resourceMetrics(mr, []activerequests.Count{activeRequestCount(service, "GET", 1)}, now)
	assert.Equal(t, map[string]int64{"one/GET/http": 1}, activeRequestValues(t, metrics))
}

func TestHTTPActiveRequestsDeltaTemporality(t *testing.T) {
	mr := &MetricsReporter{
		cfg:      &otelcfg.MetricsConfig{TTL: time.Minute},
		exporter: activeRequestTemporalityExporter{temporality: metricdata.DeltaTemporality},
	}
	state := activeRequestOTLPState{series: map[activeRequestSeriesKey]*activeRequestSeries{}}
	service := svc.Attrs{UID: svc.UID{Name: "service", Instance: "one"}}
	now := time.Unix(100, 0)

	metrics := state.resourceMetrics(mr, []activerequests.Count{activeRequestCount(service, "GET", 5)}, now)
	assert.Equal(t, map[string]int64{"one/GET/http": 5}, activeRequestValues(t, metrics))

	now = now.Add(time.Second)
	metrics = state.resourceMetrics(mr, []activerequests.Count{activeRequestCount(service, "GET", 3)}, now)
	assert.Equal(t, map[string]int64{"one/GET/http": -2}, activeRequestValues(t, metrics))

	now = now.Add(time.Second)
	metrics = state.resourceMetrics(mr, nil, now)
	assert.Equal(t, map[string]int64{"one/GET/http": -3}, activeRequestValues(t, metrics))
}

func TestHTTPActiveRequestsEmitsZeroBeforeSeriesExpires(t *testing.T) {
	mr := &MetricsReporter{
		cfg:      &otelcfg.MetricsConfig{TTL: time.Minute},
		exporter: activeRequestTemporalityExporter{temporality: metricdata.CumulativeTemporality},
	}
	state := activeRequestOTLPState{series: map[activeRequestSeriesKey]*activeRequestSeries{}}
	service := svc.Attrs{UID: svc.UID{Name: "service", Instance: "one"}}
	now := time.Unix(100, 0)

	state.resourceMetrics(mr, []activerequests.Count{activeRequestCount(service, "GET", 1)}, now)
	metrics := state.resourceMetrics(mr, nil, now.Add(2*time.Minute))
	assert.Equal(t, map[string]int64{"one/GET/http": 0}, activeRequestValues(t, metrics))

	metrics = state.resourceMetrics(mr, nil, now.Add(3*time.Minute))
	assert.Empty(t, activeRequestValues(t, metrics))
}
