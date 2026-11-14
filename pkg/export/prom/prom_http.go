// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/expire"
)

type httpActiveRequestsMetric struct {
	mu      sync.Mutex
	desc    *prometheus.Desc
	getters []attributes.Field[*request.Span, string]
	series  map[string]*httpActiveRequestsSeries
	clock   expire.Clock
	ttl     time.Duration
}

type httpActiveRequestsSeries struct {
	labels  []string
	count   int64
	updated time.Time
}

func newHTTPActiveRequestsMetric(getters []attributes.Field[*request.Span, string], clock expire.Clock, ttl time.Duration) *httpActiveRequestsMetric {
	return &httpActiveRequestsMetric{
		desc: prometheus.NewDesc(attributes.HTTPServerActiveRequests.Prom,
			"Number of active HTTP server requests.", labelNames(getters), nil),
		getters: getters,
		series:  map[string]*httpActiveRequestsSeries{},
		clock:   clock,
		ttl:     ttl,
	}
}

func (r *metricsReporter) observeHTTPServerRequests(deltas []request.HTTPServerRequestDelta) {
	m := r.httpActiveRequests
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range deltas {
		delta := &deltas[i]
		span := &delta.Span
		if delta.Delta == 0 || !span.Service.ExportModes.CanExportMetrics() || !span.Service.Features.HTTPServerActiveRequests() {
			continue
		}
		labels := labelValues(span, m.getters)
		key := expire.LabelsKey(labels)
		series := m.series[key]
		if series == nil {
			if delta.Delta < 0 {
				continue
			}
			series = &httpActiveRequestsSeries{labels: labels}
			m.series[key] = series
		}
		series.count += delta.Delta
		series.updated = m.clock()
	}
}

func (m *httpActiveRequestsMetric) Describe(out chan<- *prometheus.Desc) {
	out <- m.desc
}

func (m *httpActiveRequestsMetric) Collect(out chan<- prometheus.Metric) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, series := range m.series {
		// A request can remain active longer than the metric TTL.
		if series.count == 0 && m.ttl > 0 && m.clock().Sub(series.updated) > m.ttl {
			delete(m.series, key)
			continue
		}
		out <- prometheus.MustNewConstMetric(m.desc, prometheus.GaugeValue, float64(series.count), series.labels...)
	}
}
