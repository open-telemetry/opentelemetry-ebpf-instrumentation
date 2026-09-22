// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

func TestExpirerDeleteLabelValues(t *testing.T) {
	registry := prometheus.NewRegistry()
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "expirer_delete_test"}, []string{"service"})
	expirer := NewExpirer[prometheus.Gauge](gauge.MetricVec, time.Now, time.Minute)
	registry.MustRegister(expirer)

	expirer.WithLabelValues("orders").Metric.Set(1)
	require.NotNil(t, gatheredMetric(t, registry, "expirer_delete_test", map[string]string{"service": "orders"}))

	expirer.DeleteLabelValues("orders")
	assert.Nil(t, gatheredMetric(t, registry, "expirer_delete_test", map[string]string{"service": "orders"}))
	assert.Empty(t, expirer.entries.All())
}

func TestExpirerDistinctServiceLabelsWithColons(t *testing.T) {
	selection := attributes.Selection{
		attributes.HTTPServerDuration.Section: {Include: []string{"service.name", "service.namespace"}},
	}
	selector, err := attributes.NewAttrSelector(attributes.GroupPrometheus,
		&attributes.SelectorConfig{SelectionCfg: selection})
	require.NoError(t, err)
	getters := attributes.PrometheusGetters(request.SpanPromGetters(request.UnresolvedNames{}),
		selector.For(attributes.HTTPServerDuration))

	registry := prometheus.NewRegistry()
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "expirer_service_labels_total"},
		labelNames(getters))
	expirer := NewExpirer[prometheus.Counter](counter.MetricVec, time.Now, time.Minute)
	registry.MustRegister(expirer)

	services := [][2]string{{"checkout:blue", "prod"}, {"checkout", "blue:prod"}}
	for _, service := range services {
		span := &request.Span{}
		span.Service.UID.Name = service[0]
		span.Service.UID.Namespace = service[1]
		expirer.WithLabelValues(labelValues(span, getters)...).Metric.Inc()
	}

	for _, service := range services {
		metric := gatheredMetric(t, registry, "expirer_service_labels_total", map[string]string{
			"service_name": service[0], "service_namespace": service[1],
		})
		require.NotNil(t, metric)
		assert.InDelta(t, 1, metric.GetCounter().GetValue(), 0)
	}
}
