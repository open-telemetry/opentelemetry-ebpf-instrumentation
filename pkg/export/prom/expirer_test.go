// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
