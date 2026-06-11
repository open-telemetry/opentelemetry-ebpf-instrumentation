// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestJVMRuntimeMetricsReporterRecordsHeapSummary(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newJVMRuntimeMetricsReporter(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.MetricsConfig{Features: export.FeatureApplicationJVM},
		&attributes.SelectorConfig{},
	)

	reporter.observe(jvmruntime.JVMRuntimeEvent{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
			Features: export.FeatureApplicationJVM,
		},
		Kind:       jvmruntime.JVMMetricBeylaHeapUsed,
		GCPhase:    jvmruntime.JVMGCPhaseAfter,
		ValueBytes: 42,
	})

	metric := gatheredMetric(t, registry, "beyla_jvm_heap_used_bytes", map[string]string{
		"service_name":        "orders",
		"service_namespace":   "prod",
		"service_instance_id": "orders-1",
		"jvm_gc_phase":        "after",
	})
	require.NotNil(t, metric)
	assert.InEpsilon(t, 42.0, metric.GetGauge().GetValue(), 0)
}

func TestJVMRuntimeMetricsReporterDropsServiceWithoutJVMFeature(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newJVMRuntimeMetricsReporter(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.MetricsConfig{Features: export.FeatureApplicationJVM},
		&attributes.SelectorConfig{},
	)

	reporter.observe(jvmruntime.JVMRuntimeEvent{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
			Features: export.FeatureApplicationRED,
		},
		Kind:       jvmruntime.JVMMetricBeylaHeapUsed,
		GCPhase:    jvmruntime.JVMGCPhaseAfter,
		ValueBytes: 42,
	})

	assert.Nil(t, gatheredMetric(t, registry, "beyla_jvm_heap_used_bytes", map[string]string{
		"service_name":        "orders",
		"service_namespace":   "prod",
		"service_instance_id": "orders-1",
		"jvm_gc_phase":        "after",
	}))
}
