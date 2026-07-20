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
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestRuntimeMetricsReporterRecordsJVMMemoryPoolUsed(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter, err := newReporter(
		t.Context(),
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.MetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		nil,
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
		nil,
	)
	require.NoError(t, err)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
			Features: export.FeatureApplicationRuntime,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			Kind:       jvmruntime.JVMMetricMemoryUsed,
			MemoryType: jvmruntime.JVMMemoryTypeHeap,
			PoolName:   "G1 Old Gen",
			GCPhase:    jvmruntime.JVMGCPhaseAfter,
			ValueBytes: 42,
		},
	}})

	metric := gatheredMetric(t, registry, "jvm_memory_used_bytes", map[string]string{
		"service_name":         "orders",
		"service_namespace":    "prod",
		"service_instance_id":  "orders-1",
		"jvm_memory_type":      "heap",
		"jvm_memory_pool_name": "G1 Old Gen",
	})
	require.NotNil(t, metric)
	assert.InEpsilon(t, 42.0, metric.GetGauge().GetValue(), 0)
}

func TestRuntimeMetricsReporterDropsJVMServiceWithoutRuntimeFeature(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter, err := newReporter(
		t.Context(),
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.MetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		nil,
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
		nil,
	)
	require.NoError(t, err)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
			Features: export.FeatureApplicationRED,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			Kind:       jvmruntime.JVMMetricMemoryUsed,
			MemoryType: jvmruntime.JVMMemoryTypeHeap,
			PoolName:   "G1 Old Gen",
			GCPhase:    jvmruntime.JVMGCPhaseAfter,
			ValueBytes: 42,
		},
	}})

	assert.Nil(t, gatheredMetric(t, registry, "jvm_memory_used_bytes", map[string]string{
		"service_name":         "orders",
		"service_namespace":    "prod",
		"service_instance_id":  "orders-1",
		"jvm_memory_type":      "heap",
		"jvm_memory_pool_name": "G1 Old Gen",
	}))
}
