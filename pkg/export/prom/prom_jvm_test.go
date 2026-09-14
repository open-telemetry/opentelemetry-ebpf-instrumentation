// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"log/slog"
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

func TestRuntimeMetricsReporterRecordsJVMMetrics(t *testing.T) {
	t.Run("memory pool", testJVMRuntimeMemoryPool)
	t.Run("current runtime values", testJVMRuntimeCurrentValues)
	t.Run("process lifecycle", testJVMRuntimeProcessLifecycle)
}

func testJVMRuntimeMemoryPool(t *testing.T) {
	reporter, registry := newJVMRuntimeMetricsTestReporter(t)
	service := jvmRuntimeMetricsTestService()
	reporter.handleProcessEvent(
		jvmRuntimeMetricsProcessEvent(service, exec.ProcessEventCreated, 1),
		slog.Default(),
	)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service:    service,
		Generation: 1,
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

func testJVMRuntimeCurrentValues(t *testing.T) {
	reporter, registry := newJVMRuntimeMetricsTestReporter(t)
	service := jvmRuntimeMetricsTestService()
	reporter.handleProcessEvent(
		jvmRuntimeMetricsProcessEvent(service, exec.ProcessEventCreated, 1),
		slog.Default(),
	)

	values := jvmruntime.JVMRuntimeValues{
		LoadedClassCount:        43,
		TotalLoadedClassCount:   100,
		UnloadedClassCount:      0,
		ThreadCount:             10,
		DaemonThreadCount:       4,
		AvailableProcessorCount: 8,
		ProcessCPUTimeNS:        2_000_000_000,
		RecentCPUUtilization:    0.25,
	}
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service: service,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			Kind:       jvmruntime.JVMMetricGCDuration,
			GCName:     "G1 Young Generation",
			GCAction:   "end of minor GC",
			DurationNS: 25_000_000,
		},
	}})
	gcDuration := gatheredMetric(t, registry, "jvm_gc_duration_seconds", map[string]string{
		"service_name":        "orders",
		"service_namespace":   "prod",
		"service_instance_id": "orders-1",
		"jvm_gc_name":         "G1 Young Generation",
		"jvm_gc_action":       "end of minor GC",
	})
	require.NotNil(t, gcDuration)
	assert.Equal(t, uint64(1), gcDuration.GetHistogram().GetSampleCount())
	assert.InEpsilon(t, 0.025, gcDuration.GetHistogram().GetSampleSum(), 0)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service:    service,
		Generation: 1,
		JVM:        &runtimemetrics.JVMRuntimeMetricSnapshot{RuntimeValues: &values},
	}})

	labels := jvmRuntimeMetricsTestLabels()
	assert.InEpsilon(t, 100.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)
	unloaded := gatheredMetric(t, registry, "jvm_class_unloaded_total", labels)
	require.NotNil(t, unloaded)
	assert.Zero(t, unloaded.GetCounter().GetValue())
	assert.InEpsilon(t, 43.0,
		gatheredMetric(t, registry, "jvm_class_count", labels).GetGauge().GetValue(), 0)
	assert.InEpsilon(t, 4.0,
		gatheredMetric(t, registry, "jvm_thread_count", map[string]string{
			"service_name":        "orders",
			"service_namespace":   "prod",
			"service_instance_id": "orders-1",
			"jvm_thread_daemon":   "true",
		}).GetGauge().GetValue(), 0)
	assert.InEpsilon(t, 6.0,
		gatheredMetric(t, registry, "jvm_thread_count", map[string]string{
			"service_name":        "orders",
			"service_namespace":   "prod",
			"service_instance_id": "orders-1",
			"jvm_thread_daemon":   "false",
		}).GetGauge().GetValue(), 0)
	assert.InEpsilon(t, 2.0,
		gatheredMetric(t, registry, "jvm_cpu_time_seconds_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 8.0,
		gatheredMetric(t, registry, "jvm_cpu_count", labels).GetGauge().GetValue(), 0)
	assert.InEpsilon(t, 0.25,
		gatheredMetric(t, registry, "jvm_cpu_recent_utilization_ratio", labels).GetGauge().GetValue(), 0)

	values.RecentCPUUtilization = -1
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service:    service,
		Generation: 1,
		JVM:        &runtimemetrics.JVMRuntimeMetricSnapshot{RuntimeValues: &values},
	}})
	assert.Nil(t, gatheredMetric(t, registry, "jvm_cpu_recent_utilization_ratio", labels))
}

func testJVMRuntimeProcessLifecycle(t *testing.T) {
	reporter, registry := newJVMRuntimeMetricsTestReporter(t)
	service := jvmRuntimeMetricsTestService()
	reporter.handleProcessEvent(
		jvmRuntimeMetricsProcessEvent(service, exec.ProcessEventCreated, 1),
		slog.Default(),
	)

	initialValues := jvmruntime.JVMRuntimeValues{
		TotalLoadedClassCount: 100,
		UnloadedClassCount:    0,
		ProcessCPUTimeNS:      2_000_000_000,
	}
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service:    service,
		Generation: 1,
		JVM:        &runtimemetrics.JVMRuntimeMetricSnapshot{RuntimeValues: &initialValues},
	}})

	labels := jvmRuntimeMetricsTestLabels()
	assert.InEpsilon(t, 100.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)

	secondService := service
	secondService.ProcPID = 202
	reporter.handleProcessEvent(
		jvmRuntimeMetricsProcessEvent(secondService, exec.ProcessEventCreated, 1),
		slog.Default(),
	)

	// Discovering another PID for the same service must not reset its counters.
	assert.InEpsilon(t, 100.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)

	secondValues := jvmruntime.JVMRuntimeValues{
		TotalLoadedClassCount: 40,
		UnloadedClassCount:    2,
		ProcessCPUTimeNS:      1_000_000_000,
	}
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service:    secondService,
		Generation: 1,
		JVM:        &runtimemetrics.JVMRuntimeMetricSnapshot{RuntimeValues: &secondValues},
	}})

	assert.InEpsilon(t, 140.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 2.0,
		gatheredMetric(t, registry, "jvm_class_unloaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 3.0,
		gatheredMetric(t, registry, "jvm_cpu_time_seconds_total", labels).GetCounter().GetValue(), 0)

	updatedValues := jvmruntime.JVMRuntimeValues{
		TotalLoadedClassCount: 110,
		UnloadedClassCount:    6,
		ProcessCPUTimeNS:      3_000_000_000,
	}
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service:    service,
		Generation: 1,
		JVM:        &runtimemetrics.JVMRuntimeMetricSnapshot{RuntimeValues: &updatedValues},
	}})

	assert.InEpsilon(t, 150.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 8.0,
		gatheredMetric(t, registry, "jvm_class_unloaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 4.0,
		gatheredMetric(t, registry, "jvm_cpu_time_seconds_total", labels).GetCounter().GetValue(), 0)

	reporter.handleProcessEvent(
		jvmRuntimeMetricsProcessEvent(service, exec.ProcessEventTerminated, 1),
		slog.Default(),
	)
	assert.InEpsilon(t, 150.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)
	assert.NotContains(t, reporter.jvmRuntimeMetrics.counters.values,
		runtimeMetricLabelsKey(append(
			append([]string{attributes.JVMClassLoaded.Prom}, runtimeServiceLabelValuesForService(service)...),
			jvmRuntimeSource(service.ProcPID, 1),
		)))

	reporter.handleProcessEvent(
		jvmRuntimeMetricsProcessEvent(service, exec.ProcessEventCreated, 2),
		slog.Default(),
	)
	reusedSnapshot := runtimemetrics.RuntimeMetricSnapshot{
		Service:    service,
		Generation: 2,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			RuntimeValues: &jvmruntime.JVMRuntimeValues{
				TotalLoadedClassCount: 120,
				UnloadedClassCount:    7,
				ProcessCPUTimeNS:      4_000_000_000,
			},
		},
	}
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{reusedSnapshot})
	assert.InEpsilon(t, 270.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 15.0,
		gatheredMetric(t, registry, "jvm_class_unloaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 8.0,
		gatheredMetric(t, registry, "jvm_cpu_time_seconds_total", labels).GetCounter().GetValue(), 0)

	staleSnapshot := reusedSnapshot
	staleSnapshot.Generation = 1
	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{staleSnapshot})
	assert.InEpsilon(t, 270.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0,
		"an old JVM generation must be rejected after PID reuse")

	reporter.handleProcessEvent(
		jvmRuntimeMetricsProcessEvent(secondService, exec.ProcessEventTerminated, 1),
		slog.Default(),
	)
	assert.InEpsilon(t, 270.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)
	reporter.handleProcessEvent(
		jvmRuntimeMetricsProcessEvent(service, exec.ProcessEventTerminated, 2),
		slog.Default(),
	)
	assert.Nil(t, gatheredMetric(t, registry, "jvm_class_loaded_total", labels))
	assert.Nil(t, gatheredMetric(t, registry, "jvm_class_unloaded_total", labels))
	assert.Nil(t, gatheredMetric(t, registry, "jvm_cpu_time_seconds_total", labels))

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{reusedSnapshot})
	assert.Nil(t, gatheredMetric(t, registry, "jvm_class_loaded_total", labels),
		"an in-flight snapshot must not recreate counters after termination")
}

func newJVMRuntimeMetricsTestReporter(t *testing.T) (*metricsReporter, *prometheus.Registry) {
	t.Helper()

	registry := prometheus.NewRegistry()
	reporter, err := newReporter(
		t.Context(),
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		nil,
		msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1)),
		nil,
	)
	require.NoError(t, err)
	return reporter, registry
}

func jvmRuntimeMetricsTestService() svc.Attrs {
	return svc.Attrs{
		UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
		ProcPID:  101,
		Features: export.FeatureApplicationRuntime,
	}
}

func jvmRuntimeMetricsTestLabels() map[string]string {
	return map[string]string{
		"service_name":        "orders",
		"service_namespace":   "prod",
		"service_instance_id": "orders-1",
	}
}

func jvmRuntimeMetricsProcessEvent(
	service svc.Attrs,
	eventType exec.ProcessEventType,
	generation uint64,
) exec.ProcessEvent {
	file := exec.New(exec.Init{Pid: service.ProcPID, Service: service})
	file.SetRuntimeMetricGeneration(service.ProcPID, generation)
	return exec.ProcessEvent{Type: eventType, File: file}
}

func TestRuntimeMetricsReporterDropsJVMServiceWithoutRuntimeFeature(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter, err := newReporter(
		t.Context(),
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
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

// The service.name / service.namespace metric-attribute defaults are off, but
// that only governs metric families whose labels come from AttrSelector. The
// Prometheus runtime collectors build their label sets directly --
// runtimeServiceLabels for JVM and Node.js, labelNamesTargetInfo for Go -- so
// runtime series keep both labels regardless of the default and of
// extra_group_attributes. This pins that exception until the runtime
// collectors are routed through their attribute definitions.
func TestRuntimeMetricsKeepServiceLabelsRegardlessOfDefaults(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter, err := newReporter(
		t.Context(),
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&PrometheusConfig{Registry: registry, TTL: time.Minute},
		&perapp.GlobalMetricsConfig{Features: export.FeatureApplicationRuntime},
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
	require.NotNil(t, metric, "runtime metrics must keep service_name and service_namespace")
}
