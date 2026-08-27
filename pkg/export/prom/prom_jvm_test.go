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
	service := svc.Attrs{
		UID:      svc.UID{Name: "orders", Namespace: "prod", Instance: "orders-1"},
		ProcPID:  101,
		Features: export.FeatureApplicationRuntime,
	}
	processEvent := func(service svc.Attrs, eventType exec.ProcessEventType, generation uint64) exec.ProcessEvent {
		file := exec.New(exec.Init{Pid: service.ProcPID, Service: service})
		file.SetRuntimeMetricGeneration(service.ProcPID, generation)
		return exec.ProcessEvent{
			Type: eventType,
			File: file,
		}
	}
	reporter.handleProcessEvent(
		processEvent(service, exec.ProcessEventCreated, 1),
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

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service:    service,
		Generation: 1,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			RuntimeValues: &jvmruntime.JVMRuntimeValues{
				LoadedClassCount:        43,
				TotalLoadedClassCount:   100,
				UnloadedClassCount:      5,
				ThreadCount:             10,
				DaemonThreadCount:       4,
				AvailableProcessorCount: 8,
				ProcessCPUTimeNS:        2_000_000_000,
				RecentCPUUtilization:    0.25,
			},
		},
	}})

	labels := map[string]string{
		"service_name":        "orders",
		"service_namespace":   "prod",
		"service_instance_id": "orders-1",
	}
	assert.InEpsilon(t, 100.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 5.0,
		gatheredMetric(t, registry, "jvm_class_unloaded_total", labels).GetCounter().GetValue(), 0)
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

	secondService := service
	secondService.ProcPID = 202
	reporter.handleProcessEvent(
		processEvent(secondService, exec.ProcessEventCreated, 1),
		slog.Default(),
	)

	// Discovering another PID for the same service must not reset its counters.
	assert.InEpsilon(t, 100.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service:    secondService,
		Generation: 1,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			RuntimeValues: &jvmruntime.JVMRuntimeValues{
				TotalLoadedClassCount: 40,
				UnloadedClassCount:    2,
				ProcessCPUTimeNS:      1_000_000_000,
			},
		},
	}})

	assert.InEpsilon(t, 140.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 7.0,
		gatheredMetric(t, registry, "jvm_class_unloaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 3.0,
		gatheredMetric(t, registry, "jvm_cpu_time_seconds_total", labels).GetCounter().GetValue(), 0)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service:    service,
		Generation: 1,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			RuntimeValues: &jvmruntime.JVMRuntimeValues{
				TotalLoadedClassCount: 110,
				UnloadedClassCount:    6,
				ProcessCPUTimeNS:      3_000_000_000,
			},
		},
	}})

	assert.InEpsilon(t, 150.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 8.0,
		gatheredMetric(t, registry, "jvm_class_unloaded_total", labels).GetCounter().GetValue(), 0)
	assert.InEpsilon(t, 4.0,
		gatheredMetric(t, registry, "jvm_cpu_time_seconds_total", labels).GetCounter().GetValue(), 0)

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{{
		Service:    service,
		Generation: 1,
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{
			RuntimeValues: &jvmruntime.JVMRuntimeValues{
				TotalLoadedClassCount: 110,
				UnloadedClassCount:    6,
				ProcessCPUTimeNS:      3_000_000_000,
				RecentCPUUtilization:  -1,
			},
		},
	}})
	assert.Nil(t, gatheredMetric(t, registry, "jvm_cpu_recent_utilization_ratio", labels))

	reporter.handleProcessEvent(
		processEvent(service, exec.ProcessEventTerminated, 1),
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
		processEvent(service, exec.ProcessEventCreated, 2),
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
		processEvent(secondService, exec.ProcessEventTerminated, 1),
		slog.Default(),
	)
	assert.InEpsilon(t, 270.0,
		gatheredMetric(t, registry, "jvm_class_loaded_total", labels).GetCounter().GetValue(), 0)
	reporter.handleProcessEvent(
		processEvent(service, exec.ProcessEventTerminated, 2),
		slog.Default(),
	)
	assert.Nil(t, gatheredMetric(t, registry, "jvm_class_loaded_total", labels))
	assert.Nil(t, gatheredMetric(t, registry, "jvm_class_unloaded_total", labels))
	assert.Nil(t, gatheredMetric(t, registry, "jvm_cpu_time_seconds_total", labels))

	reporter.collectRuntimeMetrics([]runtimemetrics.RuntimeMetricSnapshot{reusedSnapshot})
	assert.Nil(t, gatheredMetric(t, registry, "jvm_class_loaded_total", labels),
		"an in-flight snapshot must not recreate counters after termination")
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
