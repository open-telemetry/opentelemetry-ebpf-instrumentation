// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestRuntimeMetricsReporterShouldReportSnapshot(t *testing.T) {
	exportMetrics := services.NewExportModes()
	exportMetrics.AllowMetrics()
	blockMetrics := services.NewExportModes()

	reporter := &RuntimeMetricsReporter{
		runtimeEnabled: runtimemetrics.Enabled{Runtime: true},
	}

	require.True(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableGolang},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{},
	}))
	require.True(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationRuntime,
			ExportModes: exportMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{Kind: jvmruntime.JVMMetricMemoryUsed},
	}))

	assert.False(t, (&RuntimeMetricsReporter{runtimeEnabled: runtimemetrics.Enabled{Runtime: false}}).shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableGolang},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{},
	}))
	assert.False(t, (&RuntimeMetricsReporter{runtimeEnabled: runtimemetrics.Enabled{Runtime: false}}).shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationRuntime,
			ExportModes: exportMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationRED,
			ExportModes: exportMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationRuntime,
			ExportModes: blockMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{}))
}

func TestSetupRuntimeMetersUsesSharedRuntimeGate(t *testing.T) {
	provider := metric.NewMeterProvider()
	defer func() {
		require.NoError(t, provider.Shutdown(t.Context()))
	}()
	meter := provider.Meter(reporterName)

	disabled := RuntimeMetrics{ctx: t.Context()}
	require.NoError(t, setupRuntimeMeters(&disabled, meter, time.Minute, runtimemetrics.Enabled{}))
	assert.Nil(t, disabled.goMetrics.memoryLimit)
	assert.Nil(t, disabled.jvmMetrics.memoryUsed)

	enabled := RuntimeMetrics{ctx: t.Context()}
	require.NoError(t, setupRuntimeMeters(&enabled, meter, time.Minute, runtimemetrics.Enabled{Runtime: true}))
	assert.NotNil(t, enabled.goMetrics.memoryLimit)
	assert.NotNil(t, enabled.jvmMetrics.memoryUsed)
}

func TestGoRuntimeCPUTimeCounterDeltaResetAndRemoval(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(t.Context()))
	})

	var metrics goRuntimeMetrics
	require.NoError(t, setupGoRuntimeMeters(&metrics, provider.Meter(reporterName)))

	cpu := &runtimemetrics.GoRuntimeCPUTimeSnapshot{UserTime: 100}
	recordGoRuntimeCPUTime(t.Context(), &metrics, cpu)
	points := collectGoRuntimeCPUTimePoints(t, reader)
	user := points[goCPUTimePointKey{state: "user"}]
	assert.InDelta(t, float64(100*time.Nanosecond)/float64(time.Second), user.Value, 1e-12)
	assert.False(t, user.Attributes.HasValue(semconv.GoCPUDetailedStateKey))
	gcAssist := points[goCPUTimePointKey{state: "gc", detailedState: "gc/mark/assist"}]
	assert.True(t, gcAssist.Attributes.HasValue(semconv.GoCPUDetailedStateKey))

	cpu.UserTime = 250
	recordGoRuntimeCPUTime(t.Context(), &metrics, cpu)
	points = collectGoRuntimeCPUTimePoints(t, reader)
	assert.InDelta(t, float64(250*time.Nanosecond)/float64(time.Second),
		points[goCPUTimePointKey{state: "user"}].Value, 1e-12)

	cpu.UserTime = 50
	recordGoRuntimeCPUTime(t.Context(), &metrics, cpu)
	points = collectGoRuntimeCPUTimePoints(t, reader)
	assert.InDelta(t, float64(50*time.Nanosecond)/float64(time.Second),
		points[goCPUTimePointKey{state: "user"}].Value, 1e-12)

	recordGoRuntimeCPUTime(t.Context(), &metrics, nil)
	assert.Empty(t, collectGoRuntimeCPUTimePoints(t, reader))
	assert.Empty(t, metrics.cpuTimeValues)
}

func TestGoRuntimeMemoryMetricsDeltaResetAndRemoval(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(t.Context()))
	})

	var metrics goRuntimeMetrics
	require.NoError(t, setupGoRuntimeMeters(&metrics, provider.Meter(reporterName)))
	assertMemoryUsed := func(wantStack, wantOther int64) {
		used := collectGoRuntimeInt64Points(t, reader, attributes.GoRuntimeMemoryUsed.OTEL)
		require.Len(t, used, 2)
		usedByType := map[string]int64{}
		for _, point := range used {
			memoryType, ok := point.Attributes.Value(semconv.GoMemoryTypeKey)
			require.True(t, ok)
			usedByType[memoryType.AsString()] = point.Value
		}
		assert.Equal(t, wantStack, usedByType["stack"])
		assert.Equal(t, wantOther, usedByType["other"])
	}

	stack := int64(100)
	other := int64(200)
	allocated := uint64(1000)
	allocations := uint64(10)
	recordGoRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{
			MemoryUsedStack:   &stack,
			MemoryUsedOther:   &other,
			MemoryAllocated:   &allocated,
			MemoryAllocations: &allocations,
		},
	})

	assertMemoryUsed(100, 200)
	assert.Equal(t, int64(1000), collectSingleGoRuntimeInt64Value(t, reader, attributes.GoRuntimeMemoryAllocated.OTEL))
	assert.Equal(t, int64(10), collectSingleGoRuntimeInt64Value(t, reader, attributes.GoRuntimeMemoryAllocations.OTEL))

	stack = 50
	other = 250
	changedMemoryUsed := runtimemetrics.RuntimeMetricSnapshot{
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{
			MemoryUsedStack: &stack,
			MemoryUsedOther: &other,
		},
	}
	recordGoRuntimeMetrics(t.Context(), &metrics, changedMemoryUsed)
	assertMemoryUsed(50, 250)

	recordGoRuntimeMetrics(t.Context(), &metrics, changedMemoryUsed)
	assertMemoryUsed(50, 250)

	allocated = 50
	allocations = 2
	recordGoRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{
			MemoryAllocated:   &allocated,
			MemoryAllocations: &allocations,
		},
	})
	assert.Equal(t, int64(50), collectSingleGoRuntimeInt64Value(t, reader, attributes.GoRuntimeMemoryAllocated.OTEL))
	assert.Equal(t, int64(2), collectSingleGoRuntimeInt64Value(t, reader, attributes.GoRuntimeMemoryAllocations.OTEL))
	assert.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.GoRuntimeMemoryUsed.OTEL))

	recordGoRuntimeMetrics(t.Context(), &metrics, runtimemetrics.RuntimeMetricSnapshot{
		Go: &runtimemetrics.GoRuntimeMetricSnapshot{},
	})
	assert.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.GoRuntimeMemoryAllocated.OTEL))
	assert.Empty(t, collectGoRuntimeInt64Points(t, reader, attributes.GoRuntimeMemoryAllocations.OTEL))
}

type goCPUTimePointKey struct {
	state         string
	detailedState string
}

func collectGoRuntimeCPUTimePoints(
	t *testing.T,
	reader *metric.ManualReader,
) map[goCPUTimePointKey]metricdata.DataPoint[float64] {
	t.Helper()

	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &resourceMetrics))

	points := map[goCPUTimePointKey]metricdata.DataPoint[float64]{}
	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, collected := range scopeMetrics.Metrics {
			if collected.Name != attributes.GoRuntimeCPUTime.OTEL {
				continue
			}

			sum, ok := collected.Data.(metricdata.Sum[float64])
			require.True(t, ok)
			for _, point := range sum.DataPoints {
				state, ok := point.Attributes.Value(semconv.GoCPUStateKey)
				require.True(t, ok)
				key := goCPUTimePointKey{state: state.AsString()}
				if detailedState, ok := point.Attributes.Value(semconv.GoCPUDetailedStateKey); ok {
					key.detailedState = detailedState.AsString()
				}
				points[key] = point
			}
		}
	}

	return points
}

func collectSingleGoRuntimeInt64Value(t *testing.T, reader *metric.ManualReader, name string) int64 {
	t.Helper()

	points := collectGoRuntimeInt64Points(t, reader, name)
	require.Len(t, points, 1)
	return points[0].Value
}

func collectGoRuntimeInt64Points(
	t *testing.T,
	reader *metric.ManualReader,
	name string,
) []metricdata.DataPoint[int64] {
	t.Helper()

	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &resourceMetrics))

	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, collected := range scopeMetrics.Metrics {
			if collected.Name != name {
				continue
			}

			sum, ok := collected.Data.(metricdata.Sum[int64])
			require.True(t, ok)
			return sum.DataPoints
		}
	}

	return nil
}
