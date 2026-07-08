// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
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
