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
		runtimeEnabled: runtimemetrics.Enabled{Go: true, JVM: true},
	}

	require.True(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableGolang},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{},
	}))
	require.True(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationJVM,
			ExportModes: exportMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{Kind: jvmruntime.JVMMetricObiHeapUsed},
	}))

	assert.False(t, (&RuntimeMetricsReporter{runtimeEnabled: runtimemetrics.Enabled{Go: false}}).shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableGolang},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava},
		Go:      &runtimemetrics.GoRuntimeMetricSnapshot{},
	}))
	assert.False(t, (&RuntimeMetricsReporter{runtimeEnabled: runtimemetrics.Enabled{JVM: false}}).shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationJVM,
			ExportModes: exportMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationRuntime,
			ExportModes: exportMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features:    export.FeatureApplicationJVM,
			ExportModes: blockMetrics,
		},
		JVM: &runtimemetrics.JVMRuntimeMetricSnapshot{},
	}))
	assert.False(t, reporter.shouldReportSnapshot(runtimemetrics.RuntimeMetricSnapshot{}))
}

func TestSetupRuntimeMetersRespectsEnabledSections(t *testing.T) {
	provider := metric.NewMeterProvider()
	defer func() {
		require.NoError(t, provider.Shutdown(t.Context()))
	}()
	meter := provider.Meter(reporterName)

	goOnly := RuntimeMetrics{ctx: t.Context()}
	require.NoError(t, setupRuntimeMeters(&goOnly, meter, time.Minute, runtimemetrics.Enabled{Go: true}))
	assert.NotNil(t, goOnly.goMetrics.memoryLimit)
	assert.Nil(t, goOnly.jvmMetrics.memoryUsed)

	jvmOnly := RuntimeMetrics{ctx: t.Context()}
	require.NoError(t, setupRuntimeMeters(&jvmOnly, meter, time.Minute, runtimemetrics.Enabled{JVM: true}))
	assert.Nil(t, jvmOnly.goMetrics.memoryLimit)
	assert.NotNil(t, jvmOnly.jvmMetrics.memoryUsed)
}
