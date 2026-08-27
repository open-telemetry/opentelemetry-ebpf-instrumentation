// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export"
)

func TestEnabledFeaturesGroupsRuntimeMetrics(t *testing.T) {
	enabled := EnabledFeatures(export.FeatureApplicationRuntime)

	require.True(t, enabled.Any())
	require.True(t, enabled.Runtime)
}

func TestEnabledShouldReportGoRuntimeMetrics(t *testing.T) {
	snapshot := RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableGolang},
		Go:      &GoRuntimeMetricSnapshot{},
	}

	require.True(t, Enabled{Runtime: true}.ShouldReport(snapshot))
	require.False(t, Enabled{Runtime: false}.ShouldReport(snapshot))

	snapshot.Service.SDKLanguage = svc.InstrumentableJava
	require.False(t, Enabled{Runtime: true}.ShouldReport(snapshot))
}

func TestEnabledShouldReportGoRuntimeHistograms(t *testing.T) {
	snapshot := RuntimeMetricSnapshot{
		Service:   svc.Attrs{SDKLanguage: svc.InstrumentableGolang},
		Histogram: &GoRuntimeHistogramSnapshot{},
	}

	require.True(t, Enabled{Runtime: true}.ShouldReport(snapshot))
	require.False(t, Enabled{Runtime: false}.ShouldReport(snapshot))

	snapshot.Service.SDKLanguage = svc.InstrumentableJava
	require.False(t, Enabled{Runtime: true}.ShouldReport(snapshot))
}

func TestEnabledShouldReportNodejsRuntimeMetrics(t *testing.T) {
	snapshot := RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features: export.FeatureApplicationRuntime,
		},
		Nodejs: &NodejsRuntimeMetricSnapshot{},
	}

	require.True(t, Enabled{Runtime: true}.ShouldReport(snapshot))
	require.False(t, Enabled{Runtime: false}.ShouldReport(snapshot))

	snapshot.Service.Features = export.FeatureApplicationRED
	require.False(t, Enabled{Runtime: true}.ShouldReport(snapshot))
}

func TestEnabledShouldReportNodejsV8Metrics(t *testing.T) {
	service := svc.Attrs{Features: export.FeatureApplicationRuntime}

	gc := RuntimeMetricSnapshot{Service: service, NodejsGC: &NodejsGCSnapshot{}}
	require.True(t, Enabled{Runtime: true}.ShouldReport(gc))
	require.False(t, Enabled{Runtime: false}.ShouldReport(gc))

	heap := RuntimeMetricSnapshot{Service: service, NodejsHeapSpace: &NodejsHeapSpaceSnapshot{}}
	require.True(t, Enabled{Runtime: true}.ShouldReport(heap))
	require.False(t, Enabled{Runtime: false}.ShouldReport(heap))

	gc.Service.Features = export.FeatureApplicationRED
	require.False(t, Enabled{Runtime: true}.ShouldReport(gc))
	heap.Service.Features = export.FeatureApplicationRED
	require.False(t, Enabled{Runtime: true}.ShouldReport(heap))
}

func TestEnabledShouldReportJVMRuntimeMetrics(t *testing.T) {
	snapshot := RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features: export.FeatureApplicationRuntime,
		},
		JVM: &JVMRuntimeMetricSnapshot{},
	}

	require.True(t, Enabled{Runtime: true}.ShouldReport(snapshot))
	require.False(t, Enabled{Runtime: false}.ShouldReport(snapshot))

	snapshot.Service.Features = export.FeatureApplicationRED
	require.False(t, Enabled{Runtime: true}.ShouldReport(snapshot))
}
