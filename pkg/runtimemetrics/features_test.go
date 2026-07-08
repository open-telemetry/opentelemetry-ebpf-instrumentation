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
