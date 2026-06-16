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
	enabled := EnabledFeatures(export.FeatureApplicationRuntime | export.FeatureApplicationJVM)

	require.True(t, enabled.Any())
	require.True(t, enabled.Go)
	require.True(t, enabled.JVM)
}

func TestEnabledShouldReportGoRuntimeMetrics(t *testing.T) {
	snapshot := RuntimeMetricSnapshot{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableGolang},
		Go:      &GoRuntimeMetricSnapshot{},
	}

	require.True(t, Enabled{Go: true}.ShouldReport(snapshot))
	require.False(t, Enabled{Go: false}.ShouldReport(snapshot))

	snapshot.Service.SDKLanguage = svc.InstrumentableJava
	require.False(t, Enabled{Go: true}.ShouldReport(snapshot))
}

func TestEnabledShouldReportJVMRuntimeMetrics(t *testing.T) {
	snapshot := RuntimeMetricSnapshot{
		Service: svc.Attrs{
			Features: export.FeatureApplicationJVM,
		},
		JVM: &JVMRuntimeMetricSnapshot{},
	}

	require.True(t, Enabled{JVM: true}.ShouldReport(snapshot))
	require.False(t, Enabled{JVM: false}.ShouldReport(snapshot))

	snapshot.Service.Features = export.FeatureApplicationRuntime
	require.False(t, Enabled{JVM: true}.ShouldReport(snapshot))
}
