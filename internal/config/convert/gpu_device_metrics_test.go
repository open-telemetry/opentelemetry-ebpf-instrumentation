// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestGPUDeviceMetricsYAML(t *testing.T) {
	t.Parallel()

	defaults := obi.DefaultConfig.GPUDevices

	for _, test := range []struct {
		name     string
		gpu      string
		expected config.GPUDeviceMetrics
	}{
		{name: "omitted", gpu: "{}", expected: defaults},
		{name: "empty section", gpu: "{device_metrics: {}}", expected: defaults},
		{
			name:     "enabled",
			gpu:      "{device_metrics: {enabled: true}}",
			expected: config.GPUDeviceMetrics{Enabled: true, Interval: defaults.Interval},
		},
		{
			name:     "enabled with interval",
			gpu:      "{device_metrics: {enabled: true, interval: 10s}}",
			expected: config.GPUDeviceMetrics{Enabled: true, Interval: 10 * time.Second},
		},
		{
			name:     "disabled",
			gpu:      "{device_metrics: {enabled: false, interval: 1m}}",
			expected: config.GPUDeviceMetrics{Interval: time.Minute},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, standalone, err := schema.ParseStandaloneYAML([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      instrumentation:
        gpu: ` + test.gpu + "\n"))
			require.NoError(t, err)

			receiver, err := schema.ParseReceiverYAML([]byte("version: \"2.0\"\ninstrumentation:\n  gpu: " + test.gpu + "\n"))
			require.NoError(t, err)

			for _, ext := range []*schema.Extension{standalone, receiver} {
				got, err := V2ToRuntime(ext)
				require.NoError(t, err)
				require.Equal(t, test.expected, got.GPUDevices)
			}
		})
	}
}

func TestGPUDeviceMetricsProgrammaticConfig(t *testing.T) {
	t.Parallel()

	const interval = 5 * time.Second

	for _, enabled := range []bool{false, true} {
		for _, complete := range []bool{false, true} {
			ext := &schema.Extension{Version: schema.SupportedVersion}
			if complete {
				_, ext = RuntimeToV2(nil)
			}

			ext.Capture.Instrumentation.GPU.DeviceMetrics = schema.GPUDeviceMetrics{
				Enabled:  &enabled,
				Interval: schema.Duration(interval),
			}

			got, err := V2ToRuntime(ext)
			require.NoError(t, err)
			require.Equal(t, config.GPUDeviceMetrics{Enabled: enabled, Interval: interval}, got.GPUDevices)

			_, exported := RuntimeToV2(got)
			require.NotNil(t, exported.Capture.Instrumentation.GPU.DeviceMetrics.Enabled)
			require.Equal(t, enabled, *exported.Capture.Instrumentation.GPU.DeviceMetrics.Enabled)
			require.Equal(t, schema.Duration(interval), exported.Capture.Instrumentation.GPU.DeviceMetrics.Interval)
		}
	}

	got, err := V2ToRuntime(&schema.Extension{Version: schema.SupportedVersion})
	require.NoError(t, err)
	require.Equal(t, obi.DefaultConfig.GPUDevices, got.GPUDevices)
}

func TestGPUDeviceMetricsRejectsInvalidInterval(t *testing.T) {
	t.Parallel()

	enabled := true
	ext := &schema.Extension{Version: schema.SupportedVersion}
	ext.Capture.Instrumentation.GPU.DeviceMetrics = schema.GPUDeviceMetrics{
		Enabled:  &enabled,
		Interval: schema.Duration(-time.Second),
	}

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)
	require.ErrorContains(t, got.Validate(), "GPUDevices.Interval")
}
