// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obiconfigv2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	obiv2 "go.opentelemetry.io/obi/pkg/obiconfig/v2"
)

func TestDefaultConfigRoundTrip(t *testing.T) {
	doc, err := RuntimeToDocument(&obi.DefaultConfig)
	require.NoError(t, err)

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.ChannelBufferLen, got.ChannelBufferLen)
	require.Equal(t, obi.DefaultConfig.ChannelSendTimeout, got.ChannelSendTimeout)
	require.Equal(t, obi.DefaultConfig.EnforceSysCaps, got.EnforceSysCaps)
	require.Equal(t, obi.DefaultConfig.EBPF.WakeupLen, got.EBPF.WakeupLen)
	require.Equal(t, obi.DefaultConfig.EBPF.BatchLength, got.EBPF.BatchLength)
	require.Equal(t, obi.DefaultConfig.EBPF.BatchTimeout, got.EBPF.BatchTimeout)
	require.Equal(t, obi.DefaultConfig.EBPF.ContextPropagation, got.EBPF.ContextPropagation)
	require.Equal(t, obi.DefaultConfig.EBPF.TCBackend, got.EBPF.TCBackend)
	require.Equal(t, obi.DefaultConfig.EBPF.InstrumentCuda, got.EBPF.InstrumentCuda)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.Source, got.NetworkFlows.Source)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.ListenInterfaces, got.NetworkFlows.ListenInterfaces)
	require.Equal(t, obi.DefaultConfig.NameResolver.CacheLen, got.NameResolver.CacheLen)
	require.Equal(t, obi.DefaultConfig.Attributes.Kubernetes.Enable, got.Attributes.Kubernetes.Enable)
	require.Equal(t, obi.DefaultConfig.Traces.QueueSize, got.Traces.QueueSize)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.OTELIntervalMS, got.OTELMetrics.OTELIntervalMS)
}

func TestRuntimeFilterAndGoFlagRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.Discovery.SkipGoSpecificTracers = true
	cfg.Filters.Application = filter.AttributeFamilyConfig{
		"http_request_method": {Match: "GET"},
	}
	cfg.Filters.Network = filter.AttributeFamilyConfig{
		"src_name": {NotMatch: "loopback"},
	}

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	require.Equal(t, false, nestedMap(doc.Extensions.OBI.Capture.Runtimes, "go")["enabled"])
	require.Equal(t, "GET", nestedMap(doc.Extensions.OBI.Capture.Instrumentation, "http", "filters", "traces", "http_request_method")["match"])
	require.Equal(t, "loopback", nestedMap(doc.Extensions.OBI.Capture.Network, "capture", "filters", "metrics", "src_name")["not_match"])

	got, err := ConfigToRuntime(doc.Extensions.OBI, obiv2.DeploymentModeStandalone)
	require.NoError(t, err)

	require.True(t, got.Discovery.SkipGoSpecificTracers)
	require.Equal(t, cfg.Filters.Application, got.Filters.Application)
	require.Equal(t, cfg.Filters.Network, got.Filters.Network)
}

func TestConfigToRuntimeAppliesProtocolEnablement(t *testing.T) {
	cfg, err := ConfigToRuntime(&obiv2.Extension{
		Version: obiv2.SupportedVersion,
		Capture: obiv2.CaptureConfig{
			Instrumentation: map[string]any{
				"http": map[string]any{
					"enabled": map[string]any{"traces": false, "metrics": false},
				},
				"sql": map[string]any{
					"enabled": map[string]any{"traces": true, "metrics": false},
				},
				"dns": map[string]any{
					"enabled": map[string]any{"traces": true, "metrics": true},
				},
			},
			Network: map[string]any{
				"capture": map[string]any{
					"enabled": true,
				},
			},
		},
	}, obiv2.DeploymentModeStandalone)
	require.NoError(t, err)

	require.NotContains(t, cfg.Traces.Instrumentations, instrumentations.InstrumentationHTTP)
	require.Contains(t, cfg.Traces.Instrumentations, instrumentations.InstrumentationSQL)
	require.Contains(t, cfg.Traces.Instrumentations, instrumentations.InstrumentationDNS)

	require.NotContains(t, cfg.OTELMetrics.Instrumentations, instrumentations.InstrumentationHTTP)
	require.NotContains(t, cfg.OTELMetrics.Instrumentations, instrumentations.InstrumentationSQL)
	require.Contains(t, cfg.OTELMetrics.Instrumentations, instrumentations.InstrumentationDNS)

	require.NotContains(t, cfg.Prometheus.Instrumentations, instrumentations.InstrumentationHTTP)
	require.NotContains(t, cfg.Prometheus.Instrumentations, instrumentations.InstrumentationSQL)
	require.Contains(t, cfg.Prometheus.Instrumentations, instrumentations.InstrumentationDNS)

	require.True(t, cfg.NetworkFlows.Enable)
	require.Equal(t, export.FeatureApplicationRED|export.FeatureNetwork, cfg.Metrics.Features)
}

func TestConfigToRuntimeAppliesMetricsFeatureBuckets(t *testing.T) {
	testCases := []struct {
		name     string
		src      *obiv2.Extension
		expected export.Features
	}{
		{
			name: "application metrics only",
			src: &obiv2.Extension{
				Version: obiv2.SupportedVersion,
				Capture: obiv2.CaptureConfig{
					Instrumentation: map[string]any{
						"http": map[string]any{
							"enabled": map[string]any{"metrics": true},
						},
					},
				},
			},
			expected: export.FeatureApplicationRED,
		},
		{
			name: "network only",
			src: &obiv2.Extension{
				Version: obiv2.SupportedVersion,
				Capture: obiv2.CaptureConfig{
					Instrumentation: map[string]any{
						"http": map[string]any{
							"enabled": map[string]any{"metrics": false},
						},
					},
					Network: map[string]any{
						"capture": map[string]any{
							"enabled": true,
						},
					},
				},
			},
			expected: export.FeatureNetwork,
		},
		{
			name: "all protocol and network metrics disabled",
			src: &obiv2.Extension{
				Version: obiv2.SupportedVersion,
				Capture: obiv2.CaptureConfig{
					Instrumentation: map[string]any{
						"http": map[string]any{
							"enabled": map[string]any{"metrics": false},
						},
						"dns": map[string]any{
							"enabled": map[string]any{"metrics": false},
						},
					},
					Network: map[string]any{
						"capture": map[string]any{
							"enabled": false,
						},
					},
				},
			},
			expected: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ConfigToRuntime(tc.src, obiv2.DeploymentModeStandalone)
			require.NoError(t, err)
			require.Equal(t, tc.expected, cfg.Metrics.Features)
		})
	}
}

func TestRuntimeProtocolEnablementRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.Metrics.Features = export.FeatureApplicationRED | export.FeatureNetworkInterZone
	cfg.Traces.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationSQL,
		instrumentations.InstrumentationDNS,
	}
	cfg.OTELMetrics.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationHTTP,
		instrumentations.InstrumentationDNS,
	}
	cfg.Prometheus.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationHTTP,
		instrumentations.InstrumentationDNS,
	}

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	require.Equal(t, map[string]any{"traces": false, "metrics": true}, nestedMap(doc.Extensions.OBI.Capture.Instrumentation, "http")["enabled"])
	require.Equal(t, map[string]any{"traces": true, "metrics": false}, nestedMap(doc.Extensions.OBI.Capture.Instrumentation, "sql")["enabled"])
	require.Equal(t, map[string]any{"traces": true, "metrics": true}, nestedMap(doc.Extensions.OBI.Capture.Instrumentation, "dns")["enabled"])
	require.Equal(t, true, nestedMap(doc.Extensions.OBI.Capture.Network, "capture")["enabled"])

	got, err := ConfigToRuntime(doc.Extensions.OBI, obiv2.DeploymentModeStandalone)
	require.NoError(t, err)

	require.Contains(t, got.Traces.Instrumentations, instrumentations.InstrumentationSQL)
	require.Contains(t, got.Traces.Instrumentations, instrumentations.InstrumentationDNS)
	require.NotContains(t, got.Traces.Instrumentations, instrumentations.InstrumentationHTTP)

	require.Contains(t, got.OTELMetrics.Instrumentations, instrumentations.InstrumentationHTTP)
	require.Contains(t, got.OTELMetrics.Instrumentations, instrumentations.InstrumentationDNS)
	require.NotContains(t, got.OTELMetrics.Instrumentations, instrumentations.InstrumentationSQL)

	require.Contains(t, got.Prometheus.Instrumentations, instrumentations.InstrumentationHTTP)
	require.Contains(t, got.Prometheus.Instrumentations, instrumentations.InstrumentationDNS)
	require.NotContains(t, got.Prometheus.Instrumentations, instrumentations.InstrumentationSQL)
	require.True(t, got.NetworkFlows.Enable)
	require.Equal(t, export.FeatureApplicationRED|export.FeatureNetwork, got.Metrics.Features)
}
