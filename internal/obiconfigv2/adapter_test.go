// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obiconfigv2

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/obi"
	obiv2 "go.opentelemetry.io/obi/pkg/obiconfig/v2"
	"go.opentelemetry.io/obi/pkg/transform"
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
	require.Equal(t, obi.DefaultConfig.EBPF.DisableBlackBoxCP, got.EBPF.DisableBlackBoxCP)
	require.Equal(t, obi.DefaultConfig.EBPF.TCBackend, got.EBPF.TCBackend)
	require.Equal(t, obi.DefaultConfig.EBPF.ForceBPFMapReader, got.EBPF.ForceBPFMapReader)
	require.Equal(t, obi.DefaultConfig.EBPF.MapsConfig, got.EBPF.MapsConfig)
	require.Equal(t, obi.DefaultConfig.EBPF.InstrumentCuda, got.EBPF.InstrumentCuda)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.Source, got.NetworkFlows.Source)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.ListenInterfaces, got.NetworkFlows.ListenInterfaces)
	require.Equal(t, obi.DefaultConfig.NameResolver.CacheLen, got.NameResolver.CacheLen)
	require.Equal(t, obi.DefaultConfig.Attributes.Kubernetes.Enable, got.Attributes.Kubernetes.Enable)
	require.Equal(t, obi.DefaultConfig.Traces.QueueSize, got.Traces.QueueSize)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.OTELIntervalMS, got.OTELMetrics.OTELIntervalMS)
}

func TestTracerControlsRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.EBPF.DisableBlackBoxCP = true
	cfg.EBPF.ContextPropagation = config.ContextPropagationHeaders
	cfg.EBPF.TCBackend = config.TCBackendTCX
	cfg.EBPF.ForceBPFMapReader = config.MapReaderLegacy
	cfg.EBPF.MapsConfig.GlobalScaleFactor = 2

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	require.Equal(t, "headers", nestedMap(doc.Extensions.OBI.Raw, "capture", "engine", "propagation")["context_propagation"])
	require.Equal(t, true, nestedMap(doc.Extensions.OBI.Raw, "capture", "engine", "propagation")["disable_black_box_cp"])
	require.Equal(t, "tcx", nestedMap(doc.Extensions.OBI.Raw, "capture", "engine", "traffic")["control_backend"])
	require.Equal(t, "legacy", nestedMap(doc.Extensions.OBI.Raw, "capture", "engine", "traffic")["force_map_reader"])
	require.Equal(t, 2, nestedMap(doc.Extensions.OBI.Raw, "capture", "engine", "maps")["global_scale_factor"])

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)

	require.True(t, got.EBPF.DisableBlackBoxCP)
	require.Equal(t, config.ContextPropagationHeaders, got.EBPF.ContextPropagation)
	require.Equal(t, config.TCBackendTCX, got.EBPF.TCBackend)
	require.Equal(t, config.MapReaderLegacy, got.EBPF.ForceBPFMapReader)
	require.Equal(t, 2, got.EBPF.MapsConfig.GlobalScaleFactor)
}

func TestMSSQLAndTCPBufferRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.EBPF.BufferSizes.MSSQL = 8192
	cfg.EBPF.MSSQLPreparedStatementsCacheSize = 2048
	cfg.EBPF.BufferSizes.TCP = 4096
	cfg.NetworkFlows.Enable = true

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	require.Equal(t, uint32(8192), nestedMap(doc.Extensions.OBI.Capture.Instrumentation, "sql", "mssql")["buffer_size"])
	require.Equal(t, 2048, nestedMap(doc.Extensions.OBI.Capture.Instrumentation, "sql", "mssql")["prepared_statements_cache_size"])
	require.Equal(t, uint32(4096), nestedMap(doc.Extensions.OBI.Capture.Network, "capture")["buffer_size"])

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.Equal(t, cfg.EBPF.BufferSizes.MSSQL, got.EBPF.BufferSizes.MSSQL)
	require.Equal(t, cfg.EBPF.MSSQLPreparedStatementsCacheSize, got.EBPF.MSSQLPreparedStatementsCacheSize)
	require.Equal(t, cfg.EBPF.BufferSizes.TCP, got.EBPF.BufferSizes.TCP)
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

func TestDiscoverySelectorPIDAndPortRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.Discovery.Instrument = []services.GlobAttributes{
		{OpenPorts: services.IntEnum{Ranges: []services.IntRange{{Start: 8080}, {Start: 8443, End: 8444}}}},
		{PIDs: []uint32{1234, 5678}},
	}
	cfg.Discovery.ExcludeInstrument = []services.GlobAttributes{
		{OpenPorts: services.IntEnum{Ranges: []services.IntRange{{Start: 4317}}}},
		{PIDs: []uint32{99}},
	}

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	rules := doc.Extensions.OBI.Capture.Rules
	require.Contains(t, rules, obiv2.Rule{
		Action: "include",
		Match: map[string]any{
			"process": map[string]any{
				"open_ports": services.IntEnum{Ranges: []services.IntRange{{Start: 8080}, {Start: 8443, End: 8444}}},
			},
		},
	})
	require.Contains(t, rules, obiv2.Rule{
		Action: "include",
		Match: map[string]any{
			"process": map[string]any{
				"target_pids": []uint32{1234, 5678},
			},
		},
	})
	require.Contains(t, rules, obiv2.Rule{
		Action: "exclude",
		Match: map[string]any{
			"process": map[string]any{
				"open_ports": services.IntEnum{Ranges: []services.IntRange{{Start: 4317}}},
			},
		},
	})
	require.Contains(t, rules, obiv2.Rule{
		Action: "exclude",
		Match: map[string]any{
			"process": map[string]any{
				"target_pids": []uint32{99},
			},
		},
	})

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.Instrument {
			if len(selector.OpenPorts.Ranges) == 2 &&
				selector.OpenPorts.Ranges[0] == (services.IntRange{Start: 8080}) &&
				selector.OpenPorts.Ranges[1] == (services.IntRange{Start: 8443, End: 8444}) {
				return true
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.Instrument {
			if len(selector.PIDs) == 2 && selector.PIDs[0] == 1234 && selector.PIDs[1] == 5678 {
				return true
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.ExcludeInstrument {
			if len(selector.OpenPorts.Ranges) == 1 && selector.OpenPorts.Ranges[0] == (services.IntRange{Start: 4317}) {
				return true
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.ExcludeInstrument {
			if len(selector.PIDs) == 1 && selector.PIDs[0] == 99 {
				return true
			}
		}
		return false
	})
}

func TestDiscoverySelectorLanguageAndCmdArgsRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.Discovery.Instrument = []services.GlobAttributes{
		{Languages: services.NewGlob("java")},
		{CmdArgs: services.NewGlob("*serve*")},
	}
	cfg.Discovery.ExcludeInstrument = []services.GlobAttributes{
		{Languages: services.NewGlob("python")},
		{CmdArgs: services.NewGlob("*sidecar*")},
	}

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	rules := doc.Extensions.OBI.Capture.Rules
	require.Contains(t, rules, obiv2.Rule{
		Action: "include",
		Match: map[string]any{
			"process": map[string]any{
				"language_glob": []string{"java"},
			},
		},
	})
	require.Contains(t, rules, obiv2.Rule{
		Action: "include",
		Match: map[string]any{
			"process": map[string]any{
				"cmd_args_glob": []string{"*serve*"},
			},
		},
	})
	require.Contains(t, rules, obiv2.Rule{
		Action: "exclude",
		Match: map[string]any{
			"process": map[string]any{
				"language_glob": []string{"python"},
			},
		},
	})
	require.Contains(t, rules, obiv2.Rule{
		Action: "exclude",
		Match: map[string]any{
			"process": map[string]any{
				"cmd_args_glob": []string{"*sidecar*"},
			},
		},
	})

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.Instrument {
			if selector.Languages.IsSet() && globString(selector.Languages) == "java" {
				return true
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.Instrument {
			if selector.CmdArgs.IsSet() && globString(selector.CmdArgs) == "*serve*" {
				return true
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.ExcludeInstrument {
			if selector.Languages.IsSet() && globString(selector.Languages) == "python" {
				return true
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.ExcludeInstrument {
			if selector.CmdArgs.IsSet() && globString(selector.CmdArgs) == "*sidecar*" {
				return true
			}
		}
		return false
	})
}

func TestDiscoverySelectorPodMetadataRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.Discovery.Instrument = []services.GlobAttributes{
		{
			PodLabels: map[string]*services.GlobAttr{
				"app.kubernetes.io/name": globPointer("{frontend,checkout}"),
			},
		},
		{
			PodAnnotations: map[string]*services.GlobAttr{
				"instrumentation.opentelemetry.io/inject-java": globPointer("true"),
			},
		},
	}
	cfg.Discovery.ExcludeInstrument = []services.GlobAttributes{
		{
			PodLabels: map[string]*services.GlobAttr{
				"team": globPointer("platform-*"),
			},
		},
		{
			PodAnnotations: map[string]*services.GlobAttr{
				"sidecar.istio.io/status": globPointer("*"),
			},
		},
	}

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	rules := doc.Extensions.OBI.Capture.Rules
	require.Contains(t, rules, obiv2.Rule{
		Action: "include",
		Match: map[string]any{
			"kubernetes": map[string]any{
				"pod_labels": map[string]any{
					"app.kubernetes.io/name": []string{"{frontend,checkout}"},
				},
			},
		},
	})
	require.Contains(t, rules, obiv2.Rule{
		Action: "include",
		Match: map[string]any{
			"kubernetes": map[string]any{
				"pod_annotations": map[string]any{
					"instrumentation.opentelemetry.io/inject-java": []string{"true"},
				},
			},
		},
	})
	require.Contains(t, rules, obiv2.Rule{
		Action: "exclude",
		Match: map[string]any{
			"kubernetes": map[string]any{
				"pod_labels": map[string]any{
					"team": []string{"platform-*"},
				},
			},
		},
	})
	require.Contains(t, rules, obiv2.Rule{
		Action: "exclude",
		Match: map[string]any{
			"kubernetes": map[string]any{
				"pod_annotations": map[string]any{
					"sidecar.istio.io/status": []string{"*"},
				},
			},
		},
	})

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.Instrument {
			if glob := selector.PodLabels["app.kubernetes.io/name"]; glob != nil && globString(*glob) == "{frontend,checkout}" {
				return true
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.Instrument {
			if glob := selector.PodAnnotations["instrumentation.opentelemetry.io/inject-java"]; glob != nil && globString(*glob) == "true" {
				return true
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.ExcludeInstrument {
			if glob := selector.PodLabels["team"]; glob != nil && globString(*glob) == "platform-*" {
				return true
			}
		}
		return false
	})
	require.Condition(t, func() bool {
		for _, selector := range got.Discovery.ExcludeInstrument {
			if glob := selector.PodAnnotations["sidecar.istio.io/status"]; glob != nil && globString(*glob) == "*" {
				return true
			}
		}
		return false
	})
}

func TestKubernetesReconnectAndResourceLabelsRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.Attributes.Kubernetes.ReconnectInitialInterval = 17 * time.Second
	cfg.Attributes.Kubernetes.ResourceLabels = kube.ResourceLabels{
		"service.name":      {"app.kubernetes.io/name", "app.kubernetes.io/instance"},
		"service.namespace": {"team"},
	}

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	kubernetes := nestedMap(doc.Extensions.OBI.Enrich, "enrichers", "kubernetes")
	require.Equal(t, "17s", nestedMap(kubernetes, "informers")["reconnect_initial_interval"])
	require.Equal(t, kube.ResourceLabels{
		"service.name":      {"app.kubernetes.io/name", "app.kubernetes.io/instance"},
		"service.namespace": {"team"},
	}, kubernetes["resource_labels"])

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.Equal(t, 17*time.Second, got.Attributes.Kubernetes.ReconnectInitialInterval)
	require.Equal(t, kube.ResourceLabels{
		"service.name":      {"app.kubernetes.io/name", "app.kubernetes.io/instance"},
		"service.namespace": {"team"},
	}, got.Attributes.Kubernetes.ResourceLabels)
}

func TestAttributeGroupingAndMetadataRetryRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.Prometheus.Port = 9090
	cfg.Attributes.ExtraGroupAttributes = obi.ExtraGroupAttributesMap{
		"k8s_app_meta": {attr.Name("k8s.app.version")},
	}
	cfg.Attributes.MetadataRetry = meta.RetryConfig{
		Timeout:       45 * time.Second,
		StartInterval: 2 * time.Second,
		MaxInterval:   9 * time.Second,
	}

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	attributes := nestedMap(doc.Extensions.OBI.Enrich, "attributes")
	require.Equal(t, obi.ExtraGroupAttributesMap{
		"k8s_app_meta": {attr.Name("k8s.app.version")},
	}, attributes["extra_group_attributes"])
	require.Equal(t, map[string]any{
		"timeout":        "45s",
		"start_interval": "2s",
		"max_interval":   "9s",
	}, attributes["metadata_retry"])

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.Equal(t, cfg.Attributes.ExtraGroupAttributes, got.Attributes.ExtraGroupAttributes)
	require.Equal(t, cfg.Attributes.MetadataRetry, got.Attributes.MetadataRetry)
	require.NoError(t, got.Validate())
}

func TestAttributeSelectionRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.Prometheus.Port = 9090
	cfg.Attributes.Select = attributes.Selection{
		attributes.HTTPServerDuration.Section: {
			Include: []string{"http.request.method", "service.*"},
			Exclude: []string{"server.port"},
		},
		attributes.NetworkFlow.Section: {
			Include: []string{"src.name", "dst.zone"},
			Exclude: []string{"k8s.*"},
		},
		attributes.StatTCPRtt.Section: {
			Include: []string{"src.port", "dst.port"},
			Exclude: []string{"transport"},
		},
	}

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	attributesMap := nestedMap(doc.Extensions.OBI.Enrich, "attributes")
	require.Equal(t, cfg.Attributes.Select, attributesMap["select"])

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.Equal(t, cfg.Attributes.Select, got.Attributes.Select)
	require.NoError(t, got.Validate())
}

func TestTopLevelResourceIdentityImport(t *testing.T) {
	t.Run("unset preserves defaults", func(t *testing.T) {
		got, err := StandaloneToRuntime(&obiv2.Document{
			Resource: map[string]any{},
			Extensions: obiv2.Extensions{
				OBI: &obiv2.Extension{
					Version: obiv2.SupportedVersion,
					Capture: obiv2.CaptureConfig{},
				},
			},
		})
		require.NoError(t, err)
		require.True(t, got.Attributes.InstanceID.HostnameDNSResolution)
		require.Empty(t, got.Attributes.InstanceID.OverrideHostname)
		require.Empty(t, got.Attributes.HostID.Override)
	})

	t.Run("explicit overrides apply", func(t *testing.T) {
		got, err := StandaloneToRuntime(&obiv2.Document{
			Resource: map[string]any{
				"host.name": "collector-node",
				"host.id":   "node-123",
			},
			Extensions: obiv2.Extensions{
				OBI: &obiv2.Extension{
					Version: obiv2.SupportedVersion,
					Capture: obiv2.CaptureConfig{},
				},
			},
		})
		require.NoError(t, err)
		require.Equal(t, "collector-node", got.Attributes.InstanceID.OverrideHostname)
		require.Equal(t, "node-123", got.Attributes.HostID.Override)
		require.True(t, got.Attributes.InstanceID.HostnameDNSResolution)
	})
}

func TestTopLevelResourceIdentityExport(t *testing.T) {
	t.Run("explicit overrides export", func(t *testing.T) {
		cfg := obi.DefaultConfig
		cfg.Attributes.InstanceID.OverrideHostname = "collector-node"
		cfg.Attributes.HostID.Override = "node-123"

		doc, err := RuntimeToDocument(&cfg)
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"host.name": "collector-node",
			"host.id":   "node-123",
		}, doc.Resource)
	})

	t.Run("defaults do not export synthetic identity resource", func(t *testing.T) {
		doc, err := RuntimeToDocument(&obi.DefaultConfig)
		require.NoError(t, err)
		require.Empty(t, doc.Resource)
	})
}

func TestServiceNameResolverAndTemplateRoundTrip(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.TracePrinter = "text"
	cfg.NameResolver.Sources = []transform.Source{transform.SourceDNS, transform.SourceRDNS, transform.SourceKubernetes}
	cfg.Attributes.Kubernetes.ServiceNameTemplate = "{{ .Meta.Namespace }}/{{ .Meta.Name }}"

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	serviceName := nestedMap(doc.Extensions.OBI.Enrich, "service_name")
	require.Equal(t, []transform.Source{transform.SourceDNS, transform.SourceRDNS, transform.SourceKubernetes}, serviceName["sources"])
	require.Equal(t, "{{ .Meta.Namespace }}/{{ .Meta.Name }}", nestedMap(doc.Extensions.OBI.Enrich, "enrichers", "kubernetes")["service_name_template"])

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.Equal(t, []transform.Source{transform.SourceDNS, transform.SourceRDNS, transform.SourceKubernetes}, got.NameResolver.Sources)
	require.Equal(t, "{{ .Meta.Namespace }}/{{ .Meta.Name }}", got.Attributes.Kubernetes.ServiceNameTemplate)
	got.TracePrinter = "text"
	require.NoError(t, got.Validate())
}

func TestRuntimeStatsConfigRoundTrip(t *testing.T) {
	cfg, err := obi.LoadConfig(bytes.NewBufferString(`
metrics:
  features: [stats]
otel_metrics_export:
  endpoint: localhost:4317
stats:
  agent_ip: 10.0.0.1
  agent_ip_iface: "name:eth1"
  agent_ip_type: ipv6
  cidrs:
    - cidr: 10.0.0.0/8
      name: internal
    - 2001:db8::/32
  reverse_dns:
    type: local
    cache_len: 32
    cache_expiry: 2m
  print_stats: true
  geo_ip:
    cache_len: 64
    cache_expiry: 3m
    ipinfo:
      path: /tmp/ipinfo.mmdb
    maxmind:
      country_path: /tmp/country.mmdb
      asn_path: /tmp/asn.mmdb
`))
	require.NoError(t, err)

	doc, err := RuntimeToDocument(cfg)
	require.NoError(t, err)

	require.Equal(t, true, nestedMap(doc.Extensions.OBI.Capture.Network, "stats", "diagnostics")["print_stats"])
	require.Equal(t, "local", nestedMap(doc.Extensions.OBI.Capture.Network, "stats", "enrichment", "reverse_dns")["mode"])
	require.Equal(t, "/tmp/ipinfo.mmdb", nestedMap(doc.Extensions.OBI.Capture.Network, "stats", "enrichment", "geo_ip", "ipinfo")["path"])

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.Equal(t, cfg.Stats, got.Stats)
}

func TestRuntimeNetworkCIDRsRoundTrip(t *testing.T) {
	cfg, err := obi.LoadConfig(bytes.NewBufferString(`
metrics:
  features: [network]
network:
  enable: true
  cidrs:
    - cidr: 10.0.0.0/8
      name: internal
    - 2001:db8::/32
`))
	require.NoError(t, err)

	doc, err := RuntimeToDocument(cfg)
	require.NoError(t, err)

	require.Equal(t, cfg.NetworkFlows.CIDRs, nestedMap(doc.Extensions.OBI.Capture.Network, "capture", "selection")["cidrs"])

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.Equal(t, cfg.NetworkFlows.CIDRs, got.NetworkFlows.CIDRs)
}

func TestHTTPEnrichmentRoundTrip(t *testing.T) {
	jsonPath, err := config.NewJSONPathExpr("$.password")
	require.NoError(t, err)

	cfg := obi.DefaultConfig
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.DefaultAction.Headers = config.HTTPParsingActionInclude
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.DefaultAction.Body = config.HTTPParsingActionObfuscate
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.ObfuscationString = "[redacted]"
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Rules = []config.HTTPParsingRule{{
		Action: config.HTTPParsingActionObfuscate,
		Type:   config.HTTPParsingRuleTypeBody,
		Scope:  config.HTTPParsingScopeRequest,
		Match: config.HTTPParsingMatch{
			URLPathPatterns:      []services.GlobAttr{services.NewGlob("/login")},
			Methods:              []config.HTTPMethod{config.HTTPMethodPOST},
			ObfuscationJSONPaths: []config.JSONPathExpr{jsonPath},
		},
	}}

	doc, err := RuntimeToDocument(&cfg)
	require.NoError(t, err)

	payloadExtraction := nestedMap(doc.Extensions.OBI.Capture.Instrumentation, "http", "payload_extraction")
	require.Contains(t, payloadExtraction["enabled"], "enrichment")
	require.Equal(t, "include", nestedMap(payloadExtraction, "enrichment", "policy", "default_action")["headers"])
	require.Equal(t, "obfuscate", nestedMap(payloadExtraction, "enrichment", "policy", "default_action")["body"])
	require.Equal(t, "[redacted]", nestedMap(payloadExtraction, "enrichment", "policy")["obfuscation_string"])

	got, err := StandaloneToRuntime(doc)
	require.NoError(t, err)
	require.True(t, got.EBPF.PayloadExtraction.HTTP.Enrichment.Enabled)
	require.Equal(t, config.HTTPParsingActionInclude, got.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.DefaultAction.Headers)
	require.Equal(t, config.HTTPParsingActionObfuscate, got.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.DefaultAction.Body)
	require.Equal(t, "[redacted]", got.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.ObfuscationString)
	require.Len(t, got.EBPF.PayloadExtraction.HTTP.Enrichment.Rules, 1)
	require.Equal(t, config.HTTPParsingActionObfuscate, got.EBPF.PayloadExtraction.HTTP.Enrichment.Rules[0].Action)
	require.Equal(t, config.HTTPParsingRuleTypeBody, got.EBPF.PayloadExtraction.HTTP.Enrichment.Rules[0].Type)
	require.Equal(t, config.HTTPParsingScopeRequest, got.EBPF.PayloadExtraction.HTTP.Enrichment.Rules[0].Scope)
	require.Equal(t, services.NewGlob("/login"), got.EBPF.PayloadExtraction.HTTP.Enrichment.Rules[0].Match.URLPathPatterns[0])
	require.Equal(t, config.HTTPMethodPOST, got.EBPF.PayloadExtraction.HTTP.Enrichment.Rules[0].Match.Methods[0])
	require.Equal(t, "$.password", got.EBPF.PayloadExtraction.HTTP.Enrichment.Rules[0].Match.ObfuscationJSONPaths[0].String())
}
