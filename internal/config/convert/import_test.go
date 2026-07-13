// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

func TestV2ToRuntimeDefaultExportFoundation(t *testing.T) {
	t.Parallel()

	_, ext := RuntimeToV2(nil)

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.ChannelBufferLen, got.ChannelBufferLen)
	require.Equal(t, obi.DefaultConfig.ChannelSendTimeout, got.ChannelSendTimeout)
	require.Equal(t, obi.DefaultConfig.EnforceSysCaps, got.EnforceSysCaps)
	require.Equal(t, obi.DefaultConfig.EBPF.WakeupLen, got.EBPF.WakeupLen)
	require.Equal(t, obi.DefaultConfig.EBPF.BatchLength, got.EBPF.BatchLength)
	require.Equal(t, obi.DefaultConfig.EBPF.BatchTimeout, got.EBPF.BatchTimeout)
	require.Equal(t, obi.DefaultConfig.EBPF.ContextPropagation, got.EBPF.ContextPropagation)
	require.Equal(t, obi.DefaultConfig.EBPF.TCBackend, got.EBPF.TCBackend)
	require.Equal(t, obi.DefaultConfig.EBPF.ForceBPFMapReader, got.EBPF.ForceBPFMapReader)
	require.Equal(t, obi.DefaultConfig.EBPF.MapsConfig, got.EBPF.MapsConfig)
	require.Equal(t, obi.DefaultConfig.EBPF.InstrumentCuda, got.EBPF.InstrumentCuda)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.Source, got.NetworkFlows.Source)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.ExcludeInterfaces, got.NetworkFlows.ExcludeInterfaces)
	require.Equal(t, obi.DefaultConfig.NodeJS.Enabled, got.NodeJS.Enabled)
	require.Equal(t, obi.DefaultConfig.Java.Enabled, got.Java.Enabled)
	require.Equal(t, obi.DefaultConfig.LogLevel, got.LogLevel)
	require.Equal(t, obi.DefaultConfig.LogFormat, got.LogFormat)
	require.Equal(t, obi.DefaultConfig.LogConfig, got.LogConfig)
	require.Equal(t, obi.DefaultConfig.InternalMetrics, got.InternalMetrics)
	require.Equal(t, export.FeatureApplicationRED, got.Metrics.Features)
	require.Contains(t, got.Traces.Instrumentations, instrumentations.InstrumentationHTTP)
	require.Contains(t, got.Traces.Instrumentations, instrumentations.InstrumentationSunRPC)
	require.NotContains(t, got.Traces.Instrumentations, instrumentations.InstrumentationDNS)
	require.Contains(t, got.OTELMetrics.Instrumentations, instrumentations.InstrumentationHTTP)
	require.NotContains(t, got.OTELMetrics.Instrumentations, instrumentations.InstrumentationDNS)
}

func TestV2ToRuntimeCustomFoundation(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.ChannelBufferLen = 77
	cfg.ChannelSendTimeout = 2 * time.Second
	cfg.ChannelSendTimeoutPanic = true
	cfg.EnforceSysCaps = true

	cfg.Discovery.PollInterval = 5 * time.Second
	cfg.Discovery.MinProcessAge = 6 * time.Second
	cfg.Discovery.BPFPidFilterOff = true
	cfg.Discovery.SkipGoSpecificTracers = true
	cfg.NodeJS.Enabled = false
	cfg.Java.Enabled = false
	cfg.Java.Debug = true
	cfg.Java.DebugInstrumentation = true
	cfg.Java.Timeout = 7 * time.Second

	cfg.EBPF.BpfDebug = true
	cfg.EBPF.ProtocolDebug = true
	cfg.EBPF.WakeupLen = 8
	cfg.EBPF.BatchLength = 9
	cfg.EBPF.BatchTimeout = 10 * time.Second
	cfg.EBPF.ContextPropagation = config.ContextPropagationAll
	cfg.EBPF.OverrideBPFLoopEnabled = true
	cfg.EBPF.DisableBlackBoxCP = true
	cfg.EBPF.TCBackend = config.TCBackendTCX
	cfg.EBPF.HighRequestVolume = true
	cfg.EBPF.ForceBPFMapReader = config.MapReaderLegacy
	cfg.EBPF.MapsConfig.GlobalScaleFactor = 2
	cfg.EBPF.BPFFSPath = "/tmp/bpf"
	cfg.EBPF.MaxTransactionTime = 11 * time.Second
	cfg.EBPF.TrackRequestHeaders = true
	cfg.EBPF.HTTPRequestTimeout = 12 * time.Second
	cfg.EBPF.BufferSizes.HTTP = 100
	cfg.EBPF.BufferSizes.MySQL = 101
	cfg.EBPF.BufferSizes.Postgres = 102
	cfg.EBPF.BufferSizes.MSSQL = 103
	cfg.EBPF.BufferSizes.Kafka = 104
	cfg.EBPF.BufferSizes.TCP = 105
	cfg.EBPF.HeuristicSQLDetect = true
	cfg.EBPF.MySQLPreparedStatementsCacheSize = 200
	cfg.EBPF.PostgresPreparedStatementsCacheSize = 201
	cfg.EBPF.MSSQLPreparedStatementsCacheSize = 202
	cfg.EBPF.RedisDBCache.Enabled = true
	cfg.EBPF.RedisDBCache.MaxSize = 203
	cfg.EBPF.KafkaTopicUUIDCacheSize = 204
	cfg.EBPF.MongoRequestsCacheSize = 205
	cfg.EBPF.CouchbaseDBCacheSize = 206
	cfg.EBPF.DNSRequestTimeout = 13 * time.Second
	cfg.EBPF.InstrumentCuda = config.CudaModeOn

	cfg.Traces.ReportersCacheLen = 301
	cfg.Traces.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationHTTP,
		instrumentations.InstrumentationKafka,
	}
	cfg.OTELMetrics.ReportersCacheLen = 302
	cfg.OTELMetrics.MetricsEndpoint = "http://localhost:4318"
	cfg.OTELMetrics.TTL = 303 * time.Second
	cfg.OTELMetrics.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationHTTP,
	}
	cfg.Prometheus.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationRedis,
		instrumentations.InstrumentationDNS,
	}
	cfg.Prometheus.Port = 9090
	cfg.Metrics.Features = export.FeatureApplicationRED |
		export.FeatureNetwork |
		export.FeatureStatsTCPRtt |
		export.FeatureStatsTCPRetransmits

	cfg.NetworkFlows.Enable = true
	cfg.NetworkFlows.Source = obi.EbpfSourceTC
	cfg.NetworkFlows.AgentIP = "192.0.2.1"
	cfg.NetworkFlows.AgentIPIface = obi.NetworkAgentIPIfaceLocal
	cfg.NetworkFlows.AgentIPType = "ipv4"
	cfg.NetworkFlows.Interfaces = []string{"eth0"}
	cfg.NetworkFlows.ExcludeInterfaces = []string{"lo", "docker0"}
	cfg.NetworkFlows.Protocols = []string{"tcp"}
	cfg.NetworkFlows.ExcludeProtocols = []string{"udp"}
	cfg.NetworkFlows.CacheMaxFlows = 300
	cfg.NetworkFlows.CacheActiveTimeout = 14 * time.Second
	cfg.NetworkFlows.Deduper = "none"
	cfg.NetworkFlows.DeduperFCTTL = 15 * time.Second
	cfg.NetworkFlows.Direction = "egress"
	cfg.NetworkFlows.Sampling = 16
	cfg.NetworkFlows.ListenInterfaces = obi.NetworkListenInterfacesPoll
	cfg.NetworkFlows.ListenPollPeriod = 17 * time.Second
	cfg.NetworkFlows.Print = true
	cfg.Attributes.MetricSpanNameAggregationLimit = 400

	require.NoError(t, yaml.Unmarshal([]byte("- cidr: 192.0.2.0/24\n  name: docs\n"), &cfg.Stats.CIDRs))
	cfg.Stats.AgentIP = "198.51.100.1"
	cfg.Stats.AgentIPIface = obi.NetworkAgentIPIfaceLocal
	cfg.Stats.AgentIPType = "ipv4"
	cfg.Stats.GeoIP.IPInfo.Path = "/var/lib/stats-ipinfo.mmdb"
	cfg.Stats.GeoIP.MaxMindInfo.CountryPath = "/var/lib/stats-country.mmdb"
	cfg.Stats.GeoIP.MaxMindInfo.ASNPath = "/var/lib/stats-asn.mmdb"
	cfg.Stats.GeoIP.CacheLen = 81
	cfg.Stats.GeoIP.CacheTTL = 82 * time.Second
	cfg.Stats.ReverseDNS.Type = "ebpf"
	cfg.Stats.ReverseDNS.CacheLen = 83
	cfg.Stats.ReverseDNS.CacheTTL = 84 * time.Second
	cfg.Stats.Print = true
	srtt := 1024
	cfg.Filters.Stats = filter.AttributeFamilyConfig{
		"srtt": {GreaterThan: &srtt},
	}

	cfg.NameResolver.Sources = []transform.Source{transform.SourceDNS, transform.SourceK8s}
	cfg.NameResolver.CacheLen = 501
	cfg.NameResolver.CacheTTL = 502 * time.Second
	cfg.Attributes.RenameUnresolvedHosts = "unknown"
	cfg.Attributes.RenameUnresolvedHostsOutgoing = "unknown-out"
	cfg.Attributes.RenameUnresolvedHostsIncoming = "unknown-in"

	cfg.EBPF.LogEnricher.Services = []config.LogEnricherServiceConfig{
		{Service: services.GlobDefinitionCriteria{{Path: services.NewGlob("*")}}},
	}
	cfg.EBPF.LogEnricher.CacheTTL = 601 * time.Second
	cfg.EBPF.LogEnricher.CacheSize = 602
	cfg.EBPF.LogEnricher.AsyncWriterWorkers = 603
	cfg.EBPF.LogEnricher.AsyncWriterChannelLen = 604

	cfg.LogLevel = obi.LogLevelDebug
	cfg.LogFormat = obi.LogFormatJSON
	cfg.LogConfig = obi.LogConfigOptionYAML
	cfg.TracePrinter = debug.TracePrinterJSON
	cfg.ProfilePort = 6060
	cfg.ShutdownTimeout = 18 * time.Second
	cfg.InternalMetrics.Exporter = imetrics.InternalMetricsExporterPrometheus
	cfg.InternalMetrics.Prometheus.Port = 9090
	cfg.InternalMetrics.Prometheus.Path = "/debug/metrics"
	cfg.InternalMetrics.BpfMetricScrapeInterval = 19 * time.Second
	cfg.Prometheus.AllowServiceGraphSelfReferences = true
	cfg.Prometheus.SpanMetricsServiceCacheSize = 701
	cfg.Prometheus.ExtraResourceLabels = []string{"cloud.region"}
	cfg.Prometheus.ExtraSpanResourceLabels = []string{"service.version"}

	_, ext := RuntimeToV2(&cfg)

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Equal(t, 77, got.ChannelBufferLen)
	require.Equal(t, 2*time.Second, got.ChannelSendTimeout)
	require.True(t, got.ChannelSendTimeoutPanic)
	require.True(t, got.EnforceSysCaps)
	require.Equal(t, 5*time.Second, got.Discovery.PollInterval)
	require.Equal(t, 6*time.Second, got.Discovery.MinProcessAge)
	require.True(t, got.Discovery.BPFPidFilterOff)
	require.True(t, got.Discovery.SkipGoSpecificTracers)
	require.False(t, got.NodeJS.Enabled)
	require.False(t, got.Java.Enabled)
	require.True(t, got.Java.DebugInstrumentation)
	require.Equal(t, 7*time.Second, got.Java.Timeout)

	require.Equal(t, config.ContextPropagationAll, got.EBPF.ContextPropagation)
	require.Equal(t, config.TCBackendTCX, got.EBPF.TCBackend)
	require.Equal(t, config.MapReaderLegacy, got.EBPF.ForceBPFMapReader)
	require.Equal(t, 2, got.EBPF.MapsConfig.GlobalScaleFactor)
	require.Equal(t, uint32(100), got.EBPF.BufferSizes.HTTP)
	require.Equal(t, uint32(103), got.EBPF.BufferSizes.MSSQL)
	require.Equal(t, 202, got.EBPF.MSSQLPreparedStatementsCacheSize)
	require.Equal(t, config.CudaModeOn, got.EBPF.InstrumentCuda)

	require.Contains(t, got.Traces.Instrumentations, instrumentations.InstrumentationKafka)
	require.NotContains(t, got.Traces.Instrumentations, instrumentations.InstrumentationRedis)
	require.Contains(t, got.OTELMetrics.Instrumentations, instrumentations.InstrumentationHTTP)
	require.NotContains(t, got.OTELMetrics.Instrumentations, instrumentations.InstrumentationKafka)
	require.Contains(t, got.Prometheus.Instrumentations, instrumentations.InstrumentationDNS)
	require.Equal(t,
		export.FeatureApplicationRED|
			export.FeatureNetwork|
			export.FeatureStatsTCPRtt|
			export.FeatureStatsTCPRetransmits,
		got.Metrics.Features,
	)

	require.True(t, got.NetworkFlows.Enable)
	require.Equal(t, obi.EbpfSourceTC, got.NetworkFlows.Source)
	require.Equal(t, "192.0.2.1", got.NetworkFlows.AgentIP)
	require.Equal(t, obi.AgentTypeIface(obi.NetworkAgentIPIfaceLocal), got.NetworkFlows.AgentIPIface)
	require.Equal(t, []string{"eth0"}, got.NetworkFlows.Interfaces)
	require.Equal(t, []string{"udp"}, got.NetworkFlows.ExcludeProtocols)
	require.Equal(t, 300, got.NetworkFlows.CacheMaxFlows)
	require.Equal(t, 14*time.Second, got.NetworkFlows.CacheActiveTimeout)
	require.Equal(t, "none", got.NetworkFlows.Deduper)
	require.Equal(t, 15*time.Second, got.NetworkFlows.DeduperFCTTL)
	require.Equal(t, "egress", got.NetworkFlows.Direction)
	require.Equal(t, 16, got.NetworkFlows.Sampling)
	require.True(t, got.NetworkFlows.Print)
	require.Equal(t, 400, got.Attributes.MetricSpanNameAggregationLimit)
	require.Equal(t, 301, got.Traces.ReportersCacheLen)
	require.Equal(t, 302, got.OTELMetrics.ReportersCacheLen)
	require.Equal(t, 303*time.Second, got.OTELMetrics.TTL)

	require.Equal(t, "198.51.100.1", got.Stats.AgentIP)
	require.Equal(t, obi.AgentTypeIface(obi.NetworkAgentIPIfaceLocal), got.Stats.AgentIPIface)
	require.Equal(t, "ipv4", got.Stats.AgentIPType)
	require.Len(t, got.Stats.CIDRs, 1)
	require.Equal(t, "192.0.2.0/24", got.Stats.CIDRs[0].CIDR)
	require.Equal(t, "docs", got.Stats.CIDRs[0].Name)
	require.Equal(t, filter.MatchDefinition{GreaterThan: &srtt}, got.Filters.Stats["srtt"])
	require.Equal(t, "/var/lib/stats-ipinfo.mmdb", got.Stats.GeoIP.IPInfo.Path)
	require.Equal(t, "/var/lib/stats-country.mmdb", got.Stats.GeoIP.MaxMindInfo.CountryPath)
	require.Equal(t, "/var/lib/stats-asn.mmdb", got.Stats.GeoIP.MaxMindInfo.ASNPath)
	require.Equal(t, 81, got.Stats.GeoIP.CacheLen)
	require.Equal(t, 82*time.Second, got.Stats.GeoIP.CacheTTL)
	require.Equal(t, "ebpf", got.Stats.ReverseDNS.Type)
	require.Equal(t, 83, got.Stats.ReverseDNS.CacheLen)
	require.Equal(t, 84*time.Second, got.Stats.ReverseDNS.CacheTTL)
	require.True(t, got.Stats.Print)

	require.Equal(t, []transform.Source{transform.SourceDNS, transform.SourceK8s}, got.NameResolver.Sources)
	require.Equal(t, 501, got.NameResolver.CacheLen)
	require.Equal(t, 502*time.Second, got.NameResolver.CacheTTL)
	require.Equal(t, "unknown-out", got.Attributes.RenameUnresolvedHostsOutgoing)

	require.True(t, got.EBPF.LogEnricher.Enabled())
	require.Equal(t, 601*time.Second, got.EBPF.LogEnricher.CacheTTL)
	require.Equal(t, 602, got.EBPF.LogEnricher.CacheSize)
	require.Equal(t, 603, got.EBPF.LogEnricher.AsyncWriterWorkers)
	require.Equal(t, 604, got.EBPF.LogEnricher.AsyncWriterChannelLen)

	require.Equal(t, obi.LogLevelDebug, got.LogLevel)
	require.Equal(t, obi.LogFormatJSON, got.LogFormat)
	require.Equal(t, obi.LogConfigOptionYAML, got.LogConfig)
	require.Equal(t, debug.TracePrinterJSON, got.TracePrinter)
	require.Equal(t, 6060, got.ProfilePort)
	require.Equal(t, 18*time.Second, got.ShutdownTimeout)
	require.Equal(t, imetrics.InternalMetricsExporterPrometheus, got.InternalMetrics.Exporter)
	require.Equal(t, 9090, got.InternalMetrics.Prometheus.Port)
	require.Equal(t, "/debug/metrics", got.InternalMetrics.Prometheus.Path)
	require.Equal(t, 19*time.Second, got.InternalMetrics.BpfMetricScrapeInterval)
	require.True(t, got.Prometheus.AllowServiceGraphSelfReferences)
	require.Equal(t, 701, got.Prometheus.SpanMetricsServiceCacheSize)
	require.Equal(t, []string{"cloud.region"}, got.Prometheus.ExtraResourceLabels)
	require.Equal(t, []string{"service.version"}, got.Prometheus.ExtraSpanResourceLabels)
}

func TestV2ToRuntimeImportsRules(t *testing.T) {
	t.Parallel()

	openPorts := services.IntEnum{Ranges: []services.IntRange{{Start: 8080}}}
	got, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Rules: []schema.Rule{
				{
					Action: schema.CaptureActionInclude,
					Match: schema.RuleMatch{
						Process: schema.RuleProcessMatch{
							OpenPorts:      &openPorts,
							TargetPIDs:     []uint32{1234},
							LanguageGlob:   []string{"go", "python"},
							CmdArgsGlob:    []string{"serve"},
							ExePathGlob:    []string{"/srv/*"},
							ContainersOnly: true,
						},
						Kubernetes: schema.RuleKubernetesMatch{
							NamespaceGlob:  []string{"prod"},
							MetadataGlob:   map[string][]string{"k8s.deployment.name": {"checkout*"}},
							PodLabels:      map[string][]string{"app": {"checkout"}},
							PodAnnotations: map[string][]string{"team": {"payments"}},
						},
					},
					Refine: schema.RuleRefinement{
						Exports: &schema.ExportModeRefinement{Traces: true, Metrics: false},
						HTTP: &schema.HTTPRefinement{
							Routes: schema.HTTPRefinementRoutes{
								Incoming: schema.HTTPRefinementRoute{Patterns: []string{"/orders/{id}"}},
								Outgoing: schema.HTTPRefinementRoute{Patterns: []string{"/inventory/{id}"}},
							},
						},
					},
				},
				{
					Action: schema.CaptureActionExclude,
					Match: schema.RuleMatch{
						Process: schema.RuleProcessMatch{
							ExportsOTLP: &schema.RuleExportsOTLP{Port: 4317, Protocol: "protobuf"},
						},
					},
				},
				{
					Action: schema.CaptureActionExclude,
					Match: schema.RuleMatch{
						Process: schema.RuleProcessMatch{
							ExePathRegex: "^/usr/bin/.*",
						},
						Kubernetes: schema.RuleKubernetesMatch{
							NamespaceRegex: "kube-.*",
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	require.Len(t, got.Discovery.Instrument, 1)
	include := got.Discovery.Instrument[0]
	require.Equal(t, []uint32{1234}, include.PIDs)
	require.True(t, include.OpenPorts.Matches(8080))
	require.Equal(t, "{go,python}", globString(include.Languages))
	require.Equal(t, "serve", globString(include.CmdArgs))
	require.Equal(t, "/srv/*", globString(include.Path))
	require.True(t, include.ContainersOnly)
	require.Equal(t, "prod", globString(*include.Metadata[services.AttrNamespace]))
	require.Equal(t, "checkout*", globString(*include.Metadata["k8s.deployment.name"]))
	require.Equal(t, "checkout", globString(*include.PodLabels["app"]))
	require.True(t, include.ExportModes.CanExportTraces())
	require.False(t, include.ExportModes.CanExportMetrics())
	require.Equal(t, []string{"/orders/{id}"}, include.Routes.Incoming)
	require.Equal(t, []string{"/inventory/{id}"}, include.Routes.Outgoing)

	require.True(t, got.Discovery.ExcludeOTelInstrumentedServices)
	require.Equal(t, 4317, got.Discovery.DefaultOtlpGRPCPort)
	require.Len(t, got.Discovery.ExcludeServices, 1)
	exclude := got.Discovery.ExcludeServices[0]
	require.Equal(t, "^/usr/bin/.*", regexString(exclude.Path))
	require.Equal(t, "kube-.*", regexString(*exclude.Metadata[services.AttrNamespace]))
}

func TestV2ToRuntimeSkipsUnsupportedExportsOTLPRules(t *testing.T) {
	t.Parallel()

	got, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Rules: []schema.Rule{
				{
					Action: schema.CaptureActionInclude,
					Match: schema.RuleMatch{
						Process: schema.RuleProcessMatch{
							ExportsOTLP: &schema.RuleExportsOTLP{Port: 4317, Protocol: "protobuf"},
						},
					},
				},
				{
					Action: schema.CaptureActionExclude,
					Match: schema.RuleMatch{
						Process: schema.RuleProcessMatch{
							ExePathGlob: []string{"/srv/*"},
							ExportsOTLP: &schema.RuleExportsOTLP{Port: 4317, Protocol: "protobuf"},
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	require.Empty(t, got.Discovery.Instrument)
	require.Empty(t, got.Discovery.ExcludeInstrument)
	require.False(t, got.Discovery.ExcludeOTelInstrumentedServices)
}

func TestV2ToRuntimeSkipsMixedGlobRegexRules(t *testing.T) {
	t.Parallel()

	got, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Rules: []schema.Rule{
				{
					Action: schema.CaptureActionInclude,
					Match: schema.RuleMatch{
						Process: schema.RuleProcessMatch{
							ExePathGlob: []string{"/srv/*"},
						},
						Kubernetes: schema.RuleKubernetesMatch{
							NamespaceRegex: "prod-.*",
						},
					},
				},
				{
					Action: schema.CaptureActionExclude,
					Match: schema.RuleMatch{
						Process: schema.RuleProcessMatch{
							LanguageRegex: "go|java",
						},
						Kubernetes: schema.RuleKubernetesMatch{
							PodLabels: map[string][]string{"app": {"checkout"}},
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	require.Empty(t, got.Discovery.Instrument)
	require.Empty(t, got.Discovery.Services)
	require.Empty(t, got.Discovery.ExcludeInstrument)
	require.Empty(t, got.Discovery.ExcludeServices)
}

func TestV2ToRuntimeRejectsMalformedRulePatterns(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		match   schema.RuleMatch
		wantErr string
	}{
		{
			name: "glob",
			match: schema.RuleMatch{
				Process: schema.RuleProcessMatch{ExePathGlob: []string{"["}},
			},
			wantErr: "capture.rules[0].match.process.exe_path_glob",
		},
		{
			name: "regex",
			match: schema.RuleMatch{
				Process: schema.RuleProcessMatch{ExePathRegex: "["},
			},
			wantErr: "capture.rules[0].match.process.exe_path_regex",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := V2ToRuntime(&schema.Extension{
				Version: schema.SupportedVersion,
				Capture: schema.Capture{
					Rules: []schema.Rule{
						{
							Action: schema.CaptureActionInclude,
							Match:  tc.match,
						},
					},
				},
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestV2ToRuntimeDefaultIncludeUsesOnlyExclusions(t *testing.T) {
	t.Parallel()

	got, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Policy: schema.CapturePolicy{
				DefaultAction: schema.CaptureActionInclude,
				MatchOrder:    schema.MatchOrderFirstMatchWins,
			},
			Rules: []schema.Rule{
				{
					Action: schema.CaptureActionExclude,
					Match: schema.RuleMatch{
						Process: schema.RuleProcessMatch{
							ExePathGlob: []string{"*/obi", "obi"},
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	require.Empty(t, got.Discovery.Instrument)
	require.Empty(t, got.Discovery.Services)
	require.Len(t, got.Discovery.ExcludeInstrument, 1)
	require.Equal(t, "{*/obi,obi}", globString(got.Discovery.ExcludeInstrument[0].Path))
	require.Empty(t, got.Discovery.ExcludeServices)
}

func TestV2ToRuntimeRulesPresenceControlsSelectorReplacement(t *testing.T) {
	t.Parallel()

	missing, err := V2ToRuntime(&schema.Extension{Version: schema.SupportedVersion})
	require.NoError(t, err)
	require.Equal(t, obi.DefaultConfig.Discovery.DefaultExcludeInstrument, missing.Discovery.DefaultExcludeInstrument)
	require.Equal(t, obi.DefaultConfig.Discovery.DefaultExcludeServices, missing.Discovery.DefaultExcludeServices)
	require.Equal(t,
		obi.DefaultConfig.Discovery.ExcludeOTelInstrumentedServices,
		missing.Discovery.ExcludeOTelInstrumentedServices,
	)

	empty, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Rules: []schema.Rule{},
		},
	})
	require.NoError(t, err)
	require.Empty(t, empty.Discovery.Instrument)
	require.Empty(t, empty.Discovery.ExcludeInstrument)
	require.Empty(t, empty.Discovery.DefaultExcludeInstrument)
	require.Empty(t, empty.Discovery.Services)
	require.Empty(t, empty.Discovery.ExcludeServices)
	require.Empty(t, empty.Discovery.DefaultExcludeServices)
	require.False(t, empty.Discovery.ExcludeOTelInstrumentedServices)
}

func TestV2ToRuntimePreservesDefaultsForMissingSections(t *testing.T) {
	t.Parallel()

	got, err := V2ToRuntime(&schema.Extension{Version: schema.SupportedVersion})
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.ChannelBufferLen, got.ChannelBufferLen)
	require.Equal(t, obi.DefaultConfig.EBPF.BatchLength, got.EBPF.BatchLength)
	require.Equal(t, obi.DefaultConfig.Metrics.Features, got.Metrics.Features)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.Enable, got.NetworkFlows.Enable)
}

func TestV2ToRuntimePartialInstrumentationPreservesDefaults(t *testing.T) {
	t.Parallel()

	got, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Instrumentation: schema.Instrumentation{
				HTTP: schema.HTTPInstrumentation{
					TrackRequestHeaders: true,
				},
			},
		},
	})
	require.NoError(t, err)

	require.True(t, got.EBPF.TrackRequestHeaders)
	require.Equal(t, obi.DefaultConfig.Traces.Instrumentations, got.Traces.Instrumentations)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.Instrumentations, got.OTELMetrics.Instrumentations)
	require.Equal(t, obi.DefaultConfig.Prometheus.Instrumentations, got.Prometheus.Instrumentations)
	require.Equal(t, obi.DefaultConfig.Metrics.Features, got.Metrics.Features)
	require.Equal(t, obi.DefaultConfig.EBPF.MySQLPreparedStatementsCacheSize, got.EBPF.MySQLPreparedStatementsCacheSize)
}

func TestV2ToRuntimePartialCaptureSectionsPreserveDefaults(t *testing.T) {
	t.Parallel()

	got, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Policy: schema.CapturePolicy{
				MinProcessAge: schema.Duration(6 * time.Second),
			},
			Limits: schema.CaptureLimits{
				MetricSpanNames: 400,
			},
			Safety: schema.CaptureSafety{
				EnforceSystemCapabilities: true,
			},
			Channels: schema.CaptureChannels{
				BufferLen: 77,
			},
			Engine: schema.CaptureEngine{
				Debug: schema.EngineDebug{
					BPF: true,
				},
			},
			Network: schema.CaptureNetwork{
				Capture: schema.NetworkCapture{
					Enabled: true,
				},
				Stats: schema.NetworkStats{
					EndpointIdentity: schema.EndpointIdentity{
						AgentIP: "198.51.100.1",
					},
					Diagnostics: schema.StatsDiagnostics{
						PrintStats: true,
					},
				},
			},
			Runtimes: schema.CaptureRuntimes{
				Java: schema.JavaRuntime{
					Debug: schema.JavaDebug{
						Enabled: true,
					},
				},
			},
			Telemetry: schema.CaptureTelemetry{
				Traces: schema.TracesTelemetry{
					ReportersCacheLen: 301,
				},
			},
		},
	})
	require.NoError(t, err)

	require.Equal(t, 6*time.Second, got.Discovery.MinProcessAge)
	require.Equal(t, obi.DefaultConfig.Discovery.PollInterval, got.Discovery.PollInterval)
	require.Equal(t, 400, got.Attributes.MetricSpanNameAggregationLimit)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.CacheMaxFlows, got.NetworkFlows.CacheMaxFlows)
	require.True(t, got.EnforceSysCaps)

	require.Equal(t, 77, got.ChannelBufferLen)
	require.Equal(t, obi.DefaultConfig.ChannelSendTimeout, got.ChannelSendTimeout)
	require.Equal(t, obi.DefaultConfig.ChannelSendTimeoutPanic, got.ChannelSendTimeoutPanic)

	require.True(t, got.EBPF.BpfDebug)
	require.Equal(t, obi.DefaultConfig.EBPF.WakeupLen, got.EBPF.WakeupLen)
	require.Equal(t, obi.DefaultConfig.EBPF.BatchLength, got.EBPF.BatchLength)
	require.Equal(t, obi.DefaultConfig.EBPF.TCBackend, got.EBPF.TCBackend)
	require.Equal(t, obi.DefaultConfig.EBPF.ForceBPFMapReader, got.EBPF.ForceBPFMapReader)
	require.Equal(t, obi.DefaultConfig.EBPF.MaxTransactionTime, got.EBPF.MaxTransactionTime)

	require.True(t, got.NetworkFlows.Enable)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.Source, got.NetworkFlows.Source)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.ExcludeInterfaces, got.NetworkFlows.ExcludeInterfaces)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.CacheActiveTimeout, got.NetworkFlows.CacheActiveTimeout)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.Deduper, got.NetworkFlows.Deduper)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.ListenInterfaces, got.NetworkFlows.ListenInterfaces)
	require.Equal(t, export.FeatureApplicationRED|export.FeatureNetwork, got.Metrics.Features)
	require.Equal(t, "198.51.100.1", got.Stats.AgentIP)
	require.Equal(t, obi.DefaultConfig.Stats.AgentIPIface, got.Stats.AgentIPIface)
	require.Equal(t, obi.DefaultConfig.Stats.AgentIPType, got.Stats.AgentIPType)
	require.True(t, got.Stats.Print)
	require.Equal(t, obi.DefaultConfig.Stats.ReverseDNS.CacheTTL, got.Stats.ReverseDNS.CacheTTL)

	require.True(t, got.Java.Debug)
	require.Equal(t, obi.DefaultConfig.Discovery.SkipGoSpecificTracers, got.Discovery.SkipGoSpecificTracers)
	require.Equal(t, obi.DefaultConfig.NodeJS.Enabled, got.NodeJS.Enabled)
	require.Equal(t, obi.DefaultConfig.Java.Enabled, got.Java.Enabled)
	require.Equal(t, obi.DefaultConfig.Java.Timeout, got.Java.Timeout)

	require.Equal(t, 301, got.Traces.ReportersCacheLen)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.ReportersCacheLen, got.OTELMetrics.ReportersCacheLen)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.TTL, got.OTELMetrics.TTL)
}

func TestV2ToRuntimeOmittedCaptureSiblingsPreserveDefaults(t *testing.T) {
	t.Parallel()

	_, ext := RuntimeToV2(nil)
	ext.Capture.Limits = schema.CaptureLimits{}
	ext.Capture.Channels = schema.CaptureChannels{}
	ext.Capture.Runtimes = schema.CaptureRuntimes{}
	ext.Capture.Telemetry = schema.CaptureTelemetry{}

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.Attributes.MetricSpanNameAggregationLimit, got.Attributes.MetricSpanNameAggregationLimit)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.CacheMaxFlows, got.NetworkFlows.CacheMaxFlows)
	require.Equal(t, obi.DefaultConfig.ChannelBufferLen, got.ChannelBufferLen)
	require.Equal(t, obi.DefaultConfig.ChannelSendTimeout, got.ChannelSendTimeout)
	require.Equal(t, obi.DefaultConfig.ChannelSendTimeoutPanic, got.ChannelSendTimeoutPanic)
	require.Equal(t, obi.DefaultConfig.Discovery.SkipGoSpecificTracers, got.Discovery.SkipGoSpecificTracers)
	require.Equal(t, obi.DefaultConfig.NodeJS.Enabled, got.NodeJS.Enabled)
	require.Equal(t, obi.DefaultConfig.Java.Enabled, got.Java.Enabled)
	require.Equal(t, obi.DefaultConfig.Java.Timeout, got.Java.Timeout)
	require.Equal(t, obi.DefaultConfig.Traces.ReportersCacheLen, got.Traces.ReportersCacheLen)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.ReportersCacheLen, got.OTELMetrics.ReportersCacheLen)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.TTL, got.OTELMetrics.TTL)
}

func TestV2ToRuntimeCompleteDaemonOmittedLoggingFieldsPreserveDefaults(t *testing.T) {
	t.Parallel()

	_, ext := RuntimeToV2(nil)
	ext.Daemon.Logging = schema.Logging{
		ConfigFormat: schema.ConfigFormatYAML,
	}
	ext.Daemon.Telemetry.Metrics.Prometheus.AllowServiceGraphSelfReferences = true
	ext.Daemon.Telemetry.Metrics.Prometheus.SpanMetricsServiceCacheSize = 0

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.LogLevel, got.LogLevel)
	require.Equal(t, obi.DefaultConfig.LogFormat, got.LogFormat)
	require.Equal(t, obi.LogConfigOptionYAML, got.LogConfig)
	require.Equal(t, obi.DefaultConfig.TracePrinter, got.TracePrinter)
	require.True(t, got.Prometheus.AllowServiceGraphSelfReferences)
	require.Equal(t, obi.DefaultConfig.Prometheus.SpanMetricsServiceCacheSize, got.Prometheus.SpanMetricsServiceCacheSize)
}

func TestV2ToRuntimePartialStandaloneSectionsPreserveDefaults(t *testing.T) {
	t.Parallel()

	got, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Correlation: &schema.Correlation{
			LogTraceAnnotation: schema.LogTraceAnnotation{
				Enabled: true,
			},
		},
		Daemon: &schema.Daemon{
			Logging: schema.Logging{
				Level: schema.LogLevelDebug,
			},
		},
	})
	require.NoError(t, err)

	require.Equal(t, obi.LogLevelDebug, got.LogLevel)
	require.Equal(t, obi.DefaultConfig.ShutdownTimeout, got.ShutdownTimeout)
	require.Equal(t, obi.DefaultConfig.InternalMetrics, got.InternalMetrics)
	require.Equal(t, obi.DefaultConfig.Prometheus.SpanMetricsServiceCacheSize, got.Prometheus.SpanMetricsServiceCacheSize)
	require.True(t, got.EBPF.LogEnricher.Enabled())
	require.Equal(t, obi.DefaultConfig.EBPF.LogEnricher.CacheTTL, got.EBPF.LogEnricher.CacheTTL)
	require.Equal(t, obi.DefaultConfig.EBPF.LogEnricher.AsyncWriterWorkers, got.EBPF.LogEnricher.AsyncWriterWorkers)
}
