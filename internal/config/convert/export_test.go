// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestRuntimeToV2DefaultConfig(t *testing.T) {
	t.Parallel()

	doc, ext := RuntimeToV2(nil)

	require.Equal(t, "1.0", doc.FileFormat)
	require.Same(t, ext, doc.Extensions.OBI)
	require.NotNil(t, doc.Resource)
	require.NotNil(t, doc.Propagator)
	require.NotNil(t, doc.TracerProvider)
	require.NotNil(t, doc.MeterProvider)
	require.Equal(t, schema.SupportedVersion, ext.Version)
	require.NotNil(t, ext.Capture.Rules)
	require.NotNil(t, ext.Capture.Telemetry)

	require.Equal(t, "include", value(t, ext.Capture.Policy, "default_action"))
	require.Equal(t, "first_match_wins", value(t, ext.Capture.Policy, "match_order"))
	require.Equal(t, "0s", value(t, ext.Capture.Policy, "poll_interval"))
	require.Equal(t, "5s", value(t, ext.Capture.Policy, "min_process_age"))

	require.Equal(t, 500, value(t, ext.Capture.Engine, "batching", "wakeup_len"))
	require.Equal(t, 100, value(t, ext.Capture.Engine, "batching", "batch_length"))
	require.Equal(t, "1s", value(t, ext.Capture.Engine, "batching", "batch_timeout"))
	require.Equal(t, "auto", value(t, ext.Capture.Engine, "traffic", "control_backend"))
	require.Equal(t, "auto", value(t, ext.Capture.Engine, "traffic", "force_map_reader"))
	require.Equal(t, 0, value(t, ext.Capture.Engine, "maps", "global_scale_factor"))
	require.Equal(t, "/sys/fs/bpf/", value(t, ext.Capture.Engine, "bpf_filesystem", "path"))

	require.Equal(t, 50, value(t, ext.Capture.Channels, "buffer_len"))
	require.Equal(t, "1m0s", value(t, ext.Capture.Channels, "send_timeout"))
	require.Equal(t, false, value(t, ext.Capture.Safety, "enforce_system_capabilities"))
	require.Equal(t, 100, value(t, ext.Capture.Limits, "metric_span_names"))

	require.Equal(t, false, value(t, ext.Capture.Network, "capture", "enabled"))
	require.Equal(t, obi.EbpfSourceSock, value(t, ext.Capture.Network, "capture", "source"))
	require.Equal(t, []string{"lo"}, value(t, ext.Capture.Network, "capture", "selection", "interfaces", "exclude"))
	require.Equal(t, "both", value(t, ext.Capture.Network, "capture", "selection", "direction"))
	require.Equal(t, false, value(t, ext.Capture.Network, "stats", "enabled"))
	require.Empty(t, value(t, ext.Capture.Network, "stats", "features"))

	require.Equal(t, true, value(t, ext.Capture.Instrumentation, "http", "enabled", "traces"))
	require.Equal(t, true, value(t, ext.Capture.Instrumentation, "http", "enabled", "metrics"))
	require.Equal(t, false, value(t, ext.Capture.Instrumentation, "dns", "enabled", "traces"))
	require.Equal(t, false, value(t, ext.Capture.Instrumentation, "dns", "enabled", "metrics"))
	require.ElementsMatch(t, []string{
		"http",
		"grpc",
		"sql",
		"redis",
		"kafka",
		"mongo",
		"couchbase",
		"dns",
		"gpu",
	}, keys(ext.Capture.Instrumentation))

	require.Equal(t, true, value(t, ext.Capture.Runtimes, "go", "enabled"))
	require.Equal(t, true, value(t, ext.Capture.Runtimes, "nodejs", "enabled"))
	require.Equal(t, true, value(t, ext.Capture.Runtimes, "java", "enabled"))

	require.Equal(t, obi.LogLevelInfo, value(t, ext.Daemon, "logging", "level"))
	require.Equal(t, debug.TracePrinterDisabled, value(t, ext.Daemon, "logging", "debug_trace_output"))
	require.Equal(t, "10s", value(t, ext.Daemon, "shutdown", "timeout"))
	require.Equal(t, imetrics.InternalMetricsExporterDisabled, value(t, ext.Daemon, "internal_metrics", "exporter"))
	require.Equal(t, "/internal/metrics", value(t, ext.Daemon, "internal_metrics", "prometheus", "path"))

	require.Len(t, ext.Capture.Rules, 4)
	require.Equal(t, "exclude-obi-and-collectors", ext.Capture.Rules[0].Name)
	require.Equal(t, "exclude-system-namespaces", ext.Capture.Rules[1].Name)
	require.Equal(t, "exclude-otlp-exporters", ext.Capture.Rules[2].Name)
	require.Equal(t, "exclude-linux-system-paths", ext.Capture.Rules[3].Name)
	require.Equal(t, 4317, value(t, ext.Capture.Rules[2].Match, "process", "exports_otlp", "port"))
	require.Equal(t, "protobuf", value(t, ext.Capture.Rules[2].Match, "process", "exports_otlp", "protocol"))
}

func TestRuntimeToV2NilRoutesOnlyExportsDiscovery(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.Routes = nil

	_, ext := RuntimeToV2(&cfg)

	routes, ok := value(t, ext.Capture.Instrumentation, "http", "routes").(map[string]any)
	require.True(t, ok)
	require.Contains(t, routes, "discovery")
	for _, key := range []string{
		"unmatched",
		"patterns",
		"ignored_patterns",
		"ignore_mode",
		"wildcard_char",
		"max_path_segment_cardinality",
	} {
		require.NotContains(t, routes, key)
	}
}

func TestRuntimeToV2CustomConfig(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.ChannelBufferLen = 77
	cfg.ChannelSendTimeout = 2 * time.Second
	cfg.ChannelSendTimeoutPanic = true
	cfg.EnforceSysCaps = true
	cfg.LogLevel = obi.LogLevelDebug
	cfg.LogConfig = obi.LogConfigOptionJSON
	cfg.TracePrinter = debug.TracePrinterJSON
	cfg.ShutdownTimeout = 3 * time.Second
	cfg.ProfilePort = 6060
	cfg.InternalMetrics.Exporter = imetrics.InternalMetricsExporterPrometheus
	cfg.InternalMetrics.Prometheus.Port = 9090
	cfg.InternalMetrics.Prometheus.Path = "/debug/metrics"
	cfg.InternalMetrics.BpfMetricScrapeInterval = 4 * time.Second

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

	cfg.Traces.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationHTTP,
		instrumentations.InstrumentationKafka,
	}
	cfg.OTELMetrics.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationHTTP,
	}
	cfg.Prometheus.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationRedis,
		instrumentations.InstrumentationDNS,
	}
	cfg.Metrics.Features = export.FeatureApplicationRED | export.FeatureNetwork

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

	_, ext := RuntimeToV2(&cfg)

	require.Equal(t, 77, value(t, ext.Capture.Channels, "buffer_len"))
	require.Equal(t, "2s", value(t, ext.Capture.Channels, "send_timeout"))
	require.Equal(t, true, value(t, ext.Capture.Channels, "panic_on_send_timeout"))
	require.Equal(t, true, value(t, ext.Capture.Safety, "enforce_system_capabilities"))
	require.Equal(t, 400, value(t, ext.Capture.Limits, "metric_span_names"))

	require.Equal(t, "5s", value(t, ext.Capture.Policy, "poll_interval"))
	require.Equal(t, "6s", value(t, ext.Capture.Policy, "min_process_age"))
	require.Equal(t, true, value(t, ext.Capture.Engine, "pid_filter", "disabled"))
	require.Equal(t, 8, value(t, ext.Capture.Engine, "batching", "wakeup_len"))
	require.Equal(t, 9, value(t, ext.Capture.Engine, "batching", "batch_length"))
	require.Equal(t, "10s", value(t, ext.Capture.Engine, "batching", "batch_timeout"))
	require.Equal(t, "all", value(t, ext.Capture.Engine, "propagation", "context_propagation"))
	require.Equal(t, "tcx", value(t, ext.Capture.Engine, "traffic", "control_backend"))
	require.Equal(t, true, value(t, ext.Capture.Engine, "traffic", "high_request_volume"))
	require.Equal(t, "/tmp/bpf", value(t, ext.Capture.Engine, "bpf_filesystem", "path"))

	require.Equal(t, true, value(t, ext.Capture.Instrumentation, "http", "enabled", "traces"))
	require.Equal(t, true, value(t, ext.Capture.Instrumentation, "http", "enabled", "metrics"))
	require.Equal(t, true, value(t, ext.Capture.Instrumentation, "kafka", "enabled", "traces"))
	require.Equal(t, false, value(t, ext.Capture.Instrumentation, "kafka", "enabled", "metrics"))
	require.Equal(t, false, value(t, ext.Capture.Instrumentation, "redis", "enabled", "traces"))
	require.Equal(t, true, value(t, ext.Capture.Instrumentation, "redis", "enabled", "metrics"))
	require.Equal(t, false, value(t, ext.Capture.Instrumentation, "dns", "enabled", "traces"))
	require.Equal(t, true, value(t, ext.Capture.Instrumentation, "dns", "enabled", "metrics"))
	require.Equal(t, false, value(t, ext.Capture.Instrumentation, "grpc", "enabled", "traces"))
	require.Equal(t, false, value(t, ext.Capture.Instrumentation, "grpc", "enabled", "metrics"))
	require.Equal(t, uint32(100), value(t, ext.Capture.Instrumentation, "http", "buffer_size"))
	require.Equal(t, uint32(101), value(t, ext.Capture.Instrumentation, "sql", "mysql", "buffer_size"))
	require.Equal(t, uint32(103), value(t, ext.Capture.Instrumentation, "sql", "mssql", "buffer_size"))
	require.Equal(t, 202, value(t, ext.Capture.Instrumentation, "sql", "mssql", "prepared_statements_cache_size"))
	require.Equal(t, true, value(t, ext.Capture.Instrumentation, "redis", "db_cache", "enabled"))
	require.Equal(t, 204, value(t, ext.Capture.Instrumentation, "kafka", "topic_uuid_cache_size"))
	require.Equal(t, "on", value(t, ext.Capture.Instrumentation, "gpu", "enabled_mode"))

	require.Equal(t, false, value(t, ext.Capture.Runtimes, "go", "enabled"))
	require.Equal(t, false, value(t, ext.Capture.Runtimes, "nodejs", "enabled"))
	require.Equal(t, false, value(t, ext.Capture.Runtimes, "java", "enabled"))
	require.Equal(t, true, value(t, ext.Capture.Runtimes, "java", "debug", "bytecode_instrumentation"))
	require.Equal(t, "7s", value(t, ext.Capture.Runtimes, "java", "attach_timeout"))

	require.Equal(t, true, value(t, ext.Capture.Network, "capture", "enabled"))
	require.Equal(t, obi.EbpfSourceTC, value(t, ext.Capture.Network, "capture", "source"))
	require.Equal(t, uint32(105), value(t, ext.Capture.Network, "capture", "buffer_size"))
	require.Equal(t, "192.0.2.1", value(t, ext.Capture.Network, "capture", "endpoint_identity", "agent_ip"))
	require.Equal(t, obi.AgentTypeIface(obi.NetworkAgentIPIfaceLocal), value(t, ext.Capture.Network, "capture", "endpoint_identity", "agent_ip_interface"))
	require.Equal(t, []string{"eth0"}, value(t, ext.Capture.Network, "capture", "selection", "interfaces", "include"))
	require.Equal(t, []string{"udp"}, value(t, ext.Capture.Network, "capture", "selection", "protocols", "exclude"))
	require.Equal(t, "egress", value(t, ext.Capture.Network, "capture", "selection", "direction"))
	require.Equal(t, 300, value(t, ext.Capture.Network, "capture", "flow_lifecycle", "max_tracked_flows"))
	require.Equal(t, "none", value(t, ext.Capture.Network, "capture", "flow_lifecycle", "deduplication", "strategy"))
	require.Equal(t, "15s", value(t, ext.Capture.Network, "capture", "flow_lifecycle", "deduplication", "first_come_ttl"))
	require.Equal(t, true, value(t, ext.Capture.Network, "capture", "diagnostics", "print_flows"))

	require.Equal(t, obi.LogLevelDebug, value(t, ext.Daemon, "logging", "level"))
	require.Equal(t, obi.LogConfigOptionJSON, value(t, ext.Daemon, "logging", "format"))
	require.Equal(t, debug.TracePrinterJSON, value(t, ext.Daemon, "logging", "debug_trace_output"))
	require.Equal(t, 6060, value(t, ext.Daemon, "profiling", "port"))
	require.Equal(t, "3s", value(t, ext.Daemon, "shutdown", "timeout"))
	require.Equal(t, imetrics.InternalMetricsExporterPrometheus, value(t, ext.Daemon, "internal_metrics", "exporter"))
	require.Equal(t, 9090, value(t, ext.Daemon, "internal_metrics", "prometheus", "port"))
	require.Equal(t, "4s", value(t, ext.Daemon, "internal_metrics", "bpf", "scrape_interval"))
}

func TestRuntimeToV2AdvancedCaptureParity(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.Discovery.DefaultExcludeInstrument = nil
	cfg.Discovery.ExcludeOTelInstrumentedServices = false
	cfg.Discovery.ExcludedLinuxSystemPaths = nil

	ports := services.IntEnum{}
	require.NoError(t, ports.UnmarshalText([]byte("8080,9090-9091")))
	exports := services.NewExportModes()
	exports.AllowMetrics()
	cfg.Discovery.Instrument = services.GlobDefinitionCriteria{
		{
			OpenPorts:      ports,
			PIDs:           []uint32{1234, 5678},
			Languages:      services.NewGlob("{go,java}"),
			CmdArgs:        services.NewGlob("*--serve*"),
			Path:           services.NewGlob("/usr/bin/checkout"),
			ContainersOnly: true,
			Metadata: services.MetadataGlobMap{
				services.AttrNamespace:      globPtr("shop-*"),
				services.AttrDeploymentName: globPtr("checkout-*"),
			},
			PodLabels: map[string]*services.GlobAttr{
				"app": globPtr("checkout"),
			},
			PodAnnotations: map[string]*services.GlobAttr{
				"team": globPtr("payments"),
			},
			ExportModes: exports,
			Routes: &services.CustomRoutesConfig{
				Incoming: []string{"/orders/{id}"},
				Outgoing: []string{"/inventory/{id}"},
			},
		},
	}
	cfg.Discovery.ExcludeInstrument = services.GlobDefinitionCriteria{
		{
			Path: services.NewGlob("/tmp/*"),
		},
	}
	cfg.Discovery.ExcludeOTelInstrumentedServices = true
	cfg.Discovery.DefaultOtlpGRPCPort = 14317
	cfg.Discovery.ExcludedLinuxSystemPaths = []string{"/lib/systemd/", "/usr/sbin"}

	cfg.Routes.Unmatch = "path"
	cfg.Routes.Patterns = []string{"/products/{id}"}
	cfg.Routes.IgnorePatterns = []string{"/health"}
	cfg.Routes.IgnoredEvents = "traces"
	cfg.Routes.WildcardChar = "#"
	cfg.Routes.MaxPathSegmentCardinality = 22
	cfg.Discovery.RouteHarvesterTimeout = 23 * time.Second
	cfg.Discovery.DisabledRouteHarvesters = []services.RouteHarvesterLanguage{
		services.RouteHarvesterLanguageJava,
	}
	cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay = 24 * time.Second

	eq := 500
	gt := 1024
	cfg.Filters.Application = filter.AttributeFamilyConfig{
		"http.status_code": {Equals: &eq},
		"service.name":     {Match: "checkout-*"},
	}
	cfg.Filters.Network = filter.AttributeFamilyConfig{
		"src.address": {NotMatch: "10.*"},
	}
	cfg.Filters.Stats = filter.AttributeFamilyConfig{
		"srtt": {GreaterThan: &gt},
	}

	cfg.EBPF.PayloadExtraction.HTTP.GraphQL.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.Elasticsearch.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.AWS.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.SQLPP.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.SQLPP.EndpointPatterns = []string{"/query", "/analytics"}
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.OpenAI.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Anthropic.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Gemini.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Qwen.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Bedrock.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.MCP.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Embedding.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Rerank.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Retrieval.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.JSONRPC.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Enabled = true
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.DefaultAction.Headers = config.HTTPParsingActionInclude
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.DefaultAction.Body = config.HTTPParsingActionObfuscate
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.ObfuscationString = "[redacted]"
	jsonPath, err := config.NewJSONPathExpr("$.secret")
	require.NoError(t, err)
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Rules = []config.HTTPParsingRule{
		{
			Action: config.HTTPParsingActionObfuscate,
			Type:   config.HTTPParsingRuleTypeBody,
			Scope:  config.HTTPParsingScopeRequest,
			Match: config.HTTPParsingMatch{
				ObfuscationJSONPaths: []config.JSONPathExpr{jsonPath},
				Methods:              []config.HTTPMethod{config.HTTPMethodPOST},
			},
		},
	}

	require.NoError(t, yaml.Unmarshal([]byte("- cidr: 10.0.0.0/8\n  name: private\n"), &cfg.NetworkFlows.CIDRs))
	cfg.NetworkFlows.GeoIP.IPInfo.Path = "/var/lib/ipinfo.mmdb"
	cfg.NetworkFlows.GeoIP.MaxMindInfo.CountryPath = "/var/lib/country.mmdb"
	cfg.NetworkFlows.GeoIP.MaxMindInfo.ASNPath = "/var/lib/asn.mmdb"
	cfg.NetworkFlows.GeoIP.CacheLen = 77
	cfg.NetworkFlows.GeoIP.CacheTTL = 78 * time.Second
	cfg.NetworkFlows.ReverseDNS.Type = "local"
	cfg.NetworkFlows.ReverseDNS.CacheLen = 79
	cfg.NetworkFlows.ReverseDNS.CacheTTL = 80 * time.Second
	cfg.NetworkFlows.GuessPorts = "ordinal"

	require.NoError(t, yaml.Unmarshal([]byte("- cidr: 192.0.2.0/24\n  name: docs\n"), &cfg.Stats.CIDRs))
	cfg.Stats.AgentIP = "198.51.100.1"
	cfg.Stats.AgentIPIface = obi.NetworkAgentIPIfaceLocal
	cfg.Stats.AgentIPType = "ipv4"
	cfg.Stats.GeoIP.IPInfo.Path = "/var/lib/stats-ipinfo.mmdb"
	cfg.Stats.GeoIP.CacheLen = 81
	cfg.Stats.GeoIP.CacheTTL = 82 * time.Second
	cfg.Stats.ReverseDNS.Type = "ebpf"
	cfg.Stats.ReverseDNS.CacheLen = 83
	cfg.Stats.ReverseDNS.CacheTTL = 84 * time.Second
	cfg.Stats.Print = true

	_, ext := RuntimeToV2(&cfg)

	require.Equal(t, "exclude", value(t, ext.Capture.Policy, "default_action"))
	require.Equal(t, cfg.Routes.Unmatch, value(t, ext.Capture.Instrumentation, "http", "routes", "unmatched"))
	require.Equal(t, []string{"/products/{id}"}, value(t, ext.Capture.Instrumentation, "http", "routes", "patterns"))
	require.Equal(t, []string{"/health"}, value(t, ext.Capture.Instrumentation, "http", "routes", "ignored_patterns"))
	require.Equal(t, cfg.Routes.IgnoredEvents, value(t, ext.Capture.Instrumentation, "http", "routes", "ignore_mode"))
	require.Equal(t, "#", value(t, ext.Capture.Instrumentation, "http", "routes", "wildcard_char"))
	require.Equal(t, 22, value(t, ext.Capture.Instrumentation, "http", "routes", "max_path_segment_cardinality"))
	require.Equal(t, "23s", value(t, ext.Capture.Instrumentation, "http", "routes", "discovery", "timeout"))
	require.Equal(t, []services.RouteHarvesterLanguage{services.RouteHarvesterLanguageJava}, value(t, ext.Capture.Instrumentation, "http", "routes", "discovery", "disabled_languages"))
	require.Equal(t, "24s", value(t, ext.Capture.Instrumentation, "http", "routes", "discovery", "java", "delay"))

	require.Equal(t, map[string]any{"equals": 500}, value(t, ext.Capture.Instrumentation, "http", "filters", "traces", "http.status_code"))
	require.Equal(t, map[string]any{"match": "checkout-*"}, value(t, ext.Capture.Instrumentation, "kafka", "filters", "metrics", "service.name"))
	require.Equal(t, map[string]any{"not_match": "10.*"}, value(t, ext.Capture.Network, "capture", "filters", "traces", "src.address"))
	require.Equal(t, map[string]any{"greater_than": 1024}, value(t, ext.Capture.Network, "stats", "filters", "metrics", "srtt"))

	require.ElementsMatch(t, []string{
		"graphql", "elasticsearch", "aws", "sqlpp", "openai", "anthropic", "gemini",
		"qwen", "bedrock", "mcp", "embedding", "rerank", "retrieval", "jsonrpc", "enrichment",
	}, value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "enabled"))
	require.Equal(t, []string{"/query", "/analytics"}, value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "sqlpp", "endpoint_patterns"))
	require.Equal(t, "include", value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "enrichment", "policy", "default_action", "headers"))
	require.Equal(t, "obfuscate", value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "enrichment", "policy", "default_action", "body"))
	require.Equal(t, "[redacted]", value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "enrichment", "policy", "obfuscation_string"))
	require.Equal(t, cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Rules, value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "enrichment", "rules"))

	require.Equal(t, cfg.NetworkFlows.CIDRs, value(t, ext.Capture.Network, "capture", "selection", "cidrs"))
	require.Equal(t, cfg.NetworkFlows.GuessPorts, value(t, ext.Capture.Network, "capture", "flow_lifecycle", "guess_ports"))
	require.Equal(t, "/var/lib/ipinfo.mmdb", value(t, ext.Capture.Network, "capture", "enrichment", "geo_ip", "ipinfo", "path"))
	require.Equal(t, "/var/lib/country.mmdb", value(t, ext.Capture.Network, "capture", "enrichment", "geo_ip", "maxmind", "country_path"))
	require.Equal(t, "/var/lib/asn.mmdb", value(t, ext.Capture.Network, "capture", "enrichment", "geo_ip", "maxmind", "asn_path"))
	require.Equal(t, 77, value(t, ext.Capture.Network, "capture", "enrichment", "geo_ip", "cache", "size"))
	require.Equal(t, (78 * time.Second).String(), value(t, ext.Capture.Network, "capture", "enrichment", "geo_ip", "cache", "ttl"))
	require.Equal(t, "local", value(t, ext.Capture.Network, "capture", "enrichment", "reverse_dns", "mode"))
	require.Equal(t, 79, value(t, ext.Capture.Network, "capture", "enrichment", "reverse_dns", "cache", "size"))

	require.Equal(t, "198.51.100.1", value(t, ext.Capture.Network, "stats", "endpoint_identity", "agent_ip"))
	require.Equal(t, cfg.Stats.CIDRs, value(t, ext.Capture.Network, "stats", "selection", "cidrs"))
	require.Equal(t, "/var/lib/stats-ipinfo.mmdb", value(t, ext.Capture.Network, "stats", "enrichment", "geo_ip", "ipinfo", "path"))
	require.Equal(t, "ebpf", value(t, ext.Capture.Network, "stats", "enrichment", "reverse_dns", "mode"))
	require.Equal(t, true, value(t, ext.Capture.Network, "stats", "diagnostics", "print_stats"))

	require.Len(t, ext.Capture.Rules, 4)
	require.Equal(t, "exclude", ext.Capture.Rules[0].Action)
	require.Equal(t, []string{"/tmp/*"}, value(t, ext.Capture.Rules[0].Match, "process", "exe_path_glob"))
	require.Equal(t, 14317, value(t, ext.Capture.Rules[1].Match, "process", "exports_otlp", "port"))
	require.Equal(t, []string{"/lib/systemd/*", "/usr/sbin/*"}, value(t, ext.Capture.Rules[2].Match, "process", "exe_path_glob"))
	require.Equal(t, "include", ext.Capture.Rules[3].Action)
	require.Equal(t, ports, value(t, ext.Capture.Rules[3].Match, "process", "open_ports"))
	require.Equal(t, []uint32{1234, 5678}, value(t, ext.Capture.Rules[3].Match, "process", "target_pids"))
	require.Equal(t, []string{"go", "java"}, value(t, ext.Capture.Rules[3].Match, "process", "language_glob"))
	require.Equal(t, true, value(t, ext.Capture.Rules[3].Match, "process", "containers_only"))
	require.Equal(t, []string{"shop-*"}, value(t, ext.Capture.Rules[3].Match, "kubernetes", "namespace_glob"))
	require.Equal(t, []string{"checkout-*"}, value(t, ext.Capture.Rules[3].Match, "kubernetes", "metadata_glob", services.AttrDeploymentName))
	require.Equal(t, []string{"checkout"}, value(t, ext.Capture.Rules[3].Match, "kubernetes", "pod_labels", "app"))
	require.Equal(t, []string{"payments"}, value(t, ext.Capture.Rules[3].Match, "kubernetes", "pod_annotations", "team"))
	require.Equal(t, map[string]any{"traces": false, "metrics": true}, ext.Capture.Rules[3].Refine.Exports)
	require.Nil(t, ext.Capture.Rules[3].Refine.HTTP)
}

func TestRuntimeToV2EffectiveDiscoveryCriteria(t *testing.T) {
	t.Parallel()

	t.Run("top-level glob selectors", func(t *testing.T) {
		t.Parallel()

		cfg := minimalSelectionConfig()
		require.NoError(t, cfg.Port.UnmarshalText([]byte("8080,9090-9091")))
		cfg.AutoTargetExe = services.NewGlob("/srv/*")
		cfg.AutoTargetLanguage = services.NewGlob("{go,java}")

		_, ext := RuntimeToV2(&cfg)

		require.Equal(t, "exclude", value(t, ext.Capture.Policy, "default_action"))
		require.Len(t, ext.Capture.Rules, 1)
		require.Equal(t, "include", ext.Capture.Rules[0].Action)
		require.Equal(t, cfg.Port, value(t, ext.Capture.Rules[0].Match, "process", "open_ports"))
		require.Equal(t, []string{"/srv/*"}, value(t, ext.Capture.Rules[0].Match, "process", "exe_path_glob"))
		require.Equal(t, []string{"go", "java"}, value(t, ext.Capture.Rules[0].Match, "process", "language_glob"))
	})

	t.Run("target pids selector", func(t *testing.T) {
		t.Parallel()

		cfg := minimalSelectionConfig()
		require.NoError(t, cfg.TargetPIDs.UnmarshalText([]byte("1234,5678")))

		_, ext := RuntimeToV2(&cfg)

		require.Equal(t, "exclude", value(t, ext.Capture.Policy, "default_action"))
		require.Len(t, ext.Capture.Rules, 1)
		require.Equal(t, []uint32{1234, 5678}, value(t, ext.Capture.Rules[0].Match, "process", "target_pids"))
	})

	t.Run("deprecated regex selectors", func(t *testing.T) {
		t.Parallel()

		cfg := minimalSelectionConfig()
		require.NoError(t, cfg.Port.UnmarshalText([]byte("8080")))
		cfg.Exec = services.NewRegexp("^/srv/fallback$")
		cfg.Discovery.Services = services.RegexDefinitionCriteria{
			{
				Path:      services.NewRegexp("^/srv/api$"),
				Languages: services.NewRegexp("go|java"),
				CmdArgs:   services.NewRegexp("--serve"),
				Metadata: services.MetadataRegexMap{
					services.AttrNamespace:      regexPtr("^shop$"),
					services.AttrDeploymentName: regexPtr("^checkout-.+$"),
				},
				PodLabels: map[string]*services.RegexpAttr{
					"app": regexPtr("^checkout$"),
				},
				PodAnnotations: map[string]*services.RegexpAttr{
					"team": regexPtr("^payments$"),
				},
			},
		}
		cfg.Discovery.ExcludeServices = services.RegexDefinitionCriteria{
			{
				PathRegexp: services.NewRegexp("^/tmp/.*$"),
			},
		}

		_, ext := RuntimeToV2(&cfg)

		require.Equal(t, "exclude", value(t, ext.Capture.Policy, "default_action"))
		require.Len(t, ext.Capture.Rules, 3)
		require.Equal(t, "exclude", ext.Capture.Rules[0].Action)
		require.Equal(t, "^/tmp/.*$", value(t, ext.Capture.Rules[0].Match, "process", "exe_path_regex"))
		require.Equal(t, "include", ext.Capture.Rules[1].Action)
		require.Equal(t, "^/srv/api$", value(t, ext.Capture.Rules[1].Match, "process", "exe_path_regex"))
		require.Equal(t, "go|java", value(t, ext.Capture.Rules[1].Match, "process", "language_regex"))
		require.Equal(t, "--serve", value(t, ext.Capture.Rules[1].Match, "process", "cmd_args_regex"))
		require.Equal(t, "^shop$", value(t, ext.Capture.Rules[1].Match, "kubernetes", "namespace_regex"))
		require.Equal(t, "^checkout-.+$", value(t, ext.Capture.Rules[1].Match, "kubernetes", "metadata_regex", services.AttrDeploymentName))
		require.Equal(t, "^checkout$", value(t, ext.Capture.Rules[1].Match, "kubernetes", "pod_labels_regex", "app"))
		require.Equal(t, "^payments$", value(t, ext.Capture.Rules[1].Match, "kubernetes", "pod_annotations_regex", "team"))
		require.Equal(t, "include", ext.Capture.Rules[2].Action)
		require.Equal(t, cfg.Port, value(t, ext.Capture.Rules[2].Match, "process", "open_ports"))
		require.Equal(t, "^/srv/fallback$", value(t, ext.Capture.Rules[2].Match, "process", "exe_path_regex"))
	})
}

func TestRuntimeToV2MetricInstrumentationsUseEnabledExporters(t *testing.T) {
	t.Parallel()

	t.Run("ignores disabled exporter defaults", func(t *testing.T) {
		t.Parallel()

		cfg := defaultRuntimeConfig()
		cfg.OTELMetrics.MetricsEndpoint = "http://localhost:4318"
		cfg.OTELMetrics.Instrumentations = []instrumentations.Instrumentation{
			instrumentations.InstrumentationHTTP,
		}

		_, ext := RuntimeToV2(&cfg)

		require.Equal(t, true, value(t, ext.Capture.Instrumentation, "http", "enabled", "metrics"))
		require.Equal(t, false, value(t, ext.Capture.Instrumentation, "grpc", "enabled", "metrics"))
		require.Equal(t, false, value(t, ext.Capture.Instrumentation, "sql", "enabled", "metrics"))
		require.Equal(t, false, value(t, ext.Capture.Instrumentation, "redis", "enabled", "metrics"))
	})

	t.Run("unions enabled exporters", func(t *testing.T) {
		t.Parallel()

		cfg := defaultRuntimeConfig()
		cfg.OTELMetrics.MetricsEndpoint = "http://localhost:4318"
		cfg.OTELMetrics.Instrumentations = []instrumentations.Instrumentation{
			instrumentations.InstrumentationHTTP,
		}
		cfg.Prometheus.Port = 9090
		cfg.Prometheus.Instrumentations = []instrumentations.Instrumentation{
			instrumentations.InstrumentationRedis,
		}

		_, ext := RuntimeToV2(&cfg)

		require.Equal(t, true, value(t, ext.Capture.Instrumentation, "http", "enabled", "metrics"))
		require.Equal(t, true, value(t, ext.Capture.Instrumentation, "redis", "enabled", "metrics"))
		require.Equal(t, false, value(t, ext.Capture.Instrumentation, "grpc", "enabled", "metrics"))
	})
}

func TestRuntimeToV2StatsEnablementAndFeatures(t *testing.T) {
	t.Parallel()

	t.Run("preserves features even without enabled metrics endpoint", func(t *testing.T) {
		t.Parallel()

		cfg := defaultRuntimeConfig()
		cfg.Metrics.Features = export.FeatureStats

		_, ext := RuntimeToV2(&cfg)

		require.Equal(t, false, value(t, ext.Capture.Network, "stats", "enabled"))
		require.ElementsMatch(t, []string{
			"tcp_rtt",
			"tcp_failed_connections",
			"tcp_retransmits",
			"tcp_io",
		}, value(t, ext.Capture.Network, "stats", "features"))
	})

	t.Run("enables aggregate stats with metrics endpoint", func(t *testing.T) {
		t.Parallel()

		cfg := defaultRuntimeConfig()
		cfg.Prometheus.Port = 9090
		cfg.Metrics.Features = export.FeatureStats

		_, ext := RuntimeToV2(&cfg)

		require.Equal(t, true, value(t, ext.Capture.Network, "stats", "enabled"))
		require.ElementsMatch(t, []string{
			"tcp_rtt",
			"tcp_failed_connections",
			"tcp_retransmits",
			"tcp_io",
		}, value(t, ext.Capture.Network, "stats", "features"))
	})

	t.Run("preserves individual stat families", func(t *testing.T) {
		t.Parallel()

		cfg := defaultRuntimeConfig()
		cfg.OTELMetrics.MetricsEndpoint = "http://localhost:4318"
		cfg.Metrics.Features = export.FeatureStatsTCPRtt | export.FeatureStatsTCPRetransmits

		_, ext := RuntimeToV2(&cfg)

		require.Equal(t, true, value(t, ext.Capture.Network, "stats", "enabled"))
		require.ElementsMatch(t, []string{"tcp_rtt", "tcp_retransmits"}, value(t, ext.Capture.Network, "stats", "features"))
	})
}

func TestRuntimeToV2DocumentParsesAsStandaloneV2(t *testing.T) {
	t.Parallel()

	doc, _ := RuntimeToV2(nil)

	data, err := yaml.Marshal(doc)
	require.NoError(t, err)
	require.NotContains(t, string(data), "tracer_provider: null")
	require.NotContains(t, string(data), "meter_provider: null")
	require.NotContains(t, string(data), "rules: null")
	require.NotContains(t, string(data), "telemetry: null")
	require.NotContains(t, string(data), "refine: {}")

	parsedDoc, parsedExt, err := schema.ParseStandaloneYAML(data)
	require.NoError(t, err)
	require.NotNil(t, parsedDoc.TracerProvider)
	require.NotNil(t, parsedDoc.MeterProvider)
	require.NotNil(t, parsedExt.Capture.Rules)
	require.NotNil(t, parsedExt.Capture.Telemetry)
	require.Equal(t, "1.0", parsedDoc.FileFormat)
	require.Equal(t, schema.SupportedVersion, parsedExt.Version)
	require.Equal(t, "include", parsedExt.Capture.Policy["default_action"])
	require.Equal(t, "auto", value(t, parsedExt.Capture.Engine, "traffic", "control_backend"))
}

func value(t *testing.T, root any, path ...string) any {
	t.Helper()

	cur := root
	for _, key := range path {
		if items, ok := cur.([]any); ok {
			idx, err := strconv.Atoi(key)
			require.NoErrorf(t, err, "expected slice index at %q in %v", key, path)
			require.GreaterOrEqualf(t, idx, 0, "slice index %q out of range in %v", key, path)
			require.Lessf(t, idx, len(items), "slice index %q out of range in %v", key, path)
			cur = items[idx]
			continue
		}

		m, ok := cur.(map[string]any)
		require.Truef(t, ok, "expected map at %q in %v", key, path)
		cur, ok = m[key]
		require.Truef(t, ok, "missing key %q in %v", key, path)
	}
	return cur
}

func globPtr(pattern string) *services.GlobAttr {
	glob := services.NewGlob(pattern)
	return &glob
}

func regexPtr(pattern string) *services.RegexpAttr {
	regex := services.NewRegexp(pattern)
	return &regex
}

func minimalSelectionConfig() obi.Config {
	cfg := defaultRuntimeConfig()
	cfg.Discovery.DefaultExcludeInstrument = nil
	cfg.Discovery.DefaultExcludeServices = nil
	cfg.Discovery.ExcludeOTelInstrumentedServices = false
	cfg.Discovery.ExcludedLinuxSystemPaths = nil
	return cfg
}

func defaultRuntimeConfig() obi.Config {
	cfg := obi.DefaultConfig
	if cfg.Routes != nil {
		routes := *cfg.Routes
		cfg.Routes = &routes
	}
	return cfg
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}
