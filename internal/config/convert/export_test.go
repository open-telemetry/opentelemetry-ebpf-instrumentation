// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
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
	require.Nil(t, ext.Enrich)
	require.Nil(t, ext.Correlation)
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
	require.Equal(t, "/sys/fs/bpf/", value(t, ext.Capture.Engine, "bpf_filesystem", "path"))

	require.Equal(t, 50, value(t, ext.Capture.Channels, "buffer_len"))
	require.Equal(t, "1m0s", value(t, ext.Capture.Channels, "send_timeout"))
	require.Equal(t, false, value(t, ext.Capture.Safety, "enforce_system_capabilities"))
	require.Equal(t, 100, value(t, ext.Capture.Limits, "metric_span_names"))

	require.Equal(t, false, value(t, ext.Capture.Network, "capture", "enabled"))
	require.Equal(t, obi.EbpfSourceSock, value(t, ext.Capture.Network, "capture", "source"))
	require.Equal(t, []string{"lo"}, value(t, ext.Capture.Network, "capture", "selection", "interfaces", "exclude"))
	require.Equal(t, "both", value(t, ext.Capture.Network, "capture", "selection", "direction"))

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
}

func TestRuntimeToV2CustomConfig(t *testing.T) {
	t.Parallel()

	cfg := obi.DefaultConfig
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
	require.NotContains(t, value(t, ext.Capture.Instrumentation, "sql"), "mssql")
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

func TestRuntimeToV2MetricInstrumentationsUseEnabledExporters(t *testing.T) {
	t.Parallel()

	t.Run("ignores disabled exporter defaults", func(t *testing.T) {
		t.Parallel()

		cfg := obi.DefaultConfig
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

		cfg := obi.DefaultConfig
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

func TestRuntimeToV2DocumentParsesAsStandaloneV2(t *testing.T) {
	t.Parallel()

	doc, _ := RuntimeToV2(nil)

	data, err := yaml.Marshal(doc)
	require.NoError(t, err)
	require.NotContains(t, string(data), "tracer_provider: null")
	require.NotContains(t, string(data), "meter_provider: null")
	require.NotContains(t, string(data), "rules: null")
	require.NotContains(t, string(data), "telemetry: null")

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
		m, ok := cur.(map[string]any)
		require.Truef(t, ok, "expected map at %q in %v", key, path)
		cur, ok = m[key]
		require.Truef(t, ok, "missing key %q in %v", key, path)
	}
	return cur
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}
