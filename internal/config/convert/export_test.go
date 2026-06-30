// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
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

	require.Empty(t, doc.Resource.Attributes)
	require.Equal(t, int((15 * time.Second).Milliseconds()), value(t, doc.TracerProvider, "processors", "0", "batch", "schedule_delay"))
	require.Equal(t, 16384, value(t, doc.TracerProvider, "processors", "0", "batch", "max_queue_size"))
	require.Equal(t, 4096, value(t, doc.TracerProvider, "processors", "0", "batch", "max_export_batch_size"))
	require.Empty(t, value(t, doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc", "endpoint"))
	require.Equal(t, false, value(t, doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc", "tls", "insecure"))
	require.Nil(t, doc.TracerProvider.Sampler)
	require.Equal(t, int(time.Minute.Milliseconds()), value(t, doc.MeterProvider, "readers", "0", "periodic", "interval"))
	require.Empty(t, value(t, doc.MeterProvider, "readers", "0", "periodic", "exporter", "otlp_grpc", "endpoint"))
	require.Equal(t, false, value(t, doc.MeterProvider, "readers", "0", "periodic", "exporter", "otlp_grpc", "tls", "insecure"))
	require.Equal(t, 0, value(t, doc.MeterProvider, "readers", "1", "pull", "exporter", "prometheus/development", "port"))

	require.Equal(t, schema.CaptureActionInclude, value(t, ext.Capture.Policy, "default_action"))
	require.Equal(t, schema.MatchOrderFirstMatchWins, value(t, ext.Capture.Policy, "match_order"))
	require.Equal(t, schema.Duration(0), value(t, ext.Capture.Policy, "poll_interval"))
	require.Equal(t, schema.Duration(5*time.Second), value(t, ext.Capture.Policy, "min_process_age"))

	require.Equal(t, 500, value(t, ext.Capture.Engine, "batching", "wakeup_len"))
	require.Equal(t, 100, value(t, ext.Capture.Engine, "batching", "batch_length"))
	require.Equal(t, schema.Duration(time.Second), value(t, ext.Capture.Engine, "batching", "batch_timeout"))
	require.Equal(t, config.TCBackendAuto, value(t, ext.Capture.Engine, "traffic", "control_backend"))
	require.Equal(t, config.MapReaderAuto, value(t, ext.Capture.Engine, "traffic", "force_map_reader"))
	require.Equal(t, 0, value(t, ext.Capture.Engine, "maps", "global_scale_factor"))
	require.Equal(t, "/sys/fs/bpf/", value(t, ext.Capture.Engine, "bpf_filesystem", "path"))

	require.Equal(t, 50, value(t, ext.Capture.Channels, "buffer_len"))
	require.Equal(t, schema.Duration(time.Minute), value(t, ext.Capture.Channels, "send_timeout"))
	require.Equal(t, false, value(t, ext.Capture.Safety, "enforce_system_capabilities"))
	require.Equal(t, 100, value(t, ext.Capture.Limits, "metric_span_names"))

	require.Equal(t, false, value(t, ext.Capture.Network, "capture", "enabled"))
	require.Equal(t, schema.NetworkSourceSocketFilter, value(t, ext.Capture.Network, "capture", "source"))
	require.Equal(t, []string{"lo"}, value(t, ext.Capture.Network, "capture", "selection", "interfaces", "exclude"))
	require.Equal(t, schema.NetworkDirectionBoth, value(t, ext.Capture.Network, "capture", "selection", "direction"))
	require.Equal(t, false, value(t, ext.Capture.Network, "stats", "enabled"))
	require.Empty(t, value(t, ext.Capture.Network, "stats", "features"))

	require.Equal(t, true, value(t, ext.Capture.Instrumentation, "http", "enabled", "traces"))
	require.Equal(t, true, value(t, ext.Capture.Instrumentation, "http", "enabled", "metrics"))
	require.Equal(t, false, value(t, ext.Capture.Instrumentation, "dns", "enabled", "traces"))
	require.Equal(t, false, value(t, ext.Capture.Instrumentation, "dns", "enabled", "metrics"))
	require.ElementsMatch(t, []string{
		string(protocolHTTP),
		string(protocolGRPC),
		string(protocolSQL),
		string(protocolRedis),
		string(protocolKafka),
		string(protocolMongo),
		string(protocolCouchbase),
		string(protocolDNS),
		string(protocolGPU),
	}, keys(ext.Capture.Instrumentation))

	require.Equal(t, true, value(t, ext.Capture.Runtimes, "go", "enabled"))
	require.Equal(t, true, value(t, ext.Capture.Runtimes, "nodejs", "enabled"))
	require.Equal(t, true, value(t, ext.Capture.Runtimes, "java", "enabled"))

	require.Equal(t, 256, value(t, ext.Capture.Telemetry, "traces", "reporters_cache_len"))
	require.Equal(t, 256, value(t, ext.Capture.Telemetry, "metrics", "reporters_cache_len"))
	require.Equal(t, schema.Duration(5*time.Minute), value(t, ext.Capture.Telemetry, "metrics", "ttl"))

	require.Equal(t, schema.KubernetesModeAutodetect, value(t, ext.Enrich, "enrichers", "kubernetes", "mode"))
	require.Equal(t, schema.Duration(30*time.Second), value(t, ext.Enrich, "enrichers", "kubernetes", "informers", "initial_sync_timeout"))
	require.Equal(t, schema.Duration(30*time.Minute), value(t, ext.Enrich, "enrichers", "kubernetes", "informers", "resync_period"))
	require.Equal(t, []transform.Source{transform.SourceK8s}, value(t, ext.Enrich, "service_name", "sources"))
	require.Equal(t, 1024, value(t, ext.Enrich, "service_name", "cache", "size"))
	require.Equal(t, schema.Duration(5*time.Minute), value(t, ext.Enrich, "service_name", "cache", "ttl"))
	require.Equal(t, "unresolved", value(t, ext.Enrich, "service_name", "unresolved_hosts", "names", "default"))

	require.Equal(t, false, value(t, ext.Correlation, "log_trace_annotation", "enabled"))
	require.Equal(t, schema.Duration(30*time.Minute), value(t, ext.Correlation, "log_trace_annotation", "cache", "ttl"))
	require.Equal(t, 128, value(t, ext.Correlation, "log_trace_annotation", "cache", "size"))
	require.Equal(t, 8, value(t, ext.Correlation, "log_trace_annotation", "async_writer", "workers"))

	require.Equal(t, schema.LogLevelInfo, value(t, ext.Daemon, "logging", "level"))
	require.Equal(t, schema.LogFormatText, value(t, ext.Daemon, "logging", "format"))
	require.Equal(t, schema.ConfigFormatUnset, value(t, ext.Daemon, "logging", "config_format"))
	require.Equal(t, debug.TracePrinterDisabled, value(t, ext.Daemon, "logging", "debug_trace_output"))
	require.Equal(t, schema.Duration(10*time.Second), value(t, ext.Daemon, "shutdown", "timeout"))
	require.Equal(t, imetrics.InternalMetricsExporterDisabled, value(t, ext.Daemon, "internal_metrics", "exporter"))
	require.Equal(t, "/internal/metrics", value(t, ext.Daemon, "internal_metrics", "prometheus", "path"))
	require.Equal(t, false, value(t, ext.Daemon, "telemetry", "metrics", "prometheus", "allow_service_graph_self_references"))
	require.Equal(t, 10000, value(t, ext.Daemon, "telemetry", "metrics", "prometheus", "span_metrics_service_cache_size"))

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

	routes, ok := value(t, ext.Capture.Instrumentation, "http", "routes").(schema.HTTPRoutes)
	require.True(t, ok)
	require.Equal(t, schema.Duration(10*time.Second), routes.Discovery.Timeout)
	for _, key := range []string{
		"unmatched",
		"patterns",
		"ignored_patterns",
		"ignore_mode",
		"wildcard_char",
		"max_path_segment_cardinality",
	} {
		require.Nil(t, value(t, routes, key))
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
	cfg.LogFormat = obi.LogFormatJSON
	cfg.LogConfig = obi.LogConfigOptionYAML
	cfg.TracePrinter = debug.TracePrinterJSON
	cfg.ShutdownTimeout = 3 * time.Second
	cfg.ProfilePort = 6060
	cfg.InternalMetrics.Exporter = imetrics.InternalMetricsExporterPrometheus
	cfg.InternalMetrics.Prometheus.Port = 9090
	cfg.InternalMetrics.Prometheus.Path = "/debug/metrics"
	cfg.InternalMetrics.BpfMetricScrapeInterval = 4 * time.Second

	cfg.Attributes.InstanceID.OverrideHostname = "host-override"
	cfg.Attributes.HostID.Override = "host-id-1"
	cfg.Attributes.Kubernetes.Enable = "true"
	cfg.Attributes.Kubernetes.ClusterName = "cluster-a"
	cfg.Attributes.Kubernetes.KubeconfigPath = "/etc/kube/config"
	cfg.Attributes.Kubernetes.InformersSyncTimeout = 42 * time.Second
	cfg.Attributes.Kubernetes.ReconnectInitialInterval = 43 * time.Second
	cfg.Attributes.Kubernetes.InformersResyncPeriod = 44 * time.Second
	cfg.Attributes.Kubernetes.DropExternal = true
	cfg.Attributes.Kubernetes.DisableInformers = []string{"node", "service"}
	cfg.Attributes.Kubernetes.MetaCacheAddress = "kube-cache:8999"
	cfg.Attributes.Kubernetes.MetaRestrictLocalNode = true
	cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceName = "app.kubernetes.io/name"
	cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceNamespace = "app.kubernetes.io/part-of"
	cfg.Attributes.Kubernetes.ResourceLabels = map[string][]string{
		"service.name":    {"app"},
		"service.version": {"version"},
	}
	cfg.Attributes.Kubernetes.ServiceNameTemplate = "{{ .Meta.Name }}"
	cfg.Attributes.RenameUnresolvedHosts = "unknown"
	cfg.Attributes.RenameUnresolvedHostsOutgoing = "unknown-out"
	cfg.Attributes.RenameUnresolvedHostsIncoming = "unknown-in"
	cfg.Attributes.MetadataRetry.Timeout = 45 * time.Second
	cfg.Attributes.MetadataRetry.StartInterval = 46 * time.Millisecond
	cfg.Attributes.MetadataRetry.MaxInterval = 47 * time.Second
	cfg.Attributes.Select = attributes.Selection{
		"traces": attributes.InclusionLists{
			Include: []string{"http.route"},
		},
	}
	cfg.Attributes.ExtraGroupAttributes = obi.ExtraGroupAttributesMap{
		"k8s_app_meta": []attr.Name{attr.K8sPodName},
	}
	cfg.NameResolver.Sources = []transform.Source{transform.SourceDNS, transform.SourceK8s}
	cfg.NameResolver.CacheLen = 901
	cfg.NameResolver.CacheTTL = 902 * time.Second

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
	cfg.EBPF.LogEnricher.Services = []config.LogEnricherServiceConfig{
		{
			Service: services.GlobDefinitionCriteria{
				{Path: services.NewGlob("/srv/*")},
			},
		},
	}
	cfg.EBPF.LogEnricher.CacheTTL = 903 * time.Second
	cfg.EBPF.LogEnricher.CacheSize = 904
	cfg.EBPF.LogEnricher.AsyncWriterWorkers = 905
	cfg.EBPF.LogEnricher.AsyncWriterChannelLen = 906

	cfg.Traces.TracesEndpoint = "http://traces.example:4317"
	cfg.Traces.BatchMaxSize = 907
	cfg.Traces.QueueSize = 908
	cfg.Traces.BatchTimeout = 909 * time.Millisecond
	cfg.Traces.BackOffInitialInterval = 910 * time.Millisecond
	cfg.Traces.BackOffMaxInterval = 911 * time.Second
	cfg.Traces.BackOffMaxElapsedTime = 912 * time.Second
	cfg.Traces.InsecureSkipVerify = true
	cfg.Traces.ReportersCacheLen = 913
	cfg.Traces.SamplerConfig.Name = services.SamplerTraceIDRatio
	cfg.Traces.SamplerConfig.Arg = "0.25"
	cfg.Traces.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationHTTP,
		instrumentations.InstrumentationKafka,
	}
	cfg.OTELMetrics.MetricsEndpoint = "https://metrics.example:4317"
	cfg.OTELMetrics.Interval = 914 * time.Millisecond
	cfg.OTELMetrics.ReportersCacheLen = 915
	cfg.OTELMetrics.TTL = 916 * time.Second
	cfg.OTELMetrics.InsecureSkipVerify = true
	cfg.OTELMetrics.ExtraSpanResourceLabels = []string{"deployment.environment", "service.version"}
	cfg.OTELMetrics.Instrumentations = []instrumentations.Instrumentation{
		instrumentations.InstrumentationHTTP,
	}
	cfg.Prometheus.Port = 917
	cfg.Prometheus.AllowServiceGraphSelfReferences = true
	cfg.Prometheus.SpanMetricsServiceCacheSize = 918
	cfg.Prometheus.ExtraResourceLabels = []string{"cloud.region"}
	cfg.Prometheus.ExtraSpanResourceLabels = []string{"service.version", "k8s.cluster.name"}
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

	doc, ext := RuntimeToV2(&cfg)

	require.Equal(t, "host.name", value(t, doc.Resource, "attributes", "0", "name"))
	require.Equal(t, "host-override", value(t, doc.Resource, "attributes", "0", "value"))
	require.Equal(t, "host.id", value(t, doc.Resource, "attributes", "1", "name"))
	require.Equal(t, "host-id-1", value(t, doc.Resource, "attributes", "1", "value"))
	require.Equal(t, 908, value(t, doc.TracerProvider, "processors", "0", "batch", "max_queue_size"))
	require.Equal(t, 907, value(t, doc.TracerProvider, "processors", "0", "batch", "max_export_batch_size"))
	require.Equal(t, int((909 * time.Millisecond).Milliseconds()), value(t, doc.TracerProvider, "processors", "0", "batch", "schedule_delay"))
	require.Equal(t, "http://traces.example:4317", value(t, doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc", "endpoint"))
	require.Equal(t, true, value(t, doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc", "tls", "insecure"))
	require.InEpsilon(t, 0.25, value(t, doc.TracerProvider, "sampler", "trace_id_ratio_based", "ratio"), 0.000001)
	require.Equal(t, int((914 * time.Millisecond).Milliseconds()), value(t, doc.MeterProvider, "readers", "0", "periodic", "interval"))
	require.Equal(t, "https://metrics.example:4317", value(t, doc.MeterProvider, "readers", "0", "periodic", "exporter", "otlp_grpc", "endpoint"))
	require.Equal(t, false, value(t, doc.MeterProvider, "readers", "0", "periodic", "exporter", "otlp_grpc", "tls", "insecure"))
	require.Equal(t, 917, value(t, doc.MeterProvider, "readers", "1", "pull", "exporter", "prometheus/development", "port"))

	require.Equal(t, 77, value(t, ext.Capture.Channels, "buffer_len"))
	require.Equal(t, schema.Duration(2*time.Second), value(t, ext.Capture.Channels, "send_timeout"))
	require.Equal(t, true, value(t, ext.Capture.Channels, "panic_on_send_timeout"))
	require.Equal(t, true, value(t, ext.Capture.Safety, "enforce_system_capabilities"))
	require.Equal(t, 400, value(t, ext.Capture.Limits, "metric_span_names"))

	require.Equal(t, schema.Duration(5*time.Second), value(t, ext.Capture.Policy, "poll_interval"))
	require.Equal(t, schema.Duration(6*time.Second), value(t, ext.Capture.Policy, "min_process_age"))
	require.Equal(t, true, value(t, ext.Capture.Engine, "pid_filter", "disabled"))
	require.Equal(t, 8, value(t, ext.Capture.Engine, "batching", "wakeup_len"))
	require.Equal(t, 9, value(t, ext.Capture.Engine, "batching", "batch_length"))
	require.Equal(t, schema.Duration(10*time.Second), value(t, ext.Capture.Engine, "batching", "batch_timeout"))
	require.Equal(t, config.ContextPropagationAll, value(t, ext.Capture.Engine, "propagation", "context_propagation"))
	require.Equal(t, config.TCBackendTCX, value(t, ext.Capture.Engine, "traffic", "control_backend"))
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
	require.Equal(t, config.CudaModeOn, value(t, ext.Capture.Instrumentation, "gpu", "enabled_mode"))

	require.Equal(t, false, value(t, ext.Capture.Runtimes, "go", "enabled"))
	require.Equal(t, false, value(t, ext.Capture.Runtimes, "nodejs", "enabled"))
	require.Equal(t, false, value(t, ext.Capture.Runtimes, "java", "enabled"))
	require.Equal(t, true, value(t, ext.Capture.Runtimes, "java", "debug", "bytecode_instrumentation"))
	require.Equal(t, schema.Duration(7*time.Second), value(t, ext.Capture.Runtimes, "java", "attach_timeout"))
	require.Equal(t, 913, value(t, ext.Capture.Telemetry, "traces", "reporters_cache_len"))
	require.Equal(t, 915, value(t, ext.Capture.Telemetry, "metrics", "reporters_cache_len"))
	require.Equal(t, schema.Duration(916*time.Second), value(t, ext.Capture.Telemetry, "metrics", "ttl"))

	require.Equal(t, true, value(t, ext.Capture.Network, "capture", "enabled"))
	require.Equal(t, schema.NetworkSourceTC, value(t, ext.Capture.Network, "capture", "source"))
	require.Equal(t, uint32(105), value(t, ext.Capture.Network, "capture", "buffer_size"))
	require.Equal(t, "192.0.2.1", value(t, ext.Capture.Network, "capture", "endpoint_identity", "agent_ip"))
	require.Equal(t, schema.AgentIPInterfaceLocal, value(t, ext.Capture.Network, "capture", "endpoint_identity", "agent_ip_interface"))
	require.Equal(t, []string{"eth0"}, value(t, ext.Capture.Network, "capture", "selection", "interfaces", "include"))
	require.Equal(t, []string{"udp"}, value(t, ext.Capture.Network, "capture", "selection", "protocols", "exclude"))
	require.Equal(t, schema.NetworkDirectionEgress, value(t, ext.Capture.Network, "capture", "selection", "direction"))
	require.Equal(t, 300, value(t, ext.Capture.Network, "capture", "flow_lifecycle", "max_tracked_flows"))
	require.Equal(t, schema.DeduplicationStrategyNone, value(t, ext.Capture.Network, "capture", "flow_lifecycle", "deduplication", "strategy"))
	require.Equal(t, schema.Duration(15*time.Second), value(t, ext.Capture.Network, "capture", "flow_lifecycle", "deduplication", "first_come_ttl"))
	require.Equal(t, true, value(t, ext.Capture.Network, "capture", "diagnostics", "print_flows"))

	require.Equal(t, schema.KubernetesModeEnabled, value(t, ext.Enrich, "enrichers", "kubernetes", "mode"))
	require.Equal(t, "cluster-a", value(t, ext.Enrich, "enrichers", "kubernetes", "cluster_name"))
	require.Equal(t, "/etc/kube/config", value(t, ext.Enrich, "enrichers", "kubernetes", "auth", "kubeconfig_path"))
	require.Equal(t, schema.Duration(42*time.Second), value(t, ext.Enrich, "enrichers", "kubernetes", "informers", "initial_sync_timeout"))
	require.Equal(t, schema.Duration(43*time.Second), value(t, ext.Enrich, "enrichers", "kubernetes", "informers", "reconnect_initial_interval"))
	require.Equal(t, schema.Duration(44*time.Second), value(t, ext.Enrich, "enrichers", "kubernetes", "informers", "resync_period"))
	require.Equal(t, []string{"node", "service"}, value(t, ext.Enrich, "enrichers", "kubernetes", "informers", "disabled"))
	require.Equal(t, true, value(t, ext.Enrich, "enrichers", "kubernetes", "drop_external"))
	require.Equal(t, schema.ResourceLabels(cfg.Attributes.Kubernetes.ResourceLabels), value(t, ext.Enrich, "enrichers", "kubernetes", "resource_labels"))
	require.Equal(t, "kube-cache:8999", value(t, ext.Enrich, "enrichers", "kubernetes", "metadata_cache", "address"))
	require.Equal(t, true, value(t, ext.Enrich, "enrichers", "kubernetes", "metadata_cache", "restrict_local_node"))
	require.Equal(t, "app.kubernetes.io/name", value(t, ext.Enrich, "enrichers", "kubernetes", "metadata_cache", "source_labels", "service_name"))
	require.Equal(t, "{{ .Meta.Name }}", value(t, ext.Enrich, "enrichers", "kubernetes", "service_name_template"))
	require.Equal(t, []transform.Source{transform.SourceDNS, transform.SourceK8s}, value(t, ext.Enrich, "service_name", "sources"))
	require.Equal(t, 901, value(t, ext.Enrich, "service_name", "cache", "size"))
	require.Equal(t, schema.Duration(902*time.Second), value(t, ext.Enrich, "service_name", "cache", "ttl"))
	require.Equal(t, "unknown-out", value(t, ext.Enrich, "service_name", "unresolved_hosts", "names", "outgoing"))
	require.Equal(t, cfg.Attributes.Select, value(t, ext.Enrich, "attributes", "select"))
	require.Equal(t, schema.ExtraGroupAttributes(cfg.Attributes.ExtraGroupAttributes), value(t, ext.Enrich, "attributes", "extra_group_attributes"))
	require.Equal(t, schema.Duration(45*time.Second), value(t, ext.Enrich, "attributes", "metadata_retry", "timeout"))
	require.Equal(t, schema.Duration(46*time.Millisecond), value(t, ext.Enrich, "attributes", "metadata_retry", "start_interval"))
	require.Equal(t, schema.Duration(47*time.Second), value(t, ext.Enrich, "attributes", "metadata_retry", "max_interval"))

	require.Equal(t, true, value(t, ext.Correlation, "log_trace_annotation", "enabled"))
	require.Equal(t, schema.Duration(903*time.Second), value(t, ext.Correlation, "log_trace_annotation", "cache", "ttl"))
	require.Equal(t, 904, value(t, ext.Correlation, "log_trace_annotation", "cache", "size"))
	require.Equal(t, 905, value(t, ext.Correlation, "log_trace_annotation", "async_writer", "workers"))
	require.Equal(t, 906, value(t, ext.Correlation, "log_trace_annotation", "async_writer", "channel_len"))

	require.Equal(t, schema.LogLevelDebug, value(t, ext.Daemon, "logging", "level"))
	require.Equal(t, schema.LogFormatJSON, value(t, ext.Daemon, "logging", "format"))
	require.Equal(t, schema.ConfigFormatYAML, value(t, ext.Daemon, "logging", "config_format"))
	require.Equal(t, debug.TracePrinterJSON, value(t, ext.Daemon, "logging", "debug_trace_output"))
	require.Equal(t, 6060, value(t, ext.Daemon, "profiling", "port"))
	require.Equal(t, schema.Duration(3*time.Second), value(t, ext.Daemon, "shutdown", "timeout"))
	require.Equal(t, imetrics.InternalMetricsExporterPrometheus, value(t, ext.Daemon, "internal_metrics", "exporter"))
	require.Equal(t, 9090, value(t, ext.Daemon, "internal_metrics", "prometheus", "port"))
	require.Equal(t, schema.Duration(4*time.Second), value(t, ext.Daemon, "internal_metrics", "bpf", "scrape_interval"))
	require.Equal(t, true, value(t, ext.Daemon, "telemetry", "metrics", "prometheus", "allow_service_graph_self_references"))
	require.Equal(t, 918, value(t, ext.Daemon, "telemetry", "metrics", "prometheus", "span_metrics_service_cache_size"))
	require.Equal(t, []string{"cloud.region"}, value(t, ext.Daemon, "telemetry", "metrics", "prometheus", "extra_resource_attributes"))
	require.Equal(t, []string{"service.version", "k8s.cluster.name", "deployment.environment"}, value(t, ext.Daemon, "telemetry", "metrics", "prometheus", "extra_span_resource_attributes"))
}

func TestRuntimeToV2NormalizesLogFormat(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.LogFormat = obi.LogFormat("JSON")

	_, ext := RuntimeToV2(&cfg)

	require.Equal(t, schema.LogFormatJSON, value(t, ext.Daemon, "logging", "format"))
}

func TestRuntimeToV2FallsBackOnUnsupportedLogFormats(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.LogFormat = obi.LogFormat("console")
	cfg.LogConfig = obi.LogConfigOption("text")

	_, ext := RuntimeToV2(&cfg)

	require.Equal(t, schema.LogFormatText, value(t, ext.Daemon, "logging", "format"))
	require.Equal(t, schema.ConfigFormatUnset, value(t, ext.Daemon, "logging", "config_format"))
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

	require.Equal(t, schema.CaptureActionExclude, value(t, ext.Capture.Policy, "default_action"))
	require.Equal(t, cfg.Routes.Unmatch, value(t, ext.Capture.Instrumentation, "http", "routes", "unmatched"))
	require.Equal(t, []string{"/products/{id}"}, value(t, ext.Capture.Instrumentation, "http", "routes", "patterns"))
	require.Equal(t, []string{"/health"}, value(t, ext.Capture.Instrumentation, "http", "routes", "ignored_patterns"))
	require.Equal(t, cfg.Routes.IgnoredEvents, value(t, ext.Capture.Instrumentation, "http", "routes", "ignore_mode"))
	require.Equal(t, "#", value(t, ext.Capture.Instrumentation, "http", "routes", "wildcard_char"))
	require.Equal(t, 22, value(t, ext.Capture.Instrumentation, "http", "routes", "max_path_segment_cardinality"))
	require.Equal(t, schema.Duration(23*time.Second), value(t, ext.Capture.Instrumentation, "http", "routes", "discovery", "timeout"))
	require.Equal(t, []services.RouteHarvesterLanguage{services.RouteHarvesterLanguageJava}, value(t, ext.Capture.Instrumentation, "http", "routes", "discovery", "disabled_languages"))
	require.Equal(t, schema.Duration(24*time.Second), value(t, ext.Capture.Instrumentation, "http", "routes", "discovery", "java", "delay"))

	statusCode := 500
	require.Equal(t, schema.AttributeFilter{Equals: &statusCode}, value(t, ext.Capture.Instrumentation, "http", "filters", "traces", "http.status_code"))
	require.Equal(t, schema.AttributeFilter{Match: "checkout-*"}, value(t, ext.Capture.Instrumentation, "kafka", "filters", "metrics", "service.name"))
	require.Equal(t, schema.AttributeFilter{NotMatch: "10.*"}, value(t, ext.Capture.Network, "capture", "filters", "traces", "src.address"))
	srtt := 1024
	require.Equal(t, schema.AttributeFilter{GreaterThan: &srtt}, value(t, ext.Capture.Network, "stats", "filters", "metrics", "srtt"))

	require.ElementsMatch(t, []string{
		"graphql", "elasticsearch", "aws", "sqlpp", "openai", "anthropic", "gemini",
		"qwen", "bedrock", "mcp", "embedding", "rerank", "retrieval", "jsonrpc", "enrichment",
	}, value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "enabled"))
	require.Equal(t, []string{"/query", "/analytics"}, value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "sqlpp", "endpoint_patterns"))
	require.Equal(t, config.HTTPParsingActionInclude, value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "enrichment", "policy", "default_action", "headers"))
	require.Equal(t, config.HTTPParsingActionObfuscate, value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "enrichment", "policy", "default_action", "body"))
	require.Equal(t, "[redacted]", value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "enrichment", "policy", "obfuscation_string"))
	require.Equal(t, cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Rules, value(t, ext.Capture.Instrumentation, "http", "payload_extraction", "enrichment", "rules"))

	require.Equal(t, schema.CIDRDefinitions{{CIDR: "10.0.0.0/8", Name: "private"}}, value(t, ext.Capture.Network, "capture", "selection", "cidrs"))
	require.Equal(t, cfg.NetworkFlows.GuessPorts, value(t, ext.Capture.Network, "capture", "flow_lifecycle", "guess_ports"))
	require.Equal(t, "/var/lib/ipinfo.mmdb", value(t, ext.Capture.Network, "capture", "enrichment", "geo_ip", "ipinfo", "path"))
	require.Equal(t, "/var/lib/country.mmdb", value(t, ext.Capture.Network, "capture", "enrichment", "geo_ip", "maxmind", "country_path"))
	require.Equal(t, "/var/lib/asn.mmdb", value(t, ext.Capture.Network, "capture", "enrichment", "geo_ip", "maxmind", "asn_path"))
	require.Equal(t, 77, value(t, ext.Capture.Network, "capture", "enrichment", "geo_ip", "cache", "size"))
	require.Equal(t, schema.Duration(78*time.Second), value(t, ext.Capture.Network, "capture", "enrichment", "geo_ip", "cache", "ttl"))
	require.Equal(t, schema.ReverseDNSModeLocal, value(t, ext.Capture.Network, "capture", "enrichment", "reverse_dns", "mode"))
	require.Equal(t, 79, value(t, ext.Capture.Network, "capture", "enrichment", "reverse_dns", "cache", "size"))

	require.Equal(t, "198.51.100.1", value(t, ext.Capture.Network, "stats", "endpoint_identity", "agent_ip"))
	require.Equal(t, schema.CIDRDefinitions{{CIDR: "192.0.2.0/24", Name: "docs"}}, value(t, ext.Capture.Network, "stats", "selection", "cidrs"))
	require.Equal(t, "/var/lib/stats-ipinfo.mmdb", value(t, ext.Capture.Network, "stats", "enrichment", "geo_ip", "ipinfo", "path"))
	require.Equal(t, schema.ReverseDNSModeEBPF, value(t, ext.Capture.Network, "stats", "enrichment", "reverse_dns", "mode"))
	require.Equal(t, true, value(t, ext.Capture.Network, "stats", "diagnostics", "print_stats"))

	require.Len(t, ext.Capture.Rules, 4)
	require.Equal(t, schema.CaptureActionExclude, ext.Capture.Rules[0].Action)
	require.Equal(t, []string{"/tmp/*"}, value(t, ext.Capture.Rules[0].Match, "process", "exe_path_glob"))
	require.Equal(t, 14317, value(t, ext.Capture.Rules[1].Match, "process", "exports_otlp", "port"))
	require.Equal(t, []string{"/lib/systemd/*", "/usr/sbin/*"}, value(t, ext.Capture.Rules[2].Match, "process", "exe_path_glob"))
	require.Equal(t, schema.CaptureActionInclude, ext.Capture.Rules[3].Action)
	require.Equal(t, ports, value(t, ext.Capture.Rules[3].Match, "process", "open_ports"))
	require.Equal(t, []uint32{1234, 5678}, value(t, ext.Capture.Rules[3].Match, "process", "target_pids"))
	require.Equal(t, []string{"go", "java"}, value(t, ext.Capture.Rules[3].Match, "process", "language_glob"))
	require.Equal(t, true, value(t, ext.Capture.Rules[3].Match, "process", "containers_only"))
	require.Equal(t, []string{"shop-*"}, value(t, ext.Capture.Rules[3].Match, "kubernetes", "namespace_glob"))
	require.Equal(t, []string{"checkout-*"}, value(t, ext.Capture.Rules[3].Match, "kubernetes", "metadata_glob", services.AttrDeploymentName))
	require.Equal(t, []string{"checkout"}, value(t, ext.Capture.Rules[3].Match, "kubernetes", "pod_labels", "app"))
	require.Equal(t, []string{"payments"}, value(t, ext.Capture.Rules[3].Match, "kubernetes", "pod_annotations", "team"))
	require.NotNil(t, ext.Capture.Rules[3].Refine.Exports)
	require.Equal(t, schema.ExportModeRefinement{Traces: false, Metrics: true}, *ext.Capture.Rules[3].Refine.Exports)
	require.NotNil(t, ext.Capture.Rules[3].Refine.HTTP)
	require.Equal(t, []string{"/orders/{id}"}, ext.Capture.Rules[3].Refine.HTTP.Routes.Incoming.Patterns)
	require.Equal(t, []string{"/inventory/{id}"}, ext.Capture.Rules[3].Refine.HTTP.Routes.Outgoing.Patterns)
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

		require.Equal(t, schema.CaptureActionExclude, value(t, ext.Capture.Policy, "default_action"))
		require.Len(t, ext.Capture.Rules, 1)
		require.Equal(t, schema.CaptureActionInclude, ext.Capture.Rules[0].Action)
		require.Equal(t, cfg.Port, value(t, ext.Capture.Rules[0].Match, "process", "open_ports"))
		require.Equal(t, []string{"/srv/*"}, value(t, ext.Capture.Rules[0].Match, "process", "exe_path_glob"))
		require.Equal(t, []string{"go", "java"}, value(t, ext.Capture.Rules[0].Match, "process", "language_glob"))
	})

	t.Run("env-backed top-level glob selectors", func(t *testing.T) {
		t.Parallel()

		cfg := minimalSelectionConfig()
		require.NoError(t, cfg.AutoTargetExe.UnmarshalText([]byte("/srv/*")))
		require.NoError(t, cfg.AutoTargetLanguage.UnmarshalText([]byte("{go,java}")))

		_, ext := RuntimeToV2(&cfg)

		require.Equal(t, schema.CaptureActionExclude, value(t, ext.Capture.Policy, "default_action"))
		require.Len(t, ext.Capture.Rules, 1)
		require.Equal(t, schema.CaptureActionInclude, ext.Capture.Rules[0].Action)
		require.Equal(t, []string{"/srv/*"}, value(t, ext.Capture.Rules[0].Match, "process", "exe_path_glob"))
		require.Equal(t, []string{"go", "java"}, value(t, ext.Capture.Rules[0].Match, "process", "language_glob"))
	})

	t.Run("target pids selector", func(t *testing.T) {
		t.Parallel()

		cfg := minimalSelectionConfig()
		require.NoError(t, cfg.TargetPIDs.UnmarshalText([]byte("1234,5678")))

		_, ext := RuntimeToV2(&cfg)

		require.Equal(t, schema.CaptureActionExclude, value(t, ext.Capture.Policy, "default_action"))
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

		require.Equal(t, schema.CaptureActionExclude, value(t, ext.Capture.Policy, "default_action"))
		require.Len(t, ext.Capture.Rules, 3)
		require.Equal(t, schema.CaptureActionExclude, ext.Capture.Rules[0].Action)
		require.Equal(t, "^/tmp/.*$", value(t, ext.Capture.Rules[0].Match, "process", "exe_path_regex"))
		require.Equal(t, schema.CaptureActionInclude, ext.Capture.Rules[1].Action)
		require.Equal(t, "^/srv/api$", value(t, ext.Capture.Rules[1].Match, "process", "exe_path_regex"))
		require.Equal(t, "go|java", value(t, ext.Capture.Rules[1].Match, "process", "language_regex"))
		require.Equal(t, "--serve", value(t, ext.Capture.Rules[1].Match, "process", "cmd_args_regex"))
		require.Equal(t, "^shop$", value(t, ext.Capture.Rules[1].Match, "kubernetes", "namespace_regex"))
		require.Equal(t, "^checkout-.+$", value(t, ext.Capture.Rules[1].Match, "kubernetes", "metadata_regex", services.AttrDeploymentName))
		require.Equal(t, "^checkout$", value(t, ext.Capture.Rules[1].Match, "kubernetes", "pod_labels_regex", "app"))
		require.Equal(t, "^payments$", value(t, ext.Capture.Rules[1].Match, "kubernetes", "pod_annotations_regex", "team"))
		require.Equal(t, schema.CaptureActionInclude, ext.Capture.Rules[2].Action)
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
	require.NotEmpty(t, parsedDoc.TracerProvider.Processors)
	require.NotEmpty(t, parsedDoc.MeterProvider.Readers)
	require.NotNil(t, parsedExt.Capture.Rules)
	require.Equal(t, "1.0", parsedDoc.FileFormat)
	require.Equal(t, schema.SupportedVersion, parsedExt.Version)
	require.Equal(t, schema.CaptureActionInclude, parsedExt.Capture.Policy.DefaultAction)
	require.Equal(t, config.TCBackendAuto, value(t, parsedExt.Capture.Engine, "traffic", "control_backend"))
}

func value(t *testing.T, root any, path ...string) any {
	t.Helper()

	cur := root
	for _, key := range path {
		value := reflect.ValueOf(cur)
		for value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
			require.Falsef(t, value.IsNil(), "nil value at %q in %v", key, path)
			value = value.Elem()
		}

		if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
			idx, err := strconv.Atoi(key)
			require.NoErrorf(t, err, "expected slice index at %q in %v", key, path)
			require.GreaterOrEqualf(t, idx, 0, "slice index %q out of range in %v", key, path)
			require.Lessf(t, idx, value.Len(), "slice index %q out of range in %v", key, path)
			cur = value.Index(idx).Interface()
			continue
		}

		if value.Kind() == reflect.Map {
			mapKey := reflect.ValueOf(key)
			require.Truef(t, mapKey.Type().AssignableTo(value.Type().Key()), "expected string-keyed map at %q in %v", key, path)
			item := value.MapIndex(mapKey)
			require.Truef(t, item.IsValid(), "missing key %q in %v", key, path)
			cur = item.Interface()
			continue
		}

		require.Equalf(t, reflect.Struct, value.Kind(), "expected struct at %q in %v", key, path)
		field, ok := fieldByYAMLName(value, key)
		require.Truef(t, ok, "missing field %q in %v", key, path)
		cur = field.Interface()
	}
	return plainValue(cur)
}

func plainValue(cur any) any {
	value := reflect.ValueOf(cur)
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return nil
	}
	return value.Interface()
}

func fieldByYAMLName(value reflect.Value, name string) (reflect.Value, bool) {
	valueType := value.Type()
	for i := range value.NumField() {
		field := valueType.Field(i)
		if field.PkgPath != "" {
			continue
		}
		if yamlName(field) == name {
			return value.Field(i), true
		}
	}
	return reflect.Value{}, false
}

func yamlName(field reflect.StructField) string {
	name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
	if name == "" {
		return field.Name
	}
	return name
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
	if cfg.NameResolver != nil {
		nameResolver := *cfg.NameResolver
		cfg.NameResolver = &nameResolver
	}
	return cfg
}

func keys(root any) []string {
	value := reflect.ValueOf(root)
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		value = value.Elem()
	}

	if value.Kind() == reflect.Map {
		out := make([]string, 0, value.Len())
		iter := value.MapRange()
		for iter.Next() {
			out = append(out, iter.Key().String())
		}
		return out
	}

	out := make([]string, 0, value.NumField())
	valueType := value.Type()
	for i := range value.NumField() {
		field := valueType.Field(i)
		if field.PkgPath == "" {
			out = append(out, yamlName(field))
		}
	}
	return out
}
