// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obiconfigv2 // import "go.opentelemetry.io/obi/internal/obiconfigv2"

import (
	"encoding"
	"errors"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	obiv2 "go.opentelemetry.io/obi/pkg/obiconfig/v2"
)

func StandaloneToRuntime(doc *obiv2.Document) (*obi.Config, error) {
	if doc == nil || doc.Extensions.OBI == nil {
		return nil, errors.New("missing extensions.obi config")
	}

	cfg, err := ConfigToRuntime(doc.Extensions.OBI, obiv2.DeploymentModeStandalone)
	if err != nil {
		return nil, err
	}

	applyTopLevelResource(cfg, doc)
	applyTopLevelPipelines(cfg, doc)
	return cfg, nil
}

func ConfigToRuntime(src *obiv2.Extension, mode obiv2.DeploymentMode) (*obi.Config, error) {
	if err := obiv2.Validate(src, mode); err != nil {
		return nil, err
	}

	cfg := obi.DefaultConfig

	applyCapture(&cfg, src)
	if mode == obiv2.DeploymentModeStandalone {
		applyStandalone(&cfg, src)
	}
	applyMetricsEnablement(&cfg, src)

	cfg.NormalizeForLoad()
	return &cfg, nil
}

func applyCapture(cfg *obi.Config, src *obiv2.Extension) {
	setDuration(&cfg.Discovery.PollInterval, src.Capture.Policy, "poll_interval")
	setDuration(&cfg.Discovery.MinProcessAge, src.Capture.Policy, "min_process_age")

	setInt(&cfg.Attributes.MetricSpanNameAggregationLimit, src.Capture.Limits, "metric_span_names")
	setBool(&cfg.EnforceSysCaps, src.Capture.Safety, "enforce_system_capabilities")
	setInt(&cfg.ChannelBufferLen, src.Capture.Channels, "buffer_len")
	setDuration(&cfg.ChannelSendTimeout, src.Capture.Channels, "send_timeout")
	setBool(&cfg.ChannelSendTimeoutPanic, src.Capture.Channels, "panic_on_send_timeout")

	setBool(&cfg.EBPF.BpfDebug, nestedMap(src.Capture.Engine, "debug"), "bpf")
	setBool(&cfg.EBPF.ProtocolDebug, nestedMap(src.Capture.Engine, "debug"), "protocol_print")
	setBool(&cfg.Discovery.BPFPidFilterOff, nestedMap(src.Capture.Engine, "pid_filter"), "disabled")
	setInt(&cfg.EBPF.WakeupLen, nestedMap(src.Capture.Engine, "batching"), "wakeup_len")
	setInt(&cfg.EBPF.BatchLength, nestedMap(src.Capture.Engine, "batching"), "batch_length")
	setDuration(&cfg.EBPF.BatchTimeout, nestedMap(src.Capture.Engine, "batching"), "batch_timeout")
	setText(&cfg.EBPF.ContextPropagation, nestedMap(src.Capture.Engine, "propagation"), "context_propagation")
	setBool(&cfg.EBPF.OverrideBPFLoopEnabled, nestedMap(src.Capture.Engine, "propagation"), "override_bpfloop_enabled")
	setBool(&cfg.EBPF.DisableBlackBoxCP, nestedMap(src.Capture.Engine, "propagation"), "disable_black_box_cp")
	setText(&cfg.EBPF.TCBackend, nestedMap(src.Capture.Engine, "traffic"), "control_backend")
	setBool(&cfg.EBPF.HighRequestVolume, nestedMap(src.Capture.Engine, "traffic"), "high_request_volume")
	setText(&cfg.EBPF.ForceBPFMapReader, nestedMap(src.Capture.Engine, "traffic"), "force_map_reader")
	setDuration(&cfg.EBPF.MaxTransactionTime, nestedMap(src.Capture.Engine, "transactions"), "max_duration")
	setString(&cfg.EBPF.BPFFSPath, nestedMap(src.Capture.Engine, "bpf_filesystem"), "path")
	setInt(&cfg.EBPF.MapsConfig.GlobalScaleFactor, nestedMap(src.Capture.Engine, "maps"), "global_scale_factor")

	httpCfg := nestedMap(src.Capture.Instrumentation, "http")
	mergeSignalFilters(&cfg.Filters.Application, nestedMap(httpCfg, "filters"))
	setBool(&cfg.EBPF.TrackRequestHeaders, httpCfg, "track_request_headers")
	setDuration(&cfg.EBPF.HTTPRequestTimeout, httpCfg, "request_timeout")
	setBufferSize(&cfg.EBPF.BufferSizes.HTTP, httpCfg)
	setStringAlias(&cfg.Routes.Unmatch, nestedMap(httpCfg, "routes"), "unmatched")
	setString(&cfg.Routes.WildcardChar, nestedMap(httpCfg, "routes"), "wildcard_char")
	setInt(&cfg.Routes.MaxPathSegmentCardinality, nestedMap(httpCfg, "routes"), "max_path_segment_cardinality")
	setDuration(&cfg.Discovery.RouteHarvesterTimeout, nestedMap(httpCfg, "routes", "discovery"), "timeout")
	setStringSlice(&cfg.Discovery.DisabledRouteHarvesters, nestedMap(httpCfg, "routes", "discovery"), "disabled_languages")
	setDuration(&cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay, nestedMap(httpCfg, "routes", "discovery", "java"), "delay")
	setStringSlice(&cfg.Routes.Patterns, nestedMap(httpCfg, "routes"), "patterns")
	setStringSlice(&cfg.Routes.IgnorePatterns, nestedMap(httpCfg, "routes"), "ignored_patterns")
	setStringAlias(&cfg.Routes.IgnoredEvents, nestedMap(httpCfg, "routes"), "ignore_mode")
	payloadExtraction := nestedMap(httpCfg, "payload_extraction")
	mapPayloadExtraction(cfg, payloadExtraction)
	mapHTTPEnrichment(cfg, payloadExtraction)

	sqlCfg := nestedMap(src.Capture.Instrumentation, "sql")
	setBool(&cfg.EBPF.HeuristicSQLDetect, sqlCfg, "heuristic_detect")
	setBufferSize(&cfg.EBPF.BufferSizes.MySQL, nestedMap(sqlCfg, "mysql"))
	setInt(&cfg.EBPF.MySQLPreparedStatementsCacheSize, nestedMap(sqlCfg, "mysql"), "prepared_statements_cache_size")
	setBufferSize(&cfg.EBPF.BufferSizes.Postgres, nestedMap(sqlCfg, "postgres"))
	setInt(&cfg.EBPF.PostgresPreparedStatementsCacheSize, nestedMap(sqlCfg, "postgres"), "prepared_statements_cache_size")
	setBufferSize(&cfg.EBPF.BufferSizes.MSSQL, nestedMap(sqlCfg, "mssql"))
	setInt(&cfg.EBPF.MSSQLPreparedStatementsCacheSize, nestedMap(sqlCfg, "mssql"), "prepared_statements_cache_size")

	redisCfg := nestedMap(src.Capture.Instrumentation, "redis")
	setBool(&cfg.EBPF.RedisDBCache.Enabled, nestedMap(redisCfg, "db_cache"), "enabled")
	setInt(&cfg.EBPF.RedisDBCache.MaxSize, nestedMap(redisCfg, "db_cache"), "max_size")

	kafkaCfg := nestedMap(src.Capture.Instrumentation, "kafka")
	setBufferSize(&cfg.EBPF.BufferSizes.Kafka, kafkaCfg)
	setInt(&cfg.EBPF.KafkaTopicUUIDCacheSize, kafkaCfg, "topic_uuid_cache_size")

	mongoCfg := nestedMap(src.Capture.Instrumentation, "mongo")
	setInt(&cfg.EBPF.MongoRequestsCacheSize, mongoCfg, "requests_cache_size")

	couchbaseCfg := nestedMap(src.Capture.Instrumentation, "couchbase")
	setInt(&cfg.EBPF.CouchbaseDBCacheSize, couchbaseCfg, "db_cache_size")

	dnsCfg := nestedMap(src.Capture.Instrumentation, "dns")
	setDuration(&cfg.EBPF.DNSRequestTimeout, dnsCfg, "request_timeout")

	gpuCfg := nestedMap(src.Capture.Instrumentation, "gpu")
	setText(&cfg.EBPF.InstrumentCuda, gpuCfg, "enabled_mode")

	applyProtocolEnablement(cfg, src.Capture.Instrumentation)

	network := nestedMap(src.Capture.Network, "capture")
	mergeSignalFilters(&cfg.Filters.Network, nestedMap(network, "filters"))
	setBool(&cfg.NetworkFlows.Enable, network, "enabled")
	setString(&cfg.NetworkFlows.Source, network, "source")
	setString(&cfg.NetworkFlows.AgentIP, nestedMap(network, "endpoint_identity"), "agent_ip")
	setStringAlias(&cfg.NetworkFlows.AgentIPIface, nestedMap(network, "endpoint_identity"), "agent_ip_interface")
	setString(&cfg.NetworkFlows.AgentIPType, nestedMap(network, "endpoint_identity"), "agent_ip_family")
	setStringSlice(&cfg.NetworkFlows.Interfaces, nestedMap(network, "selection", "interfaces"), "include")
	setStringSlice(&cfg.NetworkFlows.ExcludeInterfaces, nestedMap(network, "selection", "interfaces"), "exclude")
	setStringSlice(&cfg.NetworkFlows.Protocols, nestedMap(network, "selection", "protocols"), "include")
	setStringSlice(&cfg.NetworkFlows.ExcludeProtocols, nestedMap(network, "selection", "protocols"), "exclude")
	setString(&cfg.NetworkFlows.Direction, nestedMap(network, "selection"), "direction")
	setDecoded(&cfg.NetworkFlows.CIDRs, nestedMap(network, "selection"), "cidrs")
	setBufferSize(&cfg.EBPF.BufferSizes.TCP, network)
	setInt(&cfg.NetworkFlows.CacheMaxFlows, nestedMap(network, "flow_lifecycle"), "max_tracked_flows")
	setDuration(&cfg.NetworkFlows.CacheActiveTimeout, nestedMap(network, "flow_lifecycle"), "active_timeout")
	setString(&cfg.NetworkFlows.Deduper, nestedMap(network, "flow_lifecycle", "deduplication"), "strategy")
	setDuration(&cfg.NetworkFlows.DeduperFCTTL, nestedMap(network, "flow_lifecycle", "deduplication"), "first_come_ttl")
	setInt(&cfg.NetworkFlows.Sampling, nestedMap(network, "flow_lifecycle"), "sampling")
	setString(&cfg.NetworkFlows.ListenInterfaces, nestedMap(network, "interface_discovery"), "mode")
	setDuration(&cfg.NetworkFlows.ListenPollPeriod, nestedMap(network, "interface_discovery"), "poll_interval")
	setInt(&cfg.NetworkFlows.GeoIP.CacheLen, nestedMap(network, "enrichment", "geo_ip", "cache"), "size")
	setDuration(&cfg.NetworkFlows.GeoIP.CacheTTL, nestedMap(network, "enrichment", "geo_ip", "cache"), "ttl")
	setString(&cfg.NetworkFlows.GeoIP.IPInfo.Path, nestedMap(network, "enrichment", "geo_ip", "ipinfo"), "path")
	setString(&cfg.NetworkFlows.GeoIP.MaxMindInfo.CountryPath, nestedMap(network, "enrichment", "geo_ip", "maxmind"), "country_path")
	setString(&cfg.NetworkFlows.GeoIP.MaxMindInfo.ASNPath, nestedMap(network, "enrichment", "geo_ip", "maxmind"), "asn_path")
	setString(&cfg.NetworkFlows.ReverseDNS.Type, nestedMap(network, "enrichment", "reverse_dns"), "mode")
	setInt(&cfg.NetworkFlows.ReverseDNS.CacheLen, nestedMap(network, "enrichment", "reverse_dns", "cache"), "size")
	setDuration(&cfg.NetworkFlows.ReverseDNS.CacheTTL, nestedMap(network, "enrichment", "reverse_dns", "cache"), "ttl")
	setBool(&cfg.NetworkFlows.Print, nestedMap(network, "diagnostics"), "print_flows")

	stats := nestedMap(src.Capture.Network, "stats")
	setString(&cfg.Stats.AgentIP, nestedMap(stats, "endpoint_identity"), "agent_ip")
	setStringAlias(&cfg.Stats.AgentIPIface, nestedMap(stats, "endpoint_identity"), "agent_ip_interface")
	setString(&cfg.Stats.AgentIPType, nestedMap(stats, "endpoint_identity"), "agent_ip_family")
	setDecoded(&cfg.Stats.CIDRs, nestedMap(stats, "selection"), "cidrs")
	setInt(&cfg.Stats.GeoIP.CacheLen, nestedMap(stats, "enrichment", "geo_ip", "cache"), "size")
	setDuration(&cfg.Stats.GeoIP.CacheTTL, nestedMap(stats, "enrichment", "geo_ip", "cache"), "ttl")
	setString(&cfg.Stats.GeoIP.IPInfo.Path, nestedMap(stats, "enrichment", "geo_ip", "ipinfo"), "path")
	setString(&cfg.Stats.GeoIP.MaxMindInfo.CountryPath, nestedMap(stats, "enrichment", "geo_ip", "maxmind"), "country_path")
	setString(&cfg.Stats.GeoIP.MaxMindInfo.ASNPath, nestedMap(stats, "enrichment", "geo_ip", "maxmind"), "asn_path")
	setString(&cfg.Stats.ReverseDNS.Type, nestedMap(stats, "enrichment", "reverse_dns"), "mode")
	setInt(&cfg.Stats.ReverseDNS.CacheLen, nestedMap(stats, "enrichment", "reverse_dns", "cache"), "size")
	setDuration(&cfg.Stats.ReverseDNS.CacheTTL, nestedMap(stats, "enrichment", "reverse_dns", "cache"), "ttl")
	setBool(&cfg.Stats.Print, nestedMap(stats, "diagnostics"), "print_stats")

	setInt(&cfg.OTELMetrics.ReportersCacheLen, nestedMap(src.Capture.Telemetry, "metrics"), "reporters_cache_len")
	setDuration(&cfg.OTELMetrics.TTL, nestedMap(src.Capture.Telemetry, "metrics"), "ttl")
	setInt(&cfg.Traces.ReportersCacheLen, nestedMap(src.Capture.Telemetry, "traces"), "reporters_cache_len")

	setBool(&cfg.NodeJS.Enabled, nestedMap(src.Capture.Runtimes, "nodejs"), "enabled")
	setBool(&cfg.Java.Enabled, nestedMap(src.Capture.Runtimes, "java"), "enabled")
	setBool(&cfg.Java.Debug, nestedMap(src.Capture.Runtimes, "java", "debug"), "enabled")
	setBool(&cfg.Java.DebugInstrumentation, nestedMap(src.Capture.Runtimes, "java", "debug"), "bytecode_instrumentation")
	setDuration(&cfg.Java.Timeout, nestedMap(src.Capture.Runtimes, "java"), "attach_timeout")

	mapRules(cfg, src)
}

func mapHTTPEnrichment(cfg *obi.Config, payloadExtraction map[string]any) {
	if cfg == nil {
		return
	}

	enabled := false
	for _, item := range stringSliceValue(payloadExtraction, "enabled") {
		if item == "enrichment" {
			enabled = true
			break
		}
	}
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Enabled = enabled

	enrichment := nestedMap(payloadExtraction, "enrichment")
	policy := nestedMap(enrichment, "policy")
	setText(&cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.DefaultAction.Headers, nestedMap(policy, "default_action"), "headers")
	setText(&cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.DefaultAction.Body, nestedMap(policy, "default_action"), "body")
	setString(&cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Policy.ObfuscationString, policy, "obfuscation_string")

	if rules, ok := enrichment["rules"]; ok {
		setDecoded(&cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Rules, enrichment, "rules")
		if rules == nil {
			cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Rules = nil
		}
	}
}

func applyProtocolEnablement(cfg *obi.Config, instrumentationCfg map[string]any) {
	cfg.Traces.Instrumentations = applySignalEnablement(cfg.Traces.Instrumentations, instrumentationCfg, "traces")
	cfg.OTELMetrics.Instrumentations = applySignalEnablement(cfg.OTELMetrics.Instrumentations, instrumentationCfg, "metrics")
	cfg.Prometheus.Instrumentations = applySignalEnablement(cfg.Prometheus.Instrumentations, instrumentationCfg, "metrics")
}

func applyMetricsEnablement(cfg *obi.Config, src *obiv2.Extension) {
	appMetricsEnabled := false
	for _, mapping := range protocolMappings {
		if boolValue(nestedMap(src.Capture.Instrumentation, mapping.name, "enabled"), "metrics") {
			appMetricsEnabled = true
			break
		}
	}

	cfg.ApplyV2MetricsEnablement(
		appMetricsEnabled,
		boolValue(nestedMap(src.Capture.Network, "capture"), "enabled"),
	)
}

func applySignalEnablement(
	current []instrumentations.Instrumentation,
	instrumentationCfg map[string]any,
	signal string,
) []instrumentations.Instrumentation {
	if len(instrumentationCfg) == 0 {
		return current
	}

	selected := map[instrumentations.Instrumentation]bool{}
	hasAll := false
	for _, instr := range current {
		if instr == instrumentations.InstrumentationALL {
			hasAll = true
			for _, candidate := range runtimeInstrumentations {
				selected[candidate] = true
			}
			continue
		}
		selected[instr] = true
	}

	updated := false
	for _, mapping := range protocolMappings {
		enabledCfg := nestedMap(instrumentationCfg, mapping.name, "enabled")
		enabled, ok := enabledCfg[signal].(bool)
		if !ok {
			continue
		}
		selected[mapping.instr] = enabled
		updated = true
	}

	if !updated {
		return current
	}

	allRuntimeEnabled := true
	for _, candidate := range runtimeInstrumentations {
		if !selected[candidate] {
			allRuntimeEnabled = false
			break
		}
	}
	if hasAll && allRuntimeEnabled {
		return []instrumentations.Instrumentation{instrumentations.InstrumentationALL}
	}

	out := make([]instrumentations.Instrumentation, 0, len(runtimeInstrumentations))
	for _, candidate := range runtimeInstrumentations {
		if selected[candidate] {
			out = append(out, candidate)
		}
	}
	return out
}

func applyStandalone(cfg *obi.Config, src *obiv2.Extension) {
	setString((*string)(&cfg.TracePrinter), nestedMap(src.Daemon, "logging"), "debug_trace_output")
	if cfg.TracePrinter == "" {
		cfg.TracePrinter = debug.TracePrinterDisabled
	}
	setString((*string)(&cfg.LogConfig), nestedMap(src.Daemon, "logging"), "format")
	setString((*string)(&cfg.LogLevel), nestedMap(src.Daemon, "logging"), "level")
	setInt(&cfg.ProfilePort, nestedMap(src.Daemon, "profiling"), "port")
	setDuration(&cfg.ShutdownTimeout, nestedMap(src.Daemon, "shutdown"), "timeout")
	setString((*string)(&cfg.InternalMetrics.Exporter), nestedMap(src.Daemon, "internal_metrics"), "exporter")
	setInt(&cfg.InternalMetrics.Prometheus.Port, nestedMap(src.Daemon, "internal_metrics", "prometheus"), "port")
	setString(&cfg.InternalMetrics.Prometheus.Path, nestedMap(src.Daemon, "internal_metrics", "prometheus"), "path")
	setDuration(&cfg.InternalMetrics.BpfMetricScrapeInterval, nestedMap(src.Daemon, "internal_metrics", "bpf"), "scrape_interval")

	setInt(&cfg.NameResolver.CacheLen, nestedMap(src.Enrich, "service_name", "cache"), "size")
	setDuration(&cfg.NameResolver.CacheTTL, nestedMap(src.Enrich, "service_name", "cache"), "ttl")
	setStringSlice(&cfg.NameResolver.Sources, nestedMap(src.Enrich, "service_name"), "sources")
	setString(&cfg.Attributes.RenameUnresolvedHosts, nestedMap(src.Enrich, "service_name", "unresolved_hosts", "names"), "default")
	setString(&cfg.Attributes.RenameUnresolvedHostsOutgoing, nestedMap(src.Enrich, "service_name", "unresolved_hosts", "names"), "outgoing")
	setString(&cfg.Attributes.RenameUnresolvedHostsIncoming, nestedMap(src.Enrich, "service_name", "unresolved_hosts", "names"), "incoming")
	setString((*string)(&cfg.Attributes.Kubernetes.Enable), nestedMap(src.Enrich, "enrichers", "kubernetes"), "mode")
	setString(&cfg.Attributes.Kubernetes.ClusterName, nestedMap(src.Enrich, "enrichers", "kubernetes"), "cluster_name")
	setString(&cfg.Attributes.Kubernetes.ServiceNameTemplate, nestedMap(src.Enrich, "enrichers", "kubernetes"), "service_name_template")
	setString(&cfg.Attributes.Kubernetes.KubeconfigPath, nestedMap(src.Enrich, "enrichers", "kubernetes", "auth"), "kubeconfig_path")
	setDuration(&cfg.Attributes.Kubernetes.InformersSyncTimeout, nestedMap(src.Enrich, "enrichers", "kubernetes", "informers"), "initial_sync_timeout")
	setDuration(&cfg.Attributes.Kubernetes.ReconnectInitialInterval, nestedMap(src.Enrich, "enrichers", "kubernetes", "informers"), "reconnect_initial_interval")
	setDuration(&cfg.Attributes.Kubernetes.InformersResyncPeriod, nestedMap(src.Enrich, "enrichers", "kubernetes", "informers"), "resync_period")
	setStringSlice(&cfg.Attributes.Kubernetes.DisableInformers, nestedMap(src.Enrich, "enrichers", "kubernetes", "informers"), "disabled")
	setBool(&cfg.Attributes.Kubernetes.DropExternal, nestedMap(src.Enrich, "enrichers", "kubernetes"), "drop_external")
	if kubernetes := nestedMap(src.Enrich, "enrichers", "kubernetes"); kubernetes["resource_labels"] != nil {
		cfg.Attributes.Kubernetes.ResourceLabels = nil
		setDecoded(&cfg.Attributes.Kubernetes.ResourceLabels, kubernetes, "resource_labels")
	}
	setString(&cfg.Attributes.Kubernetes.MetaCacheAddress, nestedMap(src.Enrich, "enrichers", "kubernetes", "metadata_cache"), "address")
	setBool(&cfg.Attributes.Kubernetes.MetaRestrictLocalNode, nestedMap(src.Enrich, "enrichers", "kubernetes", "metadata_cache"), "restrict_local_node")
	setString(&cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceName, nestedMap(src.Enrich, "enrichers", "kubernetes", "metadata_cache", "source_labels"), "service_name")
	setString(&cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceNamespace, nestedMap(src.Enrich, "enrichers", "kubernetes", "metadata_cache", "source_labels"), "service_namespace")
	if attributes := nestedMap(src.Enrich, "attributes"); attributes["extra_group_attributes"] != nil {
		cfg.Attributes.ExtraGroupAttributes = nil
		setDecoded(&cfg.Attributes.ExtraGroupAttributes, attributes, "extra_group_attributes")
	}
	if attributes := nestedMap(src.Enrich, "attributes"); attributes["select"] != nil {
		cfg.Attributes.Select = nil
		setDecoded(&cfg.Attributes.Select, attributes, "select")
	}
	metadataRetry := nestedMap(src.Enrich, "attributes", "metadata_retry")
	setDuration(&cfg.Attributes.MetadataRetry.Timeout, metadataRetry, "timeout")
	setDuration(&cfg.Attributes.MetadataRetry.StartInterval, metadataRetry, "start_interval")
	setDuration(&cfg.Attributes.MetadataRetry.MaxInterval, metadataRetry, "max_interval")

	if boolValue(nestedMap(src.Correlation, "log_trace_annotation"), "enabled") {
		cfg.EBPF.LogEnricher.Services = []obicfg.LogEnricherServiceConfig{{
			Service: services.GlobDefinitionCriteria{{Path: services.NewGlob("*")}},
		}}
	}
	setDuration(&cfg.EBPF.LogEnricher.CacheTTL, nestedMap(src.Correlation, "log_trace_annotation", "cache"), "ttl")
	setInt(&cfg.EBPF.LogEnricher.CacheSize, nestedMap(src.Correlation, "log_trace_annotation", "cache"), "size")
	setInt(&cfg.EBPF.LogEnricher.AsyncWriterWorkers, nestedMap(src.Correlation, "log_trace_annotation", "async_writer"), "workers")
	setInt(&cfg.EBPF.LogEnricher.AsyncWriterChannelLen, nestedMap(src.Correlation, "log_trace_annotation", "async_writer"), "channel_len")

	setBool(&cfg.Prometheus.AllowServiceGraphSelfReferences, nestedMap(src.Daemon, "telemetry", "metrics", "prometheus"), "allow_service_graph_self_references")
	setInt(&cfg.Prometheus.SpanMetricsServiceCacheSize, nestedMap(src.Daemon, "telemetry", "metrics", "prometheus"), "span_metrics_service_cache_size")
	setStringSlice(&cfg.Prometheus.ExtraResourceLabels, nestedMap(src.Daemon, "telemetry", "metrics", "prometheus"), "extra_resource_attributes")
	setStringSlice(&cfg.Prometheus.ExtraSpanResourceLabels, nestedMap(src.Daemon, "telemetry", "metrics", "prometheus"), "extra_span_resource_attributes")
}

func applyTopLevelPipelines(cfg *obi.Config, doc *obiv2.Document) {
	setSamplerConfig(&cfg.Traces.SamplerConfig, nestedMap(doc.TracerProvider, "sampler"))
	setInt(&cfg.Traces.BatchMaxSize, nestedMap(doc.TracerProvider, "processors", "0", "batch"), "max_export_batch_size")
	setInt(&cfg.Traces.QueueSize, nestedMap(doc.TracerProvider, "processors", "0", "batch"), "max_queue_size")
	setMilliseconds(&cfg.Traces.BatchTimeout, nestedMap(doc.TracerProvider, "processors", "0", "batch"), "schedule_delay")
	setString(&cfg.Traces.TracesEndpoint, nestedMap(doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc"), "endpoint")
	setBool(&cfg.Traces.InsecureSkipVerify, nestedMap(doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc", "tls"), "insecure")
	setDuration(&cfg.Traces.BackOffInitialInterval, nestedMap(doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc", "retry"), "initial_interval")
	setDuration(&cfg.Traces.BackOffMaxInterval, nestedMap(doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc", "retry"), "max_interval")
	setDuration(&cfg.Traces.BackOffMaxElapsedTime, nestedMap(doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc", "retry"), "max_elapsed_time")

	periodicReader := topLevelMeterReader(doc.MeterProvider, "periodic")
	setMillisecondsInt(&cfg.OTELMetrics.OTELIntervalMS, periodicReader, "interval")
	setString(&cfg.OTELMetrics.MetricsEndpoint, nestedMap(periodicReader, "exporter", "otlp_grpc"), "endpoint")
	setString((*string)(&cfg.OTELMetrics.HistogramAggregation), nestedMap(periodicReader, "exporter", "otlp_grpc"), "default_histogram_aggregation")
	setBool(&cfg.OTELMetrics.InsecureSkipVerify, nestedMap(periodicReader, "exporter", "otlp_grpc", "tls"), "insecure")

	pullReader := topLevelMeterReader(doc.MeterProvider, "pull")
	setInt(&cfg.Prometheus.Port, nestedMap(pullReader, "exporter", "prometheus/development"), "port")
}

func applyTopLevelResource(cfg *obi.Config, doc *obiv2.Document) {
	setString(&cfg.Attributes.InstanceID.OverrideHostname, doc.Resource, "host.name")
	setString(&cfg.Attributes.HostID.Override, doc.Resource, "host.id")
}

func topLevelMeterReader(meterProvider map[string]any, readerType string) map[string]any {
	readers, _ := meterProvider["readers"].([]any)
	for _, reader := range readers {
		readerMap, _ := reader.(map[string]any)
		if readerCfg := nestedMap(readerMap, readerType); readerCfg != nil {
			return readerCfg
		}
	}

	return nil
}

func mapRules(cfg *obi.Config, src *obiv2.Extension) {
	defaultAction := stringValue(src.Capture.Policy, "default_action")
	if defaultAction == "" {
		defaultAction = "include"
	}
	if defaultAction == "include" {
		cfg.Discovery.Instrument = append(cfg.Discovery.Instrument, services.GlobAttributes{
			Path: services.NewGlob("*"),
		})
	}

	for _, rule := range src.Capture.Rules {
		process := nestedMap(rule.Match, "process")
		k8s := nestedMap(rule.Match, "kubernetes")

		if process != nil {
			if exports := nestedMap(process, "exports_otlp"); exports != nil {
				cfg.Discovery.ExcludeOTelInstrumentedServices = rule.Action == "exclude"
				setInt(&cfg.Discovery.DefaultOtlpGRPCPort, exports, "port")
				continue
			}

			if ports, ok := intEnumValue(process, "open_ports"); ok {
				appendRuleSelector(cfg, rule.Action, services.GlobAttributes{OpenPorts: ports})
			}

			if pids := uint32SliceValue(process, "target_pids"); len(pids) > 0 {
				appendRuleSelector(cfg, rule.Action, services.GlobAttributes{PIDs: pids})
			}

			for _, glob := range stringSliceValue(process, "language_glob") {
				appendRuleSelector(cfg, rule.Action, services.GlobAttributes{Languages: services.NewGlob(glob)})
			}

			for _, glob := range stringSliceValue(process, "cmd_args_glob") {
				appendRuleSelector(cfg, rule.Action, services.GlobAttributes{CmdArgs: services.NewGlob(glob)})
			}

			globs := stringSliceValue(process, "exe_path_glob")
			if len(globs) > 0 {
				if rule.Name == "exclude-linux-system-paths" {
					cfg.Discovery.ExcludedLinuxSystemPaths = make([]string, 0, len(globs))
					for _, glob := range globs {
						cfg.Discovery.ExcludedLinuxSystemPaths = append(cfg.Discovery.ExcludedLinuxSystemPaths, trimGlobSuffix(glob))
					}
				}
				for _, glob := range globs {
					appendRuleSelector(cfg, rule.Action, services.GlobAttributes{Path: services.NewGlob(glob)})
				}
			}
		}

		if k8s != nil {
			namespaces := stringSliceValue(k8s, "namespace_glob")
			if len(namespaces) > 0 {
				appendRuleSelector(cfg, rule.Action, services.GlobAttributes{
					Metadata: services.MetadataGlobMap{
						services.AttrNamespace: combinedGlobPointer(namespaces),
					},
				})
			}

			if labels := globMapValue(k8s, "pod_labels"); len(labels) > 0 {
				appendRuleSelector(cfg, rule.Action, services.GlobAttributes{PodLabels: labels})
			}

			if annotations := globMapValue(k8s, "pod_annotations"); len(annotations) > 0 {
				appendRuleSelector(cfg, rule.Action, services.GlobAttributes{PodAnnotations: annotations})
			}
		}
	}

	goEnabled := boolValue(nestedMap(src.Capture.Runtimes, "go"), "enabled")
	cfg.Discovery.SkipGoSpecificTracers = !goEnabled
}

func appendRuleSelector(cfg *obi.Config, action string, selector services.GlobAttributes) {
	switch action {
	case "exclude":
		cfg.Discovery.ExcludeInstrument = append(cfg.Discovery.ExcludeInstrument, selector)
	case "include":
		cfg.Discovery.Instrument = append(cfg.Discovery.Instrument, selector)
	}
}

func mapPayloadExtraction(cfg *obi.Config, m map[string]any) {
	enabled := map[string]bool{}
	for _, name := range stringSliceValue(m, "enabled") {
		enabled[name] = true
	}
	cfg.EBPF.PayloadExtraction.HTTP.GraphQL.Enabled = enabled["graphql"]
	cfg.EBPF.PayloadExtraction.HTTP.Elasticsearch.Enabled = enabled["elasticsearch"]
	cfg.EBPF.PayloadExtraction.HTTP.AWS.Enabled = enabled["aws"]
	cfg.EBPF.PayloadExtraction.HTTP.SQLPP.Enabled = enabled["sqlpp"]
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.OpenAI.Enabled = enabled["openai"]
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Anthropic.Enabled = enabled["anthropic"]
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Gemini.Enabled = enabled["gemini"]
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Qwen.Enabled = enabled["qwen"]
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Bedrock.Enabled = enabled["bedrock"]
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.MCP.Enabled = enabled["mcp"]
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Embedding.Enabled = enabled["embedding"]
	cfg.EBPF.PayloadExtraction.HTTP.GenAI.Rerank.Enabled = enabled["rerank"]
	setStringSlice(&cfg.EBPF.PayloadExtraction.HTTP.SQLPP.EndpointPatterns, nestedMap(m, "sqlpp"), "endpoint_patterns")
}

func trimGlobSuffix(glob string) string {
	if len(glob) >= 2 && glob[len(glob)-2:] == "/*" {
		return glob[:len(glob)-1]
	}
	return glob
}

func globPointer(value string) *services.GlobAttr {
	glob := services.NewGlob(value)
	return &glob
}

func join(values []string) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	default:
		return strings.Join(values, ",")
	}
}

func nestedMap(v any, path ...string) map[string]any {
	cur := v
	for _, key := range path {
		switch current := cur.(type) {
		case map[string]any:
			next, ok := current[key]
			if !ok {
				return nil
			}
			cur = next
			continue
		case []any:
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx >= len(current) {
				return nil
			}
			cur = current[idx]
			continue
		default:
			return nil
		}
	}
	result, _ := cur.(map[string]any)
	return result
}

func stringValue(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	value, ok := m[key].(string)
	if !ok {
		return ""
	}
	return value
}

func boolValue(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	value, _ := m[key].(bool)
	return value
}

func stringSliceValue(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	if values, ok := m[key].([]string); ok {
		return append([]string(nil), values...)
	}
	values, ok := m[key].([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		str, ok := value.(string)
		if ok {
			result = append(result, str)
		}
	}
	return result
}

func globMapValue(m map[string]any, key string) map[string]*services.GlobAttr {
	if m == nil {
		return nil
	}

	values, ok := m[key].(map[string]any)
	if !ok {
		return nil
	}

	result := make(map[string]*services.GlobAttr, len(values))
	for name, raw := range values {
		globs := globListValue(raw)
		if len(globs) == 0 {
			continue
		}
		result[name] = combinedGlobPointer(globs)
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

func globListValue(value any) []string {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			str, ok := item.(string)
			if ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return nil
	}
}

func combinedGlobPointer(globs []string) *services.GlobAttr {
	if len(globs) == 0 {
		return nil
	}
	if len(globs) == 1 {
		return globPointer(globs[0])
	}
	return globPointer("{" + join(globs) + "}")
}

func uint32SliceValue(m map[string]any, key string) []uint32 {
	if m == nil {
		return nil
	}
	switch values := m[key].(type) {
	case []uint32:
		return append([]uint32(nil), values...)
	case []int:
		result := make([]uint32, 0, len(values))
		for _, value := range values {
			result = append(result, uint32(value))
		}
		return result
	case []int64:
		result := make([]uint32, 0, len(values))
		for _, value := range values {
			result = append(result, uint32(value))
		}
		return result
	case []float64:
		result := make([]uint32, 0, len(values))
		for _, value := range values {
			result = append(result, uint32(value))
		}
		return result
	case []any:
		result := make([]uint32, 0, len(values))
		for _, value := range values {
			switch n := value.(type) {
			case int:
				result = append(result, uint32(n))
			case int64:
				result = append(result, uint32(n))
			case float64:
				result = append(result, uint32(n))
			}
		}
		return result
	}
	return nil
}

func intEnumValue(m map[string]any, key string) (services.IntEnum, bool) {
	if m == nil {
		return services.IntEnum{}, false
	}

	var out services.IntEnum
	switch value := m[key].(type) {
	case services.IntEnum:
		if value.Len() > 0 {
			return value, true
		}
	case string:
		if err := out.UnmarshalText([]byte(value)); err == nil && out.Len() > 0 {
			return out, true
		}
	case int:
		out.Ranges = []services.IntRange{{Start: value}}
		return out, true
	case int64:
		out.Ranges = []services.IntRange{{Start: int(value)}}
		return out, true
	case float64:
		out.Ranges = []services.IntRange{{Start: int(value)}}
		return out, true
	}

	return services.IntEnum{}, false
}

func setString(dst *string, m map[string]any, key string) {
	if m == nil {
		return
	}
	if value, ok := m[key].(string); ok {
		*dst = value
	}
}

func setBool(dst *bool, m map[string]any, key string) {
	if m == nil {
		return
	}
	if value, ok := m[key].(bool); ok {
		*dst = value
	}
}

func setInt(dst *int, m map[string]any, key string) {
	if m == nil {
		return
	}
	switch value := m[key].(type) {
	case int:
		*dst = value
	case int64:
		*dst = int(value)
	case float64:
		*dst = int(value)
	}
}

func setDuration(dst *time.Duration, m map[string]any, key string) {
	if m == nil {
		return
	}
	if raw, ok := m[key].(string); ok {
		if value, err := time.ParseDuration(raw); err == nil {
			*dst = value
		}
	}
}

func setMilliseconds(dst *time.Duration, m map[string]any, key string) {
	if m == nil {
		return
	}
	switch value := m[key].(type) {
	case int:
		*dst = time.Duration(value) * time.Millisecond
	case int64:
		*dst = time.Duration(value) * time.Millisecond
	case float64:
		*dst = time.Duration(int(value)) * time.Millisecond
	}
}

func setMillisecondsInt(dst *int, m map[string]any, key string) {
	if m == nil {
		return
	}
	switch value := m[key].(type) {
	case int:
		*dst = value
	case int64:
		*dst = int(value)
	case float64:
		*dst = int(value)
	}
}

func setStringSlice[T ~string](dst *[]T, m map[string]any, key string) {
	values := stringSliceValue(m, key)
	if len(values) == 0 {
		return
	}
	out := make([]T, 0, len(values))
	for _, value := range values {
		out = append(out, T(value))
	}
	*dst = out
}

func setBufferSize(dst *uint32, m map[string]any) {
	if m == nil {
		return
	}
	switch value := m["buffer_size"].(type) {
	case int:
		*dst = uint32(value)
	case int64:
		*dst = uint32(value)
	case uint32:
		*dst = value
	case uint64:
		*dst = uint32(value)
	case float64:
		*dst = uint32(value)
	}
}

func setText(dst encoding.TextUnmarshaler, m map[string]any, key string) {
	if m == nil {
		return
	}
	switch value := m[key].(type) {
	case string:
		_ = dst.UnmarshalText([]byte(value))
	case encoding.TextMarshaler:
		text, err := value.MarshalText()
		if err == nil {
			_ = dst.UnmarshalText(text)
		}
	}
}

func setStringAlias[T ~string](dst *T, m map[string]any, key string) {
	if m == nil {
		return
	}

	switch value := m[key].(type) {
	case string:
		*dst = T(value)
	case T:
		*dst = value
	}
}

func setDecoded(dst any, m map[string]any, key string) {
	if m == nil {
		return
	}

	value, ok := m[key]
	if !ok {
		return
	}

	data, err := yaml.Marshal(value)
	if err != nil {
		return
	}

	_ = yaml.Unmarshal(data, dst)
}

func setSamplerConfig(dst *services.SamplerConfig, m map[string]any) {
	if m == nil {
		return
	}

	data, err := yaml.Marshal(m)
	if err != nil {
		return
	}

	var sampler services.SamplerConfig
	if err := yaml.Unmarshal(data, &sampler); err != nil {
		return
	}

	*dst = sampler
}

func mergeSignalFilters(dst *filter.AttributeFamilyConfig, m map[string]any) {
	if m == nil {
		return
	}

	for _, key := range []string{"traces", "metrics"} {
		filters := decodeFilterFamily(nestedMap(m, key))
		if len(filters) == 0 {
			continue
		}
		if *dst == nil {
			*dst = filter.AttributeFamilyConfig{}
		}
		for attr, def := range filters {
			(*dst)[attr] = def
		}
	}
}

func decodeFilterFamily(m map[string]any) filter.AttributeFamilyConfig {
	if m == nil {
		return nil
	}

	data, err := yaml.Marshal(m)
	if err != nil {
		return nil
	}

	var filters filter.AttributeFamilyConfig
	if err := yaml.Unmarshal(data, &filters); err != nil {
		return nil
	}

	return filters
}
