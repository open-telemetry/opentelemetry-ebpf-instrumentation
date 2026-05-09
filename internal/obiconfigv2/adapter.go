// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obiconfigv2

import (
	"encoding"
	"fmt"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	obiv2 "go.opentelemetry.io/obi/pkg/obiconfig/v2"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
)

func StandaloneToRuntime(doc *obiv2.Document) (*obi.Config, error) {
	if doc == nil || doc.Extensions.OBI == nil {
		return nil, fmt.Errorf("missing extensions.obi config")
	}

	cfg, err := ConfigToRuntime(doc.Extensions.OBI, obiv2.DeploymentModeStandalone)
	if err != nil {
		return nil, err
	}

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
	setText(&cfg.EBPF.TCBackend, nestedMap(src.Capture.Engine, "traffic"), "control_backend")
	setBool(&cfg.EBPF.HighRequestVolume, nestedMap(src.Capture.Engine, "traffic"), "high_request_volume")
	setDuration(&cfg.EBPF.MaxTransactionTime, nestedMap(src.Capture.Engine, "transactions"), "max_duration")
	setString(&cfg.EBPF.BPFFSPath, nestedMap(src.Capture.Engine, "bpf_filesystem"), "path")

	httpCfg := nestedMap(src.Capture.Instrumentation, "http")
	mergeSignalFilters(&cfg.Filters.Application, nestedMap(httpCfg, "filters"))
	setBool(&cfg.EBPF.TrackRequestHeaders, httpCfg, "track_request_headers")
	setDuration(&cfg.EBPF.HTTPRequestTimeout, httpCfg, "request_timeout")
	setUint32(&cfg.EBPF.BufferSizes.HTTP, httpCfg, "buffer_size")
	setStringAlias(&cfg.Routes.Unmatch, nestedMap(httpCfg, "routes"), "unmatched")
	setString(&cfg.Routes.WildcardChar, nestedMap(httpCfg, "routes"), "wildcard_char")
	setInt(&cfg.Routes.MaxPathSegmentCardinality, nestedMap(httpCfg, "routes"), "max_path_segment_cardinality")
	setDuration(&cfg.Discovery.RouteHarvesterTimeout, nestedMap(httpCfg, "routes", "discovery"), "timeout")
	setStringSlice(&cfg.Discovery.DisabledRouteHarvesters, nestedMap(httpCfg, "routes", "discovery"), "disabled_languages")
	setDuration(&cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay, nestedMap(httpCfg, "routes", "discovery", "java"), "delay")
	setStringSlice(&cfg.Routes.Patterns, nestedMap(httpCfg, "routes"), "patterns")
	setStringSlice(&cfg.Routes.IgnorePatterns, nestedMap(httpCfg, "routes"), "ignored_patterns")
	setStringAlias(&cfg.Routes.IgnoredEvents, nestedMap(httpCfg, "routes"), "ignore_mode")
	mapPayloadExtraction(cfg, nestedMap(httpCfg, "payload_extraction"))

	sqlCfg := nestedMap(src.Capture.Instrumentation, "sql")
	setBool(&cfg.EBPF.HeuristicSQLDetect, sqlCfg, "heuristic_detect")
	setUint32(&cfg.EBPF.BufferSizes.MySQL, nestedMap(sqlCfg, "mysql"), "buffer_size")
	setInt(&cfg.EBPF.MySQLPreparedStatementsCacheSize, nestedMap(sqlCfg, "mysql"), "prepared_statements_cache_size")
	setUint32(&cfg.EBPF.BufferSizes.Postgres, nestedMap(sqlCfg, "postgres"), "buffer_size")
	setInt(&cfg.EBPF.PostgresPreparedStatementsCacheSize, nestedMap(sqlCfg, "postgres"), "prepared_statements_cache_size")

	redisCfg := nestedMap(src.Capture.Instrumentation, "redis")
	setBool(&cfg.EBPF.RedisDBCache.Enabled, nestedMap(redisCfg, "db_cache"), "enabled")
	setInt(&cfg.EBPF.RedisDBCache.MaxSize, nestedMap(redisCfg, "db_cache"), "max_size")

	kafkaCfg := nestedMap(src.Capture.Instrumentation, "kafka")
	setUint32(&cfg.EBPF.BufferSizes.Kafka, kafkaCfg, "buffer_size")
	setInt(&cfg.EBPF.KafkaTopicUUIDCacheSize, kafkaCfg, "topic_uuid_cache_size")

	mongoCfg := nestedMap(src.Capture.Instrumentation, "mongo")
	setInt(&cfg.EBPF.MongoRequestsCacheSize, mongoCfg, "requests_cache_size")

	couchbaseCfg := nestedMap(src.Capture.Instrumentation, "couchbase")
	setInt(&cfg.EBPF.CouchbaseDBCacheSize, couchbaseCfg, "db_cache_size")

	dnsCfg := nestedMap(src.Capture.Instrumentation, "dns")
	setDuration(&cfg.EBPF.DNSRequestTimeout, dnsCfg, "request_timeout")

	gpuCfg := nestedMap(src.Capture.Instrumentation, "gpu")
	setText(&cfg.EBPF.InstrumentCuda, gpuCfg, "enabled_mode")

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
	setString(&cfg.Attributes.RenameUnresolvedHosts, nestedMap(src.Enrich, "service_name", "unresolved_hosts", "names"), "default")
	setString(&cfg.Attributes.RenameUnresolvedHostsOutgoing, nestedMap(src.Enrich, "service_name", "unresolved_hosts", "names"), "outgoing")
	setString(&cfg.Attributes.RenameUnresolvedHostsIncoming, nestedMap(src.Enrich, "service_name", "unresolved_hosts", "names"), "incoming")
	setString((*string)(&cfg.Attributes.Kubernetes.Enable), nestedMap(src.Enrich, "enrichers", "kubernetes"), "mode")
	setString(&cfg.Attributes.Kubernetes.ClusterName, nestedMap(src.Enrich, "enrichers", "kubernetes"), "cluster_name")
	setString(&cfg.Attributes.Kubernetes.KubeconfigPath, nestedMap(src.Enrich, "enrichers", "kubernetes", "auth"), "kubeconfig_path")
	setDuration(&cfg.Attributes.Kubernetes.InformersSyncTimeout, nestedMap(src.Enrich, "enrichers", "kubernetes", "informers"), "initial_sync_timeout")
	setDuration(&cfg.Attributes.Kubernetes.InformersResyncPeriod, nestedMap(src.Enrich, "enrichers", "kubernetes", "informers"), "resync_period")
	setStringSlice(&cfg.Attributes.Kubernetes.DisableInformers, nestedMap(src.Enrich, "enrichers", "kubernetes", "informers"), "disabled")
	setBool(&cfg.Attributes.Kubernetes.DropExternal, nestedMap(src.Enrich, "enrichers", "kubernetes"), "drop_external")
	setString(&cfg.Attributes.Kubernetes.MetaCacheAddress, nestedMap(src.Enrich, "enrichers", "kubernetes", "metadata_cache"), "address")
	setBool(&cfg.Attributes.Kubernetes.MetaRestrictLocalNode, nestedMap(src.Enrich, "enrichers", "kubernetes", "metadata_cache"), "restrict_local_node")
	setString(&cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceName, nestedMap(src.Enrich, "enrichers", "kubernetes", "metadata_cache", "source_labels"), "service_name")
	setString(&cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceNamespace, nestedMap(src.Enrich, "enrichers", "kubernetes", "metadata_cache", "source_labels"), "service_namespace")

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
	setInt(&cfg.Traces.QueueSize, nestedMap(doc.TracerProvider, "processors", "0", "batch"), "max_queue_size")
	setMilliseconds(&cfg.Traces.BatchTimeout, nestedMap(doc.TracerProvider, "processors", "0", "batch"), "schedule_delay")
	setString(&cfg.Traces.TracesEndpoint, nestedMap(doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc"), "endpoint")
	setBool(&cfg.Traces.InsecureSkipVerify, nestedMap(doc.TracerProvider, "processors", "0", "batch", "exporter", "otlp_grpc", "tls"), "insecure")

	setMillisecondsInt(&cfg.OTELMetrics.OTELIntervalMS, nestedMap(doc.MeterProvider, "readers", "0", "periodic"), "interval")
	setString(&cfg.OTELMetrics.MetricsEndpoint, nestedMap(doc.MeterProvider, "readers", "0", "periodic", "exporter", "otlp_grpc"), "endpoint")
	setString((*string)(&cfg.OTELMetrics.HistogramAggregation), nestedMap(doc.MeterProvider, "readers", "0", "periodic", "exporter", "otlp_grpc"), "default_histogram_aggregation")
	setBool(&cfg.OTELMetrics.InsecureSkipVerify, nestedMap(doc.MeterProvider, "readers", "0", "periodic", "exporter", "otlp_grpc", "tls"), "insecure")
	setInt(&cfg.Prometheus.Port, nestedMap(doc.MeterProvider, "readers", "1", "pull", "exporter", "prometheus/development"), "port")
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
						services.AttrNamespace: globPointer("{" + join(namespaces) + "}"),
					},
				})
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
		out := values[0]
		for _, value := range values[1:] {
			out += "," + value
		}
		return out
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

func setUint32(dst *uint32, m map[string]any, key string) {
	if m == nil {
		return
	}
	switch value := m[key].(type) {
	case int:
		*dst = uint32(value)
	case int64:
		*dst = uint32(value)
	case float64:
		*dst = uint32(value)
	}
}

func setText(dst encoding.TextUnmarshaler, m map[string]any, key string) {
	if m == nil {
		return
	}
	value, ok := m[key].(string)
	if !ok {
		return
	}
	_ = dst.UnmarshalText([]byte(value))
}

func setStringAlias[T ~string](dst *T, m map[string]any, key string) {
	if m == nil {
		return
	}
	value, ok := m[key].(string)
	if !ok {
		return
	}
	*dst = T(value)
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
