// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"encoding"
	"fmt"
	"net/url"

	"go.opentelemetry.io/obi/internal/config/schema"
	featureexport "go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/obi"
)

// RuntimeToV2 converts an already-loaded v1 runtime configuration into the
// internal config v2 document shape.
func RuntimeToV2(cfg *obi.Config) (*schema.Document, *schema.Extension) {
	if cfg == nil {
		defaultConfig := obi.DefaultConfig
		cfg = &defaultConfig
	}

	ext := &schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Policy:          capturePolicy(cfg),
			Instrumentation: captureInstrumentation(cfg),
			Runtimes:        captureRuntimes(cfg),
			Network:         captureNetwork(cfg),
			Limits:          captureLimits(cfg),
			Engine:          captureEngine(cfg),
			Safety:          captureSafety(cfg),
			Channels:        captureChannels(cfg),
			Rules:           rulesFromRuntime(cfg),
			Telemetry:       captureTelemetry(cfg),
		},
		Enrich:      enrich(cfg),
		Correlation: correlation(cfg),
		Daemon:      daemon(cfg),
	}

	doc := &schema.Document{
		FileFormat:     "1.0",
		Resource:       resource(cfg),
		Propagator:     map[string]any{},
		TracerProvider: tracerProvider(cfg),
		MeterProvider:  meterProvider(cfg),
		Extensions:     schema.Extensions{OBI: ext},
	}

	return doc, ext
}

func capturePolicy(cfg *obi.Config) map[string]any {
	return map[string]any{
		"default_action":  defaultPolicyAction(cfg),
		"match_order":     "first_match_wins",
		"poll_interval":   cfg.Discovery.PollInterval.String(),
		"min_process_age": cfg.Discovery.MinProcessAge.String(),
	}
}

func defaultPolicyAction(cfg *obi.Config) string {
	if cfg.Enabled(obi.FeatureAppO11y) {
		return "exclude"
	}
	return "include"
}

func captureInstrumentation(cfg *obi.Config) map[string]any {
	tracesInstrumentations := cfg.Traces.Instrumentations
	metricsInstrs := metricsInstrumentations(cfg)
	appMetricsEnabled := cfg.Metrics.Features.AnyAppO11yMetric()

	instrumentation := make(map[string]any, len(protocolMappings))
	for _, mapping := range protocolMappings {
		instrumentation[mapping.name] = map[string]any{
			"enabled": protocolEnabled(tracesInstrumentations, metricsInstrs, appMetricsEnabled, mapping),
		}
	}

	for _, mapping := range protocolMappings {
		protocolCfg := instrumentation[mapping.name].(map[string]any)
		protocolCfg["filters"] = signalFilters(cfg.Filters.Application)
	}

	http := instrumentation["http"].(map[string]any)
	http["track_request_headers"] = cfg.EBPF.TrackRequestHeaders
	http["request_timeout"] = cfg.EBPF.HTTPRequestTimeout.String()
	http["buffer_size"] = cfg.EBPF.BufferSizes.HTTP
	http["routes"] = httpRoutes(cfg)
	http["payload_extraction"] = payloadExtraction(cfg)

	sql := instrumentation["sql"].(map[string]any)
	sql["heuristic_detect"] = cfg.EBPF.HeuristicSQLDetect
	sql["mysql"] = map[string]any{
		"buffer_size":                    cfg.EBPF.BufferSizes.MySQL,
		"prepared_statements_cache_size": cfg.EBPF.MySQLPreparedStatementsCacheSize,
	}
	sql["postgres"] = map[string]any{
		"buffer_size":                    cfg.EBPF.BufferSizes.Postgres,
		"prepared_statements_cache_size": cfg.EBPF.PostgresPreparedStatementsCacheSize,
	}
	sql["mssql"] = map[string]any{
		"buffer_size":                    cfg.EBPF.BufferSizes.MSSQL,
		"prepared_statements_cache_size": cfg.EBPF.MSSQLPreparedStatementsCacheSize,
	}

	redis := instrumentation["redis"].(map[string]any)
	redis["db_cache"] = map[string]any{
		"enabled":  cfg.EBPF.RedisDBCache.Enabled,
		"max_size": cfg.EBPF.RedisDBCache.MaxSize,
	}

	kafka := instrumentation["kafka"].(map[string]any)
	kafka["buffer_size"] = cfg.EBPF.BufferSizes.Kafka
	kafka["topic_uuid_cache_size"] = cfg.EBPF.KafkaTopicUUIDCacheSize

	mongo := instrumentation["mongo"].(map[string]any)
	mongo["requests_cache_size"] = cfg.EBPF.MongoRequestsCacheSize

	couchbase := instrumentation["couchbase"].(map[string]any)
	couchbase["db_cache_size"] = cfg.EBPF.CouchbaseDBCacheSize

	dns := instrumentation["dns"].(map[string]any)
	dns["request_timeout"] = cfg.EBPF.DNSRequestTimeout.String()

	gpu := instrumentation["gpu"].(map[string]any)
	gpu["enabled_mode"] = textValue(cfg.EBPF.InstrumentCuda)

	return instrumentation
}

func metricsInstrumentations(cfg *obi.Config) []instrumentations.Instrumentation {
	var combined []instrumentations.Instrumentation
	if cfg.OTELMetrics.EndpointEnabled() {
		combined = appendMetricInstrumentations(combined, cfg.OTELMetrics.Instrumentations)
	}
	if cfg.Prometheus.EndpointEnabled() {
		combined = appendMetricInstrumentations(combined, cfg.Prometheus.Instrumentations)
	}
	if len(combined) != 0 {
		return combined
	}

	combined = appendMetricInstrumentations(combined, cfg.OTELMetrics.Instrumentations)
	return appendMetricInstrumentations(combined, cfg.Prometheus.Instrumentations)
}

func appendMetricInstrumentations(
	dst []instrumentations.Instrumentation,
	src []instrumentations.Instrumentation,
) []instrumentations.Instrumentation {
	for _, instr := range src {
		if !containsInstrumentation(dst, instr) {
			dst = append(dst, instr)
		}
	}
	return dst
}

func containsInstrumentation(list []instrumentations.Instrumentation, needle instrumentations.Instrumentation) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

func protocolEnabled(
	tracesInstrumentations []instrumentations.Instrumentation,
	metricsInstrumentations []instrumentations.Instrumentation,
	appMetricsEnabled bool,
	mapping protocolMapping,
) map[string]any {
	metricsEnabled := protocolSelected(metricsInstrumentations, mapping, mapping.metricWildcard)
	if mapping.appMetrics {
		metricsEnabled = metricsEnabled && appMetricsEnabled
	}

	return map[string]any{
		"traces":  protocolSelected(tracesInstrumentations, mapping, true),
		"metrics": metricsEnabled,
	}
}

func protocolSelected(list []instrumentations.Instrumentation, mapping protocolMapping, wildcard bool) bool {
	for _, instr := range list {
		if instr == mapping.instr {
			return true
		}
		if instr == instrumentations.InstrumentationALL && wildcard {
			return true
		}
	}
	return false
}

func captureRuntimes(cfg *obi.Config) map[string]any {
	return map[string]any{
		"go": map[string]any{
			"enabled": !cfg.Discovery.SkipGoSpecificTracers,
			"filter":  map[string]any{},
		},
		"nodejs": map[string]any{
			"enabled": cfg.NodeJS.Enabled,
			"filter":  map[string]any{},
		},
		"java": map[string]any{
			"enabled": cfg.Java.Enabled,
			"filter":  map[string]any{},
			"debug": map[string]any{
				"enabled":                  cfg.Java.Debug,
				"bytecode_instrumentation": cfg.Java.DebugInstrumentation,
			},
			"attach_timeout": cfg.Java.Timeout.String(),
		},
	}
}

func captureNetwork(cfg *obi.Config) map[string]any {
	return map[string]any{
		"capture": map[string]any{
			"enabled":     cfg.NetworkFlows.Enable || cfg.Metrics.Features.AnyNetwork(),
			"source":      cfg.NetworkFlows.Source,
			"buffer_size": cfg.EBPF.BufferSizes.TCP,
			"endpoint_identity": map[string]any{
				"agent_ip":           cfg.NetworkFlows.AgentIP,
				"agent_ip_interface": cfg.NetworkFlows.AgentIPIface,
				"agent_ip_family":    cfg.NetworkFlows.AgentIPType,
			},
			"selection": map[string]any{
				"interfaces": map[string]any{
					"include": cfg.NetworkFlows.Interfaces,
					"exclude": cfg.NetworkFlows.ExcludeInterfaces,
				},
				"protocols": map[string]any{
					"include": cfg.NetworkFlows.Protocols,
					"exclude": cfg.NetworkFlows.ExcludeProtocols,
				},
				"direction": cfg.NetworkFlows.Direction,
				"cidrs":     cfg.NetworkFlows.CIDRs,
			},
			"filters": signalFilters(cfg.Filters.Network),
			"flow_lifecycle": map[string]any{
				"max_tracked_flows": cfg.NetworkFlows.CacheMaxFlows,
				"active_timeout":    cfg.NetworkFlows.CacheActiveTimeout.String(),
				"deduplication": map[string]any{
					"strategy":       cfg.NetworkFlows.Deduper,
					"first_come_ttl": cfg.NetworkFlows.DeduperFCTTL.String(),
				},
				"sampling":    cfg.NetworkFlows.Sampling,
				"guess_ports": cfg.NetworkFlows.GuessPorts,
			},
			"interface_discovery": map[string]any{
				"mode":          cfg.NetworkFlows.ListenInterfaces,
				"poll_interval": cfg.NetworkFlows.ListenPollPeriod.String(),
			},
			"enrichment": networkFlowEnrichment(cfg),
			"diagnostics": map[string]any{
				"print_flows": cfg.NetworkFlows.Print,
			},
		},
		"stats": map[string]any{
			"enabled":  cfg.Enabled(obi.FeatureStatsO11y),
			"features": statsFeatures(cfg.Metrics.Features),
			"endpoint_identity": map[string]any{
				"agent_ip":           cfg.Stats.AgentIP,
				"agent_ip_interface": cfg.Stats.AgentIPIface,
				"agent_ip_family":    cfg.Stats.AgentIPType,
			},
			"selection": map[string]any{
				"cidrs": cfg.Stats.CIDRs,
			},
			"filters":    signalFilters(cfg.Filters.Stats),
			"enrichment": statsEnrichment(cfg),
			"diagnostics": map[string]any{
				"print_stats": cfg.Stats.Print,
			},
		},
	}
}

const (
	statsFeatureTCPRtt               = "tcp_rtt"
	statsFeatureTCPFailedConnections = "tcp_failed_connections"
	statsFeatureTCPRetransmits       = "tcp_retransmits"
	statsFeatureTCPIo                = "tcp_io"
)

func statsFeatures(features featureexport.Features) []string {
	out := []string{}
	if features.StatsTCPRtt() {
		out = append(out, statsFeatureTCPRtt)
	}
	if features.StatsTCPFailedConnections() {
		out = append(out, statsFeatureTCPFailedConnections)
	}
	if features.StatsTCPRetransmits() {
		out = append(out, statsFeatureTCPRetransmits)
	}
	if features.StatsTCPIo() {
		out = append(out, statsFeatureTCPIo)
	}
	return out
}

func captureLimits(cfg *obi.Config) map[string]any {
	return map[string]any{
		"network_packets":   cfg.NetworkFlows.CacheMaxFlows,
		"metric_span_names": cfg.Attributes.MetricSpanNameAggregationLimit,
	}
}

func captureEngine(cfg *obi.Config) map[string]any {
	return map[string]any{
		"debug": map[string]any{
			"bpf":            cfg.EBPF.BpfDebug,
			"protocol_print": cfg.EBPF.ProtocolDebug,
		},
		"pid_filter": map[string]any{
			"disabled": cfg.Discovery.BPFPidFilterOff,
		},
		"batching": map[string]any{
			"wakeup_len":    cfg.EBPF.WakeupLen,
			"batch_length":  cfg.EBPF.BatchLength,
			"batch_timeout": cfg.EBPF.BatchTimeout.String(),
		},
		"propagation": map[string]any{
			"context_propagation":      textValue(cfg.EBPF.ContextPropagation),
			"override_bpfloop_enabled": cfg.EBPF.OverrideBPFLoopEnabled,
			"disable_black_box_cp":     cfg.EBPF.DisableBlackBoxCP,
		},
		"traffic": map[string]any{
			"control_backend":     textValue(cfg.EBPF.TCBackend),
			"high_request_volume": cfg.EBPF.HighRequestVolume,
			"force_map_reader":    textValue(cfg.EBPF.ForceBPFMapReader),
		},
		"transactions": map[string]any{
			"max_duration": cfg.EBPF.MaxTransactionTime.String(),
		},
		"maps": map[string]any{
			"global_scale_factor": cfg.EBPF.MapsConfig.GlobalScaleFactor,
		},
		"bpf_filesystem": map[string]any{
			"path": cfg.EBPF.BPFFSPath,
		},
	}
}

func captureSafety(cfg *obi.Config) map[string]any {
	return map[string]any{
		"enforce_system_capabilities": cfg.EnforceSysCaps,
	}
}

func captureChannels(cfg *obi.Config) map[string]any {
	return map[string]any{
		"buffer_len":            cfg.ChannelBufferLen,
		"send_timeout":          cfg.ChannelSendTimeout.String(),
		"panic_on_send_timeout": cfg.ChannelSendTimeoutPanic,
	}
}

func captureTelemetry(cfg *obi.Config) map[string]any {
	return map[string]any{
		"traces": map[string]any{
			"reporters_cache_len": cfg.Traces.ReportersCacheLen,
		},
		"metrics": map[string]any{
			"reporters_cache_len": cfg.OTELMetrics.ReportersCacheLen,
			"ttl":                 cfg.OTELMetrics.TTL.String(),
		},
	}
}

func resource(cfg *obi.Config) map[string]any {
	attributes := map[string]any{}
	if cfg.Attributes.InstanceID.OverrideHostname != "" {
		attributes["host.name"] = cfg.Attributes.InstanceID.OverrideHostname
	}
	if cfg.Attributes.HostID.Override != "" {
		attributes["host.id"] = cfg.Attributes.HostID.Override
	}
	if len(attributes) == 0 {
		return map[string]any{}
	}
	return map[string]any{"attributes": attributes}
}

func tracerProvider(cfg *obi.Config) map[string]any {
	endpoint, _ := cfg.Traces.OTLPTracesEndpoint()
	out := map[string]any{
		"processors": []any{
			map[string]any{
				"batch": map[string]any{
					"max_queue_size":        cfg.Traces.QueueSize,
					"max_export_batch_size": cfg.Traces.BatchMaxSize,
					"schedule_delay":        cfg.Traces.BatchTimeout.Milliseconds(),
					"exporter": map[string]any{
						"otlp_grpc": map[string]any{
							"endpoint": endpoint,
							"retry": map[string]any{
								"initial_interval": cfg.Traces.BackOffInitialInterval.String(),
								"max_interval":     cfg.Traces.BackOffMaxInterval.String(),
								"max_elapsed_time": cfg.Traces.BackOffMaxElapsedTime.String(),
							},
							"tls": map[string]any{
								"insecure":             insecureOTLPTransport(endpoint),
								"insecure_skip_verify": cfg.Traces.InsecureSkipVerify,
							},
						},
					},
				},
			},
		},
	}
	if sampler := sampler(cfg); len(sampler) > 0 {
		out["sampler"] = sampler
	}
	return out
}

func sampler(cfg *obi.Config) map[string]any {
	out := map[string]any{}
	if cfg.Traces.SamplerConfig.Name != "" {
		out["name"] = cfg.Traces.SamplerConfig.Name
	}
	if cfg.Traces.SamplerConfig.Arg != "" {
		out["arg"] = cfg.Traces.SamplerConfig.Arg
	}
	return out
}

func meterProvider(cfg *obi.Config) map[string]any {
	endpoint, _ := cfg.OTELMetrics.OTLPMetricsEndpoint()
	return map[string]any{
		"readers": []any{
			map[string]any{
				"periodic": map[string]any{
					"interval": cfg.OTELMetrics.GetInterval().Milliseconds(),
					"exporter": map[string]any{
						"otlp_grpc": map[string]any{
							"endpoint":                      endpoint,
							"default_histogram_aggregation": cfg.OTELMetrics.HistogramAggregation,
							"tls": map[string]any{
								"insecure":             insecureOTLPTransport(endpoint),
								"insecure_skip_verify": cfg.OTELMetrics.InsecureSkipVerify,
							},
						},
					},
				},
			},
			map[string]any{
				"pull": map[string]any{
					"exporter": map[string]any{
						"prometheus/development": map[string]any{
							"port": cfg.Prometheus.Port,
						},
					},
				},
			},
		},
	}
}

func insecureOTLPTransport(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	return err == nil && parsed.Scheme == "http"
}

func enrich(cfg *obi.Config) map[string]any {
	return map[string]any{
		"enrichers": map[string]any{
			"kubernetes": map[string]any{
				"mode":                  cfg.Attributes.Kubernetes.Enable,
				"cluster_name":          cfg.Attributes.Kubernetes.ClusterName,
				"service_name_template": cfg.Attributes.Kubernetes.ServiceNameTemplate,
				"auth": map[string]any{
					"kubeconfig_path": cfg.Attributes.Kubernetes.KubeconfigPath,
				},
				"informers": map[string]any{
					"initial_sync_timeout":       cfg.Attributes.Kubernetes.InformersSyncTimeout.String(),
					"reconnect_initial_interval": cfg.Attributes.Kubernetes.ReconnectInitialInterval.String(),
					"resync_period":              cfg.Attributes.Kubernetes.InformersResyncPeriod.String(),
					"disabled":                   cfg.Attributes.Kubernetes.DisableInformers,
				},
				"drop_external":   cfg.Attributes.Kubernetes.DropExternal,
				"resource_labels": cfg.Attributes.Kubernetes.ResourceLabels,
				"metadata_cache": map[string]any{
					"address":             cfg.Attributes.Kubernetes.MetaCacheAddress,
					"restrict_local_node": cfg.Attributes.Kubernetes.MetaRestrictLocalNode,
					"source_labels": map[string]any{
						"service_name":      cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceName,
						"service_namespace": cfg.Attributes.Kubernetes.MetaSourceLabels.ServiceNamespace,
					},
				},
			},
		},
		"service_name": serviceNameEnrichment(cfg),
		"attributes": map[string]any{
			"select":                 cfg.Attributes.Select,
			"extra_group_attributes": cfg.Attributes.ExtraGroupAttributes,
			"metadata_retry": map[string]any{
				"timeout":        cfg.Attributes.MetadataRetry.Timeout.String(),
				"start_interval": cfg.Attributes.MetadataRetry.StartInterval.String(),
				"max_interval":   cfg.Attributes.MetadataRetry.MaxInterval.String(),
			},
		},
	}
}

func serviceNameEnrichment(cfg *obi.Config) map[string]any {
	out := map[string]any{
		"unresolved_hosts": map[string]any{
			"names": map[string]any{
				"default":  cfg.Attributes.RenameUnresolvedHosts,
				"outgoing": cfg.Attributes.RenameUnresolvedHostsOutgoing,
				"incoming": cfg.Attributes.RenameUnresolvedHostsIncoming,
			},
		},
	}
	if cfg.NameResolver == nil {
		out["sources"] = []any{}
		out["cache"] = map[string]any{
			"size": 0,
			"ttl":  "0s",
		}
		return out
	}

	out["sources"] = cfg.NameResolver.Sources
	out["cache"] = map[string]any{
		"size": cfg.NameResolver.CacheLen,
		"ttl":  cfg.NameResolver.CacheTTL.String(),
	}
	return out
}

func correlation(cfg *obi.Config) map[string]any {
	return map[string]any{
		"log_trace_annotation": map[string]any{
			"enabled": cfg.EBPF.LogEnricher.Enabled(),
			"filter":  map[string]any{},
			"cache": map[string]any{
				"ttl":  cfg.EBPF.LogEnricher.CacheTTL.String(),
				"size": cfg.EBPF.LogEnricher.CacheSize,
			},
			"async_writer": map[string]any{
				"workers":     cfg.EBPF.LogEnricher.AsyncWriterWorkers,
				"channel_len": cfg.EBPF.LogEnricher.AsyncWriterChannelLen,
			},
		},
	}
}

func daemon(cfg *obi.Config) map[string]any {
	return map[string]any{
		"logging": map[string]any{
			"level":              cfg.LogLevel,
			"format":             cfg.LogConfig,
			"debug_trace_output": cfg.TracePrinter,
		},
		"profiling": map[string]any{
			"port": cfg.ProfilePort,
		},
		"shutdown": map[string]any{
			"timeout": cfg.ShutdownTimeout.String(),
		},
		"internal_metrics": map[string]any{
			"exporter": cfg.InternalMetrics.Exporter,
			"prometheus": map[string]any{
				"port": cfg.InternalMetrics.Prometheus.Port,
				"path": cfg.InternalMetrics.Prometheus.Path,
			},
			"bpf": map[string]any{
				"scrape_interval": cfg.InternalMetrics.BpfMetricScrapeInterval.String(),
			},
		},
		"telemetry": map[string]any{
			"metrics": map[string]any{
				"prometheus": map[string]any{
					"allow_service_graph_self_references": cfg.Prometheus.AllowServiceGraphSelfReferences,
					"span_metrics_service_cache_size":     cfg.Prometheus.SpanMetricsServiceCacheSize,
					"extra_resource_attributes":           cfg.Prometheus.ExtraResourceLabels,
					"extra_span_resource_attributes":      mergedStrings(cfg.Prometheus.ExtraSpanResourceLabels, cfg.OTELMetrics.ExtraSpanResourceLabels),
				},
			},
		},
	}
}

func mergedStrings(values ...[]string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, list := range values {
		for _, value := range list {
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func textValue(v encoding.TextMarshaler) any {
	raw, err := v.MarshalText()
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}
