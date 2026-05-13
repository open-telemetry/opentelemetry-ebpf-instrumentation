// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obiconfigv2 // import "go.opentelemetry.io/obi/internal/obiconfigv2"

import (
	"errors"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	obiv2 "go.opentelemetry.io/obi/pkg/obiconfig/v2"
)

func RuntimeToDocument(cfg *obi.Config) (*obiv2.Document, error) {
	if cfg == nil {
		return nil, errors.New("missing runtime config")
	}

	doc := &obiv2.Document{
		FileFormat:     "1.0",
		Resource:       map[string]any{},
		Propagator:     map[string]any{},
		TracerProvider: tracerProviderMap(cfg),
		MeterProvider:  meterProviderMap(cfg),
		Extensions: obiv2.Extensions{
			OBI: &obiv2.Extension{
				Version:     obiv2.SupportedVersion,
				Capture:     captureConfig(cfg),
				Enrich:      enrichMap(cfg),
				Correlation: correlationMap(cfg),
				Daemon:      daemonMap(cfg),
			},
		},
	}

	raw, err := toMap(doc)
	if err != nil {
		return nil, err
	}
	doc.Raw = raw
	doc.Extensions.OBI.Raw = nestedMap(raw, "extensions", "obi")
	return doc, nil
}

func RuntimeToReceiverExtension(cfg *obi.Config) (*obiv2.Extension, error) {
	doc, err := RuntimeToDocument(cfg)
	if err != nil {
		return nil, err
	}
	out := *doc.Extensions.OBI
	out.Enrich = nil
	out.Correlation = nil
	out.Daemon = nil
	return &out, nil
}

func captureConfig(cfg *obi.Config) obiv2.CaptureConfig {
	instrumentation := map[string]any{
		"http": map[string]any{
			"enabled":               map[string]any{"traces": true, "metrics": true},
			"filters":               signalFilters(cfg.Filters.Application),
			"track_request_headers": cfg.EBPF.TrackRequestHeaders,
			"request_timeout":       cfg.EBPF.HTTPRequestTimeout.String(),
			"buffer_size":           cfg.EBPF.BufferSizes.HTTP,
			"routes": map[string]any{
				"unmatched":                    cfg.Routes.Unmatch,
				"patterns":                     cfg.Routes.Patterns,
				"ignored_patterns":             cfg.Routes.IgnorePatterns,
				"ignore_mode":                  cfg.Routes.IgnoredEvents,
				"wildcard_char":                cfg.Routes.WildcardChar,
				"max_path_segment_cardinality": cfg.Routes.MaxPathSegmentCardinality,
				"discovery": map[string]any{
					"timeout":            cfg.Discovery.RouteHarvesterTimeout.String(),
					"disabled_languages": cfg.Discovery.DisabledRouteHarvesters,
					"java": map[string]any{
						"delay": cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay.String(),
					},
				},
			},
			"payload_extraction": payloadExtractionMap(cfg),
		},
		"grpc": map[string]any{
			"enabled": map[string]any{"traces": true, "metrics": true},
			"filters": signalFilters(cfg.Filters.Application),
		},
		"sql": map[string]any{
			"enabled":          map[string]any{"traces": true, "metrics": true},
			"filters":          signalFilters(cfg.Filters.Application),
			"heuristic_detect": cfg.EBPF.HeuristicSQLDetect,
			"mysql": map[string]any{
				"buffer_size":                    cfg.EBPF.BufferSizes.MySQL,
				"prepared_statements_cache_size": cfg.EBPF.MySQLPreparedStatementsCacheSize,
			},
			"postgres": map[string]any{
				"buffer_size":                    cfg.EBPF.BufferSizes.Postgres,
				"prepared_statements_cache_size": cfg.EBPF.PostgresPreparedStatementsCacheSize,
			},
		},
		"redis": map[string]any{
			"enabled": map[string]any{"traces": true, "metrics": true},
			"filters": signalFilters(cfg.Filters.Application),
			"db_cache": map[string]any{
				"enabled":  cfg.EBPF.RedisDBCache.Enabled,
				"max_size": cfg.EBPF.RedisDBCache.MaxSize,
			},
		},
		"kafka": map[string]any{
			"enabled":               map[string]any{"traces": true, "metrics": true},
			"filters":               signalFilters(cfg.Filters.Application),
			"buffer_size":           cfg.EBPF.BufferSizes.Kafka,
			"topic_uuid_cache_size": cfg.EBPF.KafkaTopicUUIDCacheSize,
		},
		"mongo": map[string]any{
			"enabled":             map[string]any{"traces": true, "metrics": true},
			"filters":             signalFilters(cfg.Filters.Application),
			"requests_cache_size": cfg.EBPF.MongoRequestsCacheSize,
		},
		"couchbase": map[string]any{
			"enabled":       map[string]any{"traces": true, "metrics": true},
			"filters":       signalFilters(cfg.Filters.Application),
			"db_cache_size": cfg.EBPF.CouchbaseDBCacheSize,
		},
		"dns": map[string]any{
			"enabled":         map[string]any{"traces": false, "metrics": false},
			"filters":         signalFilters(cfg.Filters.Application),
			"request_timeout": cfg.EBPF.DNSRequestTimeout.String(),
		},
		"gpu": map[string]any{
			"enabled":      map[string]any{"traces": true, "metrics": true},
			"filters":      signalFilters(cfg.Filters.Application),
			"enabled_mode": cfg.EBPF.InstrumentCuda,
		},
	}

	return obiv2.CaptureConfig{
		Policy: map[string]any{
			"default_action":  "include",
			"match_order":     "first_match_wins",
			"poll_interval":   cfg.Discovery.PollInterval.String(),
			"min_process_age": cfg.Discovery.MinProcessAge.String(),
		},
		Rules:           rulesFromRuntime(cfg),
		Instrumentation: instrumentation,
		Runtimes: map[string]any{
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
		},
		Network: map[string]any{
			"capture": map[string]any{
				"enabled": cfg.NetworkFlows.Enable,
				"source":  cfg.NetworkFlows.Source,
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
					"sampling": cfg.NetworkFlows.Sampling,
				},
				"interface_discovery": map[string]any{
					"mode":          cfg.NetworkFlows.ListenInterfaces,
					"poll_interval": cfg.NetworkFlows.ListenPollPeriod.String(),
				},
				"enrichment": map[string]any{
					"geo_ip": map[string]any{
						"ipinfo": map[string]any{
							"path": cfg.NetworkFlows.GeoIP.IPInfo.Path,
						},
						"maxmind": map[string]any{
							"country_path": cfg.NetworkFlows.GeoIP.MaxMindInfo.CountryPath,
							"asn_path":     cfg.NetworkFlows.GeoIP.MaxMindInfo.ASNPath,
						},
						"cache": map[string]any{
							"size": cfg.NetworkFlows.GeoIP.CacheLen,
							"ttl":  cfg.NetworkFlows.GeoIP.CacheTTL.String(),
						},
					},
					"reverse_dns": map[string]any{
						"mode": cfg.NetworkFlows.ReverseDNS.Type,
						"cache": map[string]any{
							"size": cfg.NetworkFlows.ReverseDNS.CacheLen,
							"ttl":  cfg.NetworkFlows.ReverseDNS.CacheTTL.String(),
						},
					},
				},
				"diagnostics": map[string]any{
					"print_flows": cfg.NetworkFlows.Print,
				},
			},
		},
		Limits: map[string]any{
			"network_packets":   cfg.NetworkFlows.CacheMaxFlows,
			"metric_span_names": cfg.Attributes.MetricSpanNameAggregationLimit,
		},
		Engine: map[string]any{
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
				"context_propagation":      cfg.EBPF.ContextPropagation,
				"override_bpfloop_enabled": cfg.EBPF.OverrideBPFLoopEnabled,
			},
			"traffic": map[string]any{
				"control_backend":     cfg.EBPF.TCBackend,
				"high_request_volume": cfg.EBPF.HighRequestVolume,
			},
			"transactions": map[string]any{
				"max_duration": cfg.EBPF.MaxTransactionTime.String(),
			},
			"bpf_filesystem": map[string]any{
				"path": cfg.EBPF.BPFFSPath,
			},
		},
		Safety: map[string]any{
			"enforce_system_capabilities": cfg.EnforceSysCaps,
		},
		Channels: map[string]any{
			"buffer_len":            cfg.ChannelBufferLen,
			"send_timeout":          cfg.ChannelSendTimeout.String(),
			"panic_on_send_timeout": cfg.ChannelSendTimeoutPanic,
		},
		Telemetry: map[string]any{
			"traces": map[string]any{
				"reporters_cache_len": cfg.Traces.ReportersCacheLen,
			},
			"metrics": map[string]any{
				"ttl":                 cfg.OTELMetrics.TTL.String(),
				"reporters_cache_len": cfg.OTELMetrics.ReportersCacheLen,
			},
		},
	}
}

func payloadExtractionMap(cfg *obi.Config) map[string]any {
	enabled := []string{}
	if cfg.EBPF.PayloadExtraction.HTTP.GraphQL.Enabled {
		enabled = append(enabled, "graphql")
	}
	if cfg.EBPF.PayloadExtraction.HTTP.Elasticsearch.Enabled {
		enabled = append(enabled, "elasticsearch")
	}
	if cfg.EBPF.PayloadExtraction.HTTP.AWS.Enabled {
		enabled = append(enabled, "aws")
	}
	if cfg.EBPF.PayloadExtraction.HTTP.SQLPP.Enabled {
		enabled = append(enabled, "sqlpp")
	}
	return map[string]any{
		"enabled": enabled,
		"sqlpp": map[string]any{
			"endpoint_patterns": cfg.EBPF.PayloadExtraction.HTTP.SQLPP.EndpointPatterns,
		},
	}
}

func signalFilters(in filter.AttributeFamilyConfig) map[string]any {
	return map[string]any{
		"traces":  filterMap(in),
		"metrics": filterMap(in),
	}
}

func filterMap(in filter.AttributeFamilyConfig) map[string]any {
	out := map[string]any{}
	for key, def := range in {
		entry := map[string]any{}
		if def.Match != "" {
			entry["match"] = def.Match
		}
		if def.NotMatch != "" {
			entry["not_match"] = def.NotMatch
		}
		out[key] = entry
	}
	return out
}

func rulesFromRuntime(cfg *obi.Config) []obiv2.Rule {
	rules := []obiv2.Rule{}
	for _, selector := range cfg.Discovery.ExcludeInstrument {
		if selector.Path.IsSet() {
			rules = append(rules, obiv2.Rule{
				Action: "exclude",
				Match: map[string]any{
					"process": map[string]any{
						"exe_path_glob": []string{globString(selector.Path)},
					},
				},
			})
		}
		if namespace := selector.Metadata[services.AttrNamespace]; namespace != nil && namespace.IsSet() {
			rules = append(rules, obiv2.Rule{
				Action: "exclude",
				Match: map[string]any{
					"kubernetes": map[string]any{
						"namespace_glob": []string{globString(*namespace)},
					},
				},
			})
		}
	}
	if cfg.Discovery.ExcludeOTelInstrumentedServices {
		rules = append(rules, obiv2.Rule{
			Action: "exclude",
			Name:   "exclude-otlp-exporters",
			Match: map[string]any{
				"process": map[string]any{
					"exports_otlp": map[string]any{
						"port":     cfg.Discovery.DefaultOtlpGRPCPort,
						"protocol": "protobuf",
					},
				},
			},
		})
	}
	for _, path := range cfg.Discovery.ExcludedLinuxSystemPaths {
		rules = append(rules, obiv2.Rule{
			Action: "exclude",
			Name:   "exclude-linux-system-paths",
			Match: map[string]any{
				"process": map[string]any{
					"exe_path_glob": []string{path + "*"},
				},
			},
		})
	}
	return rules
}

func enrichMap(cfg *obi.Config) map[string]any {
	return map[string]any{
		"enrichers": map[string]any{
			"kubernetes": map[string]any{
				"mode":         cfg.Attributes.Kubernetes.Enable,
				"cluster_name": cfg.Attributes.Kubernetes.ClusterName,
				"auth": map[string]any{
					"kubeconfig_path": cfg.Attributes.Kubernetes.KubeconfigPath,
				},
				"informers": map[string]any{
					"initial_sync_timeout": cfg.Attributes.Kubernetes.InformersSyncTimeout.String(),
					"resync_period":        cfg.Attributes.Kubernetes.InformersResyncPeriod.String(),
					"disabled":             cfg.Attributes.Kubernetes.DisableInformers,
				},
				"drop_external": cfg.Attributes.Kubernetes.DropExternal,
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
		"service_name": map[string]any{
			"cache": map[string]any{
				"size": cfg.NameResolver.CacheLen,
				"ttl":  cfg.NameResolver.CacheTTL.String(),
			},
			"unresolved_hosts": map[string]any{
				"names": map[string]any{
					"default":  cfg.Attributes.RenameUnresolvedHosts,
					"outgoing": cfg.Attributes.RenameUnresolvedHostsOutgoing,
					"incoming": cfg.Attributes.RenameUnresolvedHostsIncoming,
				},
			},
		},
		"attributes": map[string]any{},
	}
}

func correlationMap(cfg *obi.Config) map[string]any {
	return map[string]any{
		"log_trace_annotation": map[string]any{
			"enabled": len(cfg.EBPF.LogEnricher.Services) > 0,
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

func daemonMap(cfg *obi.Config) map[string]any {
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
					"extra_span_resource_attributes":      cfg.Prometheus.ExtraSpanResourceLabels,
				},
			},
		},
	}
}

func tracerProviderMap(cfg *obi.Config) map[string]any {
	out := map[string]any{
		"processors": []any{
			map[string]any{
				"batch": map[string]any{
					"max_queue_size": cfg.Traces.QueueSize,
					"schedule_delay": cfg.Traces.BatchTimeout.Milliseconds(),
					"exporter": map[string]any{
						"otlp_grpc": map[string]any{
							"endpoint": cfg.Traces.TracesEndpoint,
							"tls": map[string]any{
								"insecure": cfg.Traces.InsecureSkipVerify,
							},
						},
					},
				},
			},
		},
	}

	if sampler := samplerMap(cfg.Traces.SamplerConfig); sampler != nil {
		out["sampler"] = sampler
	}

	return out
}

func meterProviderMap(cfg *obi.Config) map[string]any {
	return map[string]any{
		"readers": []any{
			map[string]any{
				"periodic": map[string]any{
					"interval": cfg.OTELMetrics.OTELIntervalMS,
					"exporter": map[string]any{
						"otlp_grpc": map[string]any{
							"endpoint":                      cfg.OTELMetrics.MetricsEndpoint,
							"default_histogram_aggregation": cfg.OTELMetrics.HistogramAggregation,
							"tls": map[string]any{
								"insecure": cfg.OTELMetrics.InsecureSkipVerify,
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

func toMap(v any) (map[string]any, error) {
	data, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func globString(g services.GlobAttr) string {
	value, err := g.MarshalYAML()
	if err != nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

func samplerMap(cfg services.SamplerConfig) map[string]any {
	out := map[string]any{}
	if cfg.Name != "" {
		out["name"] = cfg.Name
	}
	if cfg.Arg != "" {
		out["arg"] = cfg.Arg
	}
	if cfg.OBIRuleBased != nil {
		out["obi_rule_based"] = map[string]any{
			"fallback": samplerLeafMap(cfg.OBIRuleBased.Fallback),
			"rules":    samplerRulesMap(cfg.OBIRuleBased.Rules),
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func samplerLeafMap(cfg services.SamplerLeafConfig) map[string]any {
	out := map[string]any{}
	if cfg.Name != "" {
		out["name"] = cfg.Name
	}
	if cfg.Arg != "" {
		out["arg"] = cfg.Arg
	}
	return out
}

func samplerRulesMap(rules []services.OBIRuleBasedSamplerRule) []any {
	if len(rules) == 0 {
		return nil
	}

	out := make([]any, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]any{
			"match": map[string]any{
				"resource_attributes": rule.Match.ResourceAttributes,
			},
			"action": samplerLeafMap(rule.Action),
		})
	}
	return out
}
