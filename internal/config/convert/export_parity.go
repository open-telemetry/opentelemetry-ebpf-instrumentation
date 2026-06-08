// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"strings"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
)

func resource(cfg *obi.Config) map[string]any {
	out := map[string]any{}
	if cfg.Attributes.InstanceID.OverrideHostname != "" {
		out["host.name"] = cfg.Attributes.InstanceID.OverrideHostname
	}
	if cfg.Attributes.HostID.Override != "" {
		out["host.id"] = cfg.Attributes.HostID.Override
	}
	return out
}

func tracerProvider(cfg *obi.Config) map[string]any {
	out := map[string]any{
		"processors": []any{
			map[string]any{
				"batch": map[string]any{
					"max_export_batch_size": cfg.Traces.BatchMaxSize,
					"max_queue_size":        cfg.Traces.QueueSize,
					"schedule_delay":        cfg.Traces.BatchTimeout.Milliseconds(),
					"exporter": map[string]any{
						"otlp_grpc": map[string]any{
							"endpoint": cfg.Traces.TracesEndpoint,
							"retry": map[string]any{
								"initial_interval": cfg.Traces.BackOffInitialInterval.String(),
								"max_interval":     cfg.Traces.BackOffMaxInterval.String(),
								"max_elapsed_time": cfg.Traces.BackOffMaxElapsedTime.String(),
							},
							"tls": map[string]any{
								"insecure": cfg.Traces.InsecureSkipVerify,
							},
						},
					},
				},
			},
		},
	}

	if sampler := sampler(cfg.Traces.SamplerConfig); sampler != nil {
		out["sampler"] = sampler
	}

	return out
}

func meterProvider(cfg *obi.Config) map[string]any {
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

func captureTelemetry(cfg *obi.Config) map[string]any {
	return map[string]any{
		"traces": map[string]any{
			"reporters_cache_len": cfg.Traces.ReportersCacheLen,
		},
		"metrics": map[string]any{
			"ttl":                 cfg.OTELMetrics.TTL.String(),
			"reporters_cache_len": cfg.OTELMetrics.ReportersCacheLen,
		},
	}
}

func httpRoutes(cfg *obi.Config) map[string]any {
	out := map[string]any{
		"unmatched":                    "",
		"patterns":                     []string{},
		"ignored_patterns":             []string{},
		"ignore_mode":                  "",
		"wildcard_char":                "",
		"max_path_segment_cardinality": 0,
		"discovery": map[string]any{
			"timeout":            cfg.Discovery.RouteHarvesterTimeout.String(),
			"disabled_languages": cfg.Discovery.DisabledRouteHarvesters,
			"java": map[string]any{
				"delay": cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay.String(),
			},
		},
	}
	if cfg.Routes == nil {
		return out
	}

	out["unmatched"] = cfg.Routes.Unmatch
	out["patterns"] = cfg.Routes.Patterns
	out["ignored_patterns"] = cfg.Routes.IgnorePatterns
	out["ignore_mode"] = cfg.Routes.IgnoredEvents
	out["wildcard_char"] = cfg.Routes.WildcardChar
	out["max_path_segment_cardinality"] = cfg.Routes.MaxPathSegmentCardinality
	return out
}

func payloadExtraction(cfg *obi.Config) map[string]any {
	http := cfg.EBPF.PayloadExtraction.HTTP
	enabled := []string{}
	if http.GraphQL.Enabled {
		enabled = append(enabled, "graphql")
	}
	if http.Elasticsearch.Enabled {
		enabled = append(enabled, "elasticsearch")
	}
	if http.AWS.Enabled {
		enabled = append(enabled, "aws")
	}
	if http.SQLPP.Enabled {
		enabled = append(enabled, "sqlpp")
	}
	if http.GenAI.OpenAI.Enabled {
		enabled = append(enabled, "openai")
	}
	if http.GenAI.Anthropic.Enabled {
		enabled = append(enabled, "anthropic")
	}
	if http.GenAI.Gemini.Enabled {
		enabled = append(enabled, "gemini")
	}
	if http.GenAI.Qwen.Enabled {
		enabled = append(enabled, "qwen")
	}
	if http.GenAI.Bedrock.Enabled {
		enabled = append(enabled, "bedrock")
	}
	if http.GenAI.MCP.Enabled {
		enabled = append(enabled, "mcp")
	}
	if http.GenAI.Embedding.Enabled {
		enabled = append(enabled, "embedding")
	}
	if http.GenAI.Rerank.Enabled {
		enabled = append(enabled, "rerank")
	}
	if http.GenAI.Retrieval.Enabled {
		enabled = append(enabled, "retrieval")
	}
	if http.JSONRPC.Enabled {
		enabled = append(enabled, "jsonrpc")
	}
	if http.Enrichment.Enabled {
		enabled = append(enabled, "enrichment")
	}

	return map[string]any{
		"enabled": enabled,
		"sqlpp": map[string]any{
			"endpoint_patterns": http.SQLPP.EndpointPatterns,
		},
		"enrichment": httpEnrichment(cfg),
	}
}

func httpEnrichment(cfg *obi.Config) map[string]any {
	enrichment := cfg.EBPF.PayloadExtraction.HTTP.Enrichment
	return map[string]any{
		"policy": map[string]any{
			"default_action": map[string]any{
				"headers": textValue(enrichment.Policy.DefaultAction.Headers),
				"body":    textValue(enrichment.Policy.DefaultAction.Body),
			},
			"obfuscation_string": enrichment.Policy.ObfuscationString,
		},
		"rules": enrichment.Rules,
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
		if def.Equals != nil {
			entry["equals"] = *def.Equals
		}
		if def.NotEquals != nil {
			entry["not_equals"] = *def.NotEquals
		}
		if def.GreaterEquals != nil {
			entry["greater_equals"] = *def.GreaterEquals
		}
		if def.GreaterThan != nil {
			entry["greater_than"] = *def.GreaterThan
		}
		if def.LessEquals != nil {
			entry["less_equals"] = *def.LessEquals
		}
		if def.LessThan != nil {
			entry["less_than"] = *def.LessThan
		}
		out[key] = entry
	}
	return out
}

func networkFlowEnrichment(cfg *obi.Config) map[string]any {
	return map[string]any{
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
	}
}

func statsEnrichment(cfg *obi.Config) map[string]any {
	return map[string]any{
		"geo_ip": map[string]any{
			"ipinfo": map[string]any{
				"path": cfg.Stats.GeoIP.IPInfo.Path,
			},
			"maxmind": map[string]any{
				"country_path": cfg.Stats.GeoIP.MaxMindInfo.CountryPath,
				"asn_path":     cfg.Stats.GeoIP.MaxMindInfo.ASNPath,
			},
			"cache": map[string]any{
				"size": cfg.Stats.GeoIP.CacheLen,
				"ttl":  cfg.Stats.GeoIP.CacheTTL.String(),
			},
		},
		"reverse_dns": map[string]any{
			"mode": cfg.Stats.ReverseDNS.Type,
			"cache": map[string]any{
				"size": cfg.Stats.ReverseDNS.CacheLen,
				"ttl":  cfg.Stats.ReverseDNS.CacheTTL.String(),
			},
		},
	}
}

func rulesFromRuntime(cfg *obi.Config) []schema.Rule {
	rules := []schema.Rule{}
	rules = appendSelectorRules(rules, "exclude", cfg.Discovery.DefaultExcludeInstrument, defaultExcludeRule)
	rules = appendSelectorRules(rules, "exclude", cfg.Discovery.ExcludeInstrument, nil)
	rules = appendSelectorRules(rules, "include", cfg.Discovery.Instrument, nil)

	if cfg.Discovery.ExcludeOTelInstrumentedServices {
		rules = append(rules, schema.Rule{
			Action:      "exclude",
			Name:        "exclude-otlp-exporters",
			Description: "Exclude services that already export OTLP to prevent duplicate telemetry pipelines.",
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

	if len(cfg.Discovery.ExcludedLinuxSystemPaths) > 0 {
		globs := make([]string, 0, len(cfg.Discovery.ExcludedLinuxSystemPaths))
		for _, path := range cfg.Discovery.ExcludedLinuxSystemPaths {
			globs = append(globs, path+"*")
		}
		rules = append(rules, schema.Rule{
			Action:      "exclude",
			Name:        "exclude-linux-system-paths",
			Description: "Exclude Linux system/service executable paths that are not typical application workloads.",
			Match: map[string]any{
				"process": map[string]any{
					"exe_path_glob": globs,
				},
			},
		})
	}

	return rules
}

type defaultRuleFunc func(int, map[string]any) (string, string)

func appendSelectorRules(
	rules []schema.Rule,
	action string,
	selectors services.GlobDefinitionCriteria,
	defaultRule defaultRuleFunc,
) []schema.Rule {
	for i, selector := range selectors {
		match := selectorMatch(selector)
		if len(match) == 0 {
			continue
		}

		rule := schema.Rule{
			Action: action,
			Match:  match,
		}
		if defaultRule != nil {
			rule.Name, rule.Description = defaultRule(i, match)
		}
		rule.Refine = selectorRefinement(action, selector)
		rules = append(rules, rule)
	}
	return rules
}

func selectorMatch(selector services.GlobAttributes) map[string]any {
	match := map[string]any{}
	process := map[string]any{}
	kubernetes := map[string]any{}

	if selector.OpenPorts.Len() > 0 {
		process["open_ports"] = selector.OpenPorts
	}
	if len(selector.PIDs) > 0 {
		process["target_pids"] = selector.PIDs
	}
	if selector.Languages.IsSet() {
		process["language_glob"] = globList(selector.Languages)
	}
	if selector.CmdArgs.IsSet() {
		process["cmd_args_glob"] = globList(selector.CmdArgs)
	}
	if selector.Path.IsSet() {
		process["exe_path_glob"] = globList(selector.Path)
	}
	if selector.ContainersOnly {
		process["containers_only"] = true
	}

	if namespace := selector.Metadata[services.AttrNamespace]; namespace != nil && namespace.IsSet() {
		kubernetes["namespace_glob"] = globList(*namespace)
	}
	if labels := globMap(selector.PodLabels); len(labels) > 0 {
		kubernetes["pod_labels"] = labels
	}
	if annotations := globMap(selector.PodAnnotations); len(annotations) > 0 {
		kubernetes["pod_annotations"] = annotations
	}

	if len(process) > 0 {
		match["process"] = process
	}
	if len(kubernetes) > 0 {
		match["kubernetes"] = kubernetes
	}
	return match
}

func selectorRefinement(action string, selector services.GlobAttributes) schema.RuleRefinement {
	refine := schema.RuleRefinement{}
	if action != "include" {
		return refine
	}
	if exports := exportModeRefinement(selector.ExportModes); exports != nil {
		refine.Exports = exports
	}
	if selector.Routes != nil {
		patterns := append([]string{}, selector.Routes.Incoming...)
		patterns = append(patterns, selector.Routes.Outgoing...)
		refine.HTTP = map[string]any{
			"routes": map[string]any{
				"patterns": patterns,
			},
		}
	}
	return refine
}

func exportModeRefinement(modes services.ExportModes) map[string]any {
	if modes == services.ExportModeUnset {
		return nil
	}
	return map[string]any{
		"traces":  modes.CanExportTraces(),
		"metrics": modes.CanExportMetrics(),
	}
}

func defaultExcludeRule(index int, match map[string]any) (string, string) {
	if index == 0 {
		return "exclude-obi-and-collectors",
			"Exclude OBI and collector binaries to avoid self-instrumentation and collector recursion."
	}
	if index == 1 {
		return "exclude-system-namespaces",
			"Exclude common platform/system Kubernetes namespaces from instrumentation by default."
	}
	if _, ok := match["kubernetes"]; ok {
		return "exclude-system-namespaces",
			"Exclude common platform/system Kubernetes namespaces from instrumentation by default."
	}
	return "exclude-obi-and-collectors",
		"Exclude OBI and collector binaries to avoid self-instrumentation and collector recursion."
}

func enrich(cfg *obi.Config) map[string]any {
	nameResolver := map[string]any{
		"sources": []any{},
		"cache": map[string]any{
			"size": 0,
			"ttl":  "0s",
		},
	}
	if cfg.NameResolver != nil {
		nameResolver["sources"] = cfg.NameResolver.Sources
		nameResolver["cache"] = map[string]any{
			"size": cfg.NameResolver.CacheLen,
			"ttl":  cfg.NameResolver.CacheTTL.String(),
		}
	}
	nameResolver["unresolved_hosts"] = map[string]any{
		"names": map[string]any{
			"default":  cfg.Attributes.RenameUnresolvedHosts,
			"outgoing": cfg.Attributes.RenameUnresolvedHostsOutgoing,
			"incoming": cfg.Attributes.RenameUnresolvedHostsIncoming,
		},
	}

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
		"service_name": nameResolver,
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

func globMap(values map[string]*services.GlobAttr) map[string]any {
	out := make(map[string]any, len(values))
	for key, value := range values {
		if value == nil || !value.IsSet() {
			continue
		}
		out[key] = globList(*value)
	}
	return out
}

func globList(value services.GlobAttr) []string {
	raw := globString(value)
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
		body := strings.TrimSuffix(strings.TrimPrefix(raw, "{"), "}")
		if !strings.ContainsAny(body, "{}") {
			return strings.Split(body, ",")
		}
	}
	return []string{raw}
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

func sampler(cfg services.SamplerConfig) map[string]any {
	out := map[string]any{}
	if cfg.Name != "" {
		out["name"] = cfg.Name
	}
	if cfg.Arg != "" {
		out["arg"] = cfg.Arg
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
