// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"strings"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
)

func httpRoutes(cfg *obi.Config) map[string]any {
	out := map[string]any{
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

const (
	payloadExtractorGraphQL       = "graphql"
	payloadExtractorElasticsearch = "elasticsearch"
	payloadExtractorAWS           = "aws"
	payloadExtractorSQLPP         = "sqlpp"
	payloadExtractorOpenAI        = "openai"
	payloadExtractorAnthropic     = "anthropic"
	payloadExtractorGemini        = "gemini"
	payloadExtractorQwen          = "qwen"
	payloadExtractorBedrock       = "bedrock"
	payloadExtractorMCP           = "mcp"
	payloadExtractorEmbedding     = "embedding"
	payloadExtractorRerank        = "rerank"
	payloadExtractorRetrieval     = "retrieval"
	payloadExtractorJSONRPC       = "jsonrpc"
	payloadExtractorEnrichment    = "enrichment"
)

func payloadExtraction(cfg *obi.Config) map[string]any {
	http := cfg.EBPF.PayloadExtraction.HTTP
	enabled := []string{}
	if http.GraphQL.Enabled {
		enabled = append(enabled, payloadExtractorGraphQL)
	}
	if http.Elasticsearch.Enabled {
		enabled = append(enabled, payloadExtractorElasticsearch)
	}
	if http.AWS.Enabled {
		enabled = append(enabled, payloadExtractorAWS)
	}
	if http.SQLPP.Enabled {
		enabled = append(enabled, payloadExtractorSQLPP)
	}
	if http.GenAI.OpenAI.Enabled {
		enabled = append(enabled, payloadExtractorOpenAI)
	}
	if http.GenAI.Anthropic.Enabled {
		enabled = append(enabled, payloadExtractorAnthropic)
	}
	if http.GenAI.Gemini.Enabled {
		enabled = append(enabled, payloadExtractorGemini)
	}
	if http.GenAI.Qwen.Enabled {
		enabled = append(enabled, payloadExtractorQwen)
	}
	if http.GenAI.Bedrock.Enabled {
		enabled = append(enabled, payloadExtractorBedrock)
	}
	if http.GenAI.MCP.Enabled {
		enabled = append(enabled, payloadExtractorMCP)
	}
	if http.GenAI.Embedding.Enabled {
		enabled = append(enabled, payloadExtractorEmbedding)
	}
	if http.GenAI.Rerank.Enabled {
		enabled = append(enabled, payloadExtractorRerank)
	}
	if http.GenAI.Retrieval.Enabled {
		enabled = append(enabled, payloadExtractorRetrieval)
	}
	if http.JSONRPC.Enabled {
		enabled = append(enabled, payloadExtractorJSONRPC)
	}
	if http.Enrichment.Enabled {
		enabled = append(enabled, payloadExtractorEnrichment)
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
	if discover.OnlyDefinesDeprecatedServiceSelection(cfg) {
		rules = appendSelectorRules(rules, "exclude", discover.RegexAsSelector(cfg.Discovery.ExcludeServices), nil)
		rules = appendSelectorRules(rules, "exclude", discover.RegexAsSelector(cfg.Discovery.DefaultExcludeServices), defaultExcludeRule)
	} else {
		rules = appendSelectorRules(rules, "exclude", discover.GlobsAsSelector(cfg.Discovery.ExcludeInstrument), nil)
		rules = appendSelectorRules(rules, "exclude", discover.GlobsAsSelector(cfg.Discovery.DefaultExcludeInstrument), defaultExcludeRule)
	}

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
			globs = append(globs, strings.TrimRight(path, "/")+"/*")
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

	rules = appendSelectorRules(rules, "include", discover.FindingCriteria(cfg), nil)

	return rules
}

type defaultRuleFunc func(int, map[string]any) (string, string)

func appendSelectorRules(
	rules []schema.Rule,
	action string,
	selectors []services.Selector,
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

func selectorMatch(selector services.Selector) map[string]any {
	switch selector := selector.(type) {
	case *services.GlobAttributes:
		return globSelectorMatch(selector)
	case *services.RegexSelector:
		return regexSelectorMatch(selector)
	default:
		return nil
	}
}

func globSelectorMatch(selector *services.GlobAttributes) map[string]any {
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
	if metadata := globMetadataMap(selector.Metadata); len(metadata) > 0 {
		kubernetes["metadata_glob"] = metadata
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

func regexSelectorMatch(selector *services.RegexSelector) map[string]any {
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
		process["language_regex"] = regexString(selector.Languages)
	}
	if selector.CmdArgs.IsSet() {
		process["cmd_args_regex"] = regexString(selector.CmdArgs)
	}
	switch {
	case selector.Path.IsSet():
		process["exe_path_regex"] = regexString(selector.Path)
	case selector.PathRegexp.IsSet():
		process["exe_path_regex"] = regexString(selector.PathRegexp)
	}
	if selector.ContainersOnly {
		process["containers_only"] = true
	}

	if namespace := selector.Metadata[services.AttrNamespace]; namespace != nil && namespace.IsSet() {
		kubernetes["namespace_regex"] = regexString(*namespace)
	}
	if metadata := regexMetadataMap(selector.Metadata); len(metadata) > 0 {
		kubernetes["metadata_regex"] = metadata
	}
	if labels := regexMap(selector.PodLabels); len(labels) > 0 {
		kubernetes["pod_labels_regex"] = labels
	}
	if annotations := regexMap(selector.PodAnnotations); len(annotations) > 0 {
		kubernetes["pod_annotations_regex"] = annotations
	}

	if len(process) > 0 {
		match["process"] = process
	}
	if len(kubernetes) > 0 {
		match["kubernetes"] = kubernetes
	}
	return match
}

func selectorRefinement(action string, selector services.Selector) schema.RuleRefinement {
	refine := schema.RuleRefinement{}
	if action != "include" {
		return refine
	}
	if exports := exportModeRefinement(selector.GetExportModes()); exports != nil {
		refine.Exports = exports
	}
	// TODO(#2251): add a direction-aware v2 route refinement shape for selector routes.
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

func globMetadataMap(values services.MetadataGlobMap) map[string]any {
	out := make(map[string]any, len(values))
	for key, value := range values {
		if key == services.AttrNamespace || value == nil || !value.IsSet() {
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

func regexMap(values map[string]*services.RegexpAttr) map[string]any {
	out := make(map[string]any, len(values))
	for key, value := range values {
		if value == nil || !value.IsSet() {
			continue
		}
		out[key] = regexString(*value)
	}
	return out
}

func regexMetadataMap(values services.MetadataRegexMap) map[string]any {
	out := make(map[string]any, len(values))
	for key, value := range values {
		if key == services.AttrNamespace || value == nil || !value.IsSet() {
			continue
		}
		out[key] = regexString(*value)
	}
	return out
}

func regexString(r services.RegexpAttr) string {
	value, err := r.MarshalYAML()
	if err != nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}
