// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
	legacyyaml "gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
)

// MigrationNotice describes a deterministic structural rewrite performed while
// converting a v1 configuration.
type MigrationNotice struct {
	Source  string
	Message string
}

var environmentInterpolationPattern = regexp.MustCompile(
	`\$?\$[\{\(](?:env:)?[a-zA-Z_][a-zA-Z0-9_]*(?::-[^}\)]*)?[\}\)]`,
)

// MigrateV1YAML converts deterministic, file-only v1 configuration into the
// canonical config v2 document shape.
func MigrateV1YAML(data []byte) ([]byte, []MigrationNotice, error) {
	root, err := parseV1YAML(data)
	if err != nil {
		return nil, nil, err
	}
	if err := validateV1YAMLStructure(root); err != nil {
		return nil, nil, err
	}
	if containsEnvironmentInterpolation(root) {
		return nil, nil, errors.New(
			"environment interpolation is not supported during deterministic migration; resolve ${...} and $(...) values first",
		)
	}
	if legacyMappingValue(root, "extensions") != nil {
		return nil, nil, errors.New("input contains config v2 extensions; --from=v1 requires a v1 configuration")
	}

	cfg, err := loadV1FileConfig(data)
	if err != nil {
		return nil, nil, err
	}
	unsupported := unsupportedV1Paths(root)
	unsupported = append(unsupported, unsupportedRuntimePaths(root, cfg)...)
	slices.Sort(unsupported)
	unsupported = slices.Compact(unsupported)
	if len(unsupported) > 0 {
		return nil, nil, fmt.Errorf(
			"v1 fields outside the supported migration contract: %s",
			strings.Join(unsupported, ", "),
		)
	}

	doc, _ := RuntimeToV2(cfg)
	encoded, err := marshalMigratedDocument(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("encode config v2 document: %w", err)
	}
	parsed, _, err := schema.ParseStandaloneYAML(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("parse migrated config v2 document: %w", err)
	}
	if _, err := DocumentToRuntime(parsed); err != nil {
		return nil, nil, fmt.Errorf("import migrated config v2 document: %w", err)
	}

	return encoded, migrationNotices(root), nil
}

func marshalMigratedDocument(doc *schema.Document) ([]byte, error) {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	removeGeneratedAdditionalProperties(&node)

	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&node); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func removeGeneratedAdditionalProperties(node *yaml.Node) {
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return
	}

	for i := 0; i+1 < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "tracer_provider", "meter_provider":
			removeAdditionalProperties(node.Content[i+1])
		}
	}
}

func removeAdditionalProperties(node *yaml.Node) {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); {
			if node.Content[i].Value == "additionalproperties" {
				node.Content = append(node.Content[:i], node.Content[i+2:]...)
				continue
			}
			removeAdditionalProperties(node.Content[i+1])
			i += 2
		}
		return
	}
	for _, child := range node.Content {
		removeAdditionalProperties(child)
	}
}

func validateV1YAMLStructure(node *legacyyaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == legacyyaml.AliasNode {
		return errors.New("YAML aliases are not supported during deterministic migration")
	}
	if node.Kind == legacyyaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Tag == "!!merge" || key.Value == "<<" {
				return errors.New("YAML merge keys are not supported during deterministic migration")
			}
		}
	}
	for _, child := range node.Content {
		if err := validateV1YAMLStructure(child); err != nil {
			return err
		}
	}
	return nil
}

func containsEnvironmentInterpolation(node *legacyyaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == legacyyaml.ScalarNode &&
		environmentInterpolationPattern.MatchString(node.Value) {
		for _, match := range environmentInterpolationPattern.FindAllString(node.Value, -1) {
			if !strings.HasPrefix(match, "$$") {
				return true
			}
		}
	}
	for _, child := range node.Content {
		if containsEnvironmentInterpolation(child) {
			return true
		}
	}
	return false
}

func parseV1YAML(data []byte) (*legacyyaml.Node, error) {
	decoder := legacyyaml.NewDecoder(bytes.NewReader(data))
	var document legacyyaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse v1 configuration: %w", err)
	}
	var trailing legacyyaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("parse v1 configuration: multiple YAML documents are not supported")
		}
		return nil, fmt.Errorf("parse v1 configuration: %w", err)
	}
	if document.Kind == legacyyaml.DocumentNode && len(document.Content) > 0 {
		return document.Content[0], nil
	}
	return &document, nil
}

func loadV1FileConfig(data []byte) (*obi.Config, error) {
	cfg := obi.DefaultConfig
	if cfg.Routes != nil {
		routes := *cfg.Routes
		cfg.Routes = &routes
	}
	if cfg.NameResolver != nil {
		resolver := *cfg.NameResolver
		cfg.NameResolver = &resolver
	}

	decoder := legacyyaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode v1 configuration: %w", err)
	}

	cfg.Attributes.Select.Normalize()
	if cfg.OTELMetrics.EndpointEnabled() && cfg.OTELMetrics.DeprFeatures != 0 {
		cfg.Metrics.Features = cfg.OTELMetrics.DeprFeatures
	} else if cfg.Prometheus.EndpointEnabled() && cfg.Prometheus.DeprFeatures != 0 {
		cfg.Metrics.Features = cfg.Prometheus.DeprFeatures
	}
	if cfg.NetworkFlows.Enable {
		cfg.Metrics.Features |= export.FeatureNetwork
	}
	return &cfg, nil
}

func unsupportedV1Paths(root *legacyyaml.Node) []string {
	patterns := [][]string{
		{"attributes", "instance_id", "dns"},
		{"attributes", "sensitive_query_params"},
		{"discovery", "exclude_otel_instrumented_services_span_metrics"},
		{"discovery", "instrument", "*", "metrics"},
		{"discovery", "instrument", "*", "name"},
		{"discovery", "instrument", "*", "namespace"},
		{"discovery", "instrument", "*", "sampler"},
		{"discovery", "services", "*", "metrics"},
		{"discovery", "services", "*", "name"},
		{"discovery", "services", "*", "namespace"},
		{"discovery", "services", "*", "sampler"},
		{"ebpf", "log_enricher", "services"},
		{"ebpf", "stats_wakeup_data_bytes"},
		{"health_check"},
		{"internal_metrics", "avoided_services"},
		{"jvm_runtime_metrics"},
		{"otel_metrics_export", "allow_service_graph_self_references"},
		{"otel_metrics_export", "buckets"},
		{"otel_metrics_export", "exponential_histogram"},
		{"otel_metrics_export", "extra_span_resource_attributes"},
		{"otel_metrics_export", "insecure_skip_verify"},
		{"otel_metrics_export", "instrumentations"},
		{"otel_metrics_export", "otel_sdk_log_level"},
		{"otel_traces_export", "backoff_initial_interval"},
		{"otel_traces_export", "backoff_max_elapsed_time"},
		{"otel_traces_export", "backoff_max_interval"},
		{"otel_traces_export", "insecure_skip_verify"},
		{"otel_traces_export", "instrumentations"},
		{"otel_traces_export", "otel_sdk_log_level"},
		{"prometheus_export", "buckets"},
		{"prometheus_export", "disable_build_info"},
		{"prometheus_export", "exemplar_filter"},
		{"prometheus_export", "instrumentations"},
		{"prometheus_export", "native_histogram"},
		{"prometheus_export", "path"},
		{"prometheus_export", "ttl"},
		{"service_name"},
		{"service_namespace"},
	}

	var unsupported []string
	for _, pattern := range patterns {
		unsupported = append(unsupported, findV1Paths(root, pattern, "")...)
	}
	for _, path := range [][]string{{"routes"}, {"name_resolver"}} {
		node, source := v1NodeAtPath(root, path)
		if node != nil && node.Tag == "!!null" {
			unsupported = append(unsupported, source)
		}
	}
	unsupported = append(unsupported, unsupportedMetricFeaturePaths(root)...)
	return unsupported
}

func unsupportedMetricFeaturePaths(root *legacyyaml.Node) []string {
	patterns := [][]string{
		{"metrics", "features"},
		{"otel_metrics_export", "features"},
		{"prometheus_export", "features"},
	}
	allowed := map[string]struct{}{
		"application":                  {},
		"network":                      {},
		"stats":                        {},
		"stats_tcp_failed_connections": {},
		"stats_tcp_io":                 {},
		"stats_tcp_retransmits":        {},
		"stats_tcp_rtt":                {},
	}

	var unsupported []string
	for _, pattern := range patterns {
		node, path := v1NodeAtPath(root, pattern)
		if node == nil || node.Kind != legacyyaml.SequenceNode {
			continue
		}
		for i, feature := range node.Content {
			if _, ok := allowed[feature.Value]; !ok {
				unsupported = append(unsupported, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	return unsupported
}

func unsupportedRuntimePaths(root *legacyyaml.Node, cfg *obi.Config) []string {
	var unsupported []string
	traceProtocol, _ := v1NodeAtPath(root, []string{"otel_traces_export", "protocol"})
	if (cfg.Traces.Enabled() || traceProtocol != nil) && cfg.Traces.GetProtocol() != otelcfg.ProtocolGRPC {
		unsupported = append(unsupported, "otel_traces_export.protocol")
	}
	metricsProtocol, _ := v1NodeAtPath(root, []string{"otel_metrics_export", "protocol"})
	if (cfg.OTELMetrics.EndpointEnabled() || metricsProtocol != nil) &&
		cfg.OTELMetrics.GetProtocol() != otelcfg.ProtocolGRPC {
		unsupported = append(unsupported, "otel_metrics_export.protocol")
	}

	sampler := cfg.Traces.SamplerConfig
	switch sampler.Name {
	case "", services.SamplerAlwaysOn, services.SamplerAlwaysOff, services.SamplerParentBasedAlwaysOn, services.SamplerParentBasedAlwaysOff:
	case services.SamplerTraceIDRatio, services.SamplerParentBasedTraceIDRatio:
		ratio, err := strconv.ParseFloat(sampler.Arg, 64)
		if err != nil || math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 0 || ratio > 1 {
			unsupported = append(unsupported, "otel_traces_export.sampler.arg")
		}
	default:
		unsupported = append(unsupported, "otel_traces_export.sampler.name")
	}
	if path := unsupportedNetworkFeaturePath(root, cfg); path != "" {
		unsupported = append(unsupported, path)
	}
	return unsupported
}

func unsupportedNetworkFeaturePath(root *legacyyaml.Node, cfg *obi.Config) string {
	if cfg.Enabled(obi.FeatureNetO11y) || !cfg.Metrics.Features.AnyNetwork() {
		return ""
	}

	path := []string{"metrics", "features"}
	if cfg.OTELMetrics.EndpointEnabled() && cfg.OTELMetrics.DeprFeatures != 0 {
		path = []string{"otel_metrics_export", "features"}
	} else if cfg.Prometheus.EndpointEnabled() && cfg.Prometheus.DeprFeatures != 0 {
		path = []string{"prometheus_export", "features"}
	}
	node, source := v1NodeAtPath(root, path)
	if node == nil || node.Kind != legacyyaml.SequenceNode {
		return strings.Join(path, ".")
	}
	for i, feature := range node.Content {
		if feature.Value == "network" {
			return fmt.Sprintf("%s[%d]", source, i)
		}
	}
	return strings.Join(path, ".")
}

func migrationNotices(root *legacyyaml.Node) []MigrationNotice {
	rules := []struct {
		path    []string
		message string
	}{
		{path: []string{"executable_path"}, message: "rewrote the legacy selector as an extensions.obi.capture.rules entry"},
		{path: []string{"open_port"}, message: "rewrote the legacy selector as an extensions.obi.capture.rules entry"},
		{path: []string{"target_pids"}, message: "rewrote the legacy selector as an extensions.obi.capture.rules entry"},
		{path: []string{"discovery", "instrument"}, message: "moved selectors to extensions.obi.capture.rules"},
		{path: []string{"discovery", "services"}, message: "rewrote legacy selectors as extensions.obi.capture.rules"},
		{path: []string{"discovery", "exclude_services"}, message: "rewrote legacy selectors as extensions.obi.capture.rules"},
		{path: []string{"discovery", "exclude_otel_instrumented_services"}, message: "rewrote the exclusion as an extensions.obi.capture.rules entry"},
		{path: []string{"discovery", "excluded_linux_system_paths"}, message: "rewrote paths as extensions.obi.capture.rules entries"},
		{path: []string{"discovery", "skip_go_specific_tracers"}, message: "inverted into extensions.obi.capture.runtimes.go.enabled"},
		{path: []string{"filter", "application"}, message: "fanned out to protocol and signal filters"},
		{path: []string{"filter", "network"}, message: "fanned out to network signal filters"},
		{path: []string{"filter", "stats"}, message: "fanned out to stats signal filters"},
		{path: []string{"otel_metrics_export"}, message: "moved the metric pipeline to meter_provider"},
		{path: []string{"otel_metrics_export", "features"}, message: "applied the deprecated feature alias to capture enablement"},
		{path: []string{"otel_traces_export"}, message: "moved the trace pipeline to tracer_provider"},
		{path: []string{"prometheus_export", "features"}, message: "applied the deprecated feature alias to capture enablement"},
	}

	var notices []MigrationNotice
	for _, rule := range rules {
		paths := findV1Paths(root, rule.path, "")
		for _, path := range paths {
			notices = append(notices, MigrationNotice{Source: path, Message: rule.message})
		}
	}
	slices.SortFunc(notices, func(a, b MigrationNotice) int {
		if result := strings.Compare(a.Source, b.Source); result != 0 {
			return result
		}
		return strings.Compare(a.Message, b.Message)
	})
	return notices
}

func findV1Paths(node *legacyyaml.Node, pattern []string, prefix string) []string {
	if len(pattern) == 0 {
		return []string{prefix}
	}
	if pattern[0] == "*" {
		if node == nil || node.Kind != legacyyaml.SequenceNode {
			return nil
		}
		var paths []string
		for i, child := range node.Content {
			paths = append(paths, findV1Paths(child, pattern[1:], fmt.Sprintf("%s[%d]", prefix, i))...)
		}
		return paths
	}

	child := legacyMappingValue(node, pattern[0])
	if child == nil {
		return nil
	}
	next := pattern[0]
	if prefix != "" {
		next = prefix + "." + pattern[0]
	}
	return findV1Paths(child, pattern[1:], next)
}

func v1NodeAtPath(root *legacyyaml.Node, path []string) (*legacyyaml.Node, string) {
	node := root
	var parts []string
	for _, key := range path {
		node = legacyMappingValue(node, key)
		if node == nil {
			return nil, ""
		}
		parts = append(parts, key)
	}
	return node, strings.Join(parts, ".")
}

func legacyMappingValue(node *legacyyaml.Node, key string) *legacyyaml.Node {
	if node == nil || node.Kind != legacyyaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
