// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package schema parses OBI configuration documents that use the v2 schema.
//
// The parser recognizes both supported layouts:
//   - a full OpenTelemetry declarative configuration document with the OBI
//     extension at extensions.obi
//   - a receiver-embedded OBI configuration with version and capture sections at
//     the top level
//
// This package validates only the version, shape, and deployment-specific
// section boundaries needed to route the configuration. It intentionally leaves
// nested OBI sections as map values so migration and validation layers can
// preserve and inspect the original keys.
package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// SupportedVersion is the OBI configuration schema version handled by this
// package.
const SupportedVersion = "2.0"

type validationMode string

const (
	validationModeStandalone validationMode = "standalone"
	validationModeReceiver   validationMode = "receiver"
)

// Document is the top-level OpenTelemetry declarative configuration document
// that contains extensions.obi.
//
// OBI-specific settings are available through Extensions.OBI. Other declarative
// configuration sections are retained as maps because this package only needs to
// locate and validate the OBI extension. Raw aliases the decoded YAML map passed
// to ParseStandaloneMap, or the map decoded by ParseStandaloneYAML.
type Document struct {
	FileFormat     string         `yaml:"file_format"`
	Resource       map[string]any `yaml:"resource"`
	Propagator     map[string]any `yaml:"propagator"`
	TracerProvider map[string]any `yaml:"tracer_provider"`
	MeterProvider  map[string]any `yaml:"meter_provider"`
	Extensions     Extensions     `yaml:"extensions"`
	Raw            map[string]any `yaml:"-"`
}

// Extensions holds declarative configuration extensions recognized by this
// package.
type Extensions struct {
	OBI *Extension `yaml:"obi"`
}

// Extension is the OBI v2 extension configuration.
//
// Capture is valid in all deployment modes. Enrich, Correlation, and Daemon are
// standalone-only sections and are rejected when validating receiver mode. Raw
// aliases the source map for this extension in full documents and the top-level
// source map in receiver-embedded configurations.
type Extension struct {
	Version     string         `yaml:"version"`
	Capture     Capture        `yaml:"capture"`
	Enrich      map[string]any `yaml:"enrich,omitempty"`
	Correlation map[string]any `yaml:"correlation,omitempty"`
	Daemon      map[string]any `yaml:"daemon,omitempty"`
	Raw         map[string]any `yaml:"-"`
}

// Capture contains receiver-embeddable OBI capture settings.
//
// The individual sections remain map values so callers can preserve unknown
// fields and apply schema-specific validation or migration elsewhere. Raw aliases
// the source capture map in full documents and the synthesized capture map in
// receiver-embedded configurations.
type Capture struct {
	Policy          map[string]any `yaml:"policy"`
	Rules           []Rule         `yaml:"rules"`
	Instrumentation map[string]any `yaml:"instrumentation"`
	Runtimes        map[string]any `yaml:"runtimes"`
	Network         map[string]any `yaml:"network"`
	Limits          map[string]any `yaml:"limits"`
	Engine          map[string]any `yaml:"engine"`
	Safety          map[string]any `yaml:"safety"`
	Channels        map[string]any `yaml:"channels"`
	Telemetry       map[string]any `yaml:"telemetry"`
	Raw             map[string]any `yaml:"-"`
}

// Rule describes one capture policy rule.
type Rule struct {
	Action      string         `yaml:"action"`
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Match       map[string]any `yaml:"match"`
	Refine      RuleRefinement `yaml:"refine"`
}

// RuleRefinement holds per-rule overrides that apply after a rule matches.
type RuleRefinement struct {
	Exports map[string]any `yaml:"exports,omitempty"`
	HTTP    map[string]any `yaml:"http,omitempty"`
}

// ParseStandaloneYAML decodes a standalone OBI v2 declarative document.
func ParseStandaloneYAML(data []byte) (*Document, *Extension, error) {
	raw, err := parseYAML(data)
	if err != nil {
		return nil, nil, err
	}

	return ParseStandaloneMap(raw)
}

// ParseStandaloneMap parses a standalone OBI v2 declarative document.
func ParseStandaloneMap(raw map[string]any) (*Document, *Extension, error) {
	if len(raw) == 0 {
		return nil, nil, &NotV2Error{Reason: "missing extensions.obi.version field"}
	}

	if version, ok := nestedString(raw, "extensions", "obi", "version"); ok {
		if version != SupportedVersion {
			return nil, nil, &UnsupportedVersionError{Version: version}
		}
		return parseDocument(raw)
	}

	if version, ok := nestedValue(raw, "extensions", "obi", "version"); ok {
		return nil, nil, &UnsupportedVersionError{Version: fmt.Sprint(version)}
	}

	if _, ok := nestedValue(raw, "version"); ok {
		return nil, nil, &NotV2Error{Reason: "missing extensions.obi.version field"}
	}

	if looksLikeV1(raw) {
		return nil, nil, &NotV2Error{Reason: "detected legacy v1 config shape"}
	}

	return nil, nil, &NotV2Error{Reason: "missing extensions.obi.version field"}
}

// ParseReceiverYAML decodes a receiver-embedded OBI v2 configuration.
func ParseReceiverYAML(data []byte) (*Extension, error) {
	raw, err := parseYAML(data)
	if err != nil {
		return nil, err
	}

	return ParseReceiverMap(raw)
}

// ParseReceiverMap parses a receiver-embedded OBI v2 configuration.
func ParseReceiverMap(raw map[string]any) (*Extension, error) {
	if len(raw) == 0 {
		return nil, &NotV2Error{Reason: "missing top-level OBI v2 version field"}
	}

	if version, ok := nestedString(raw, "version"); ok {
		if version != SupportedVersion {
			return nil, &UnsupportedVersionError{Version: version}
		}
		return parseReceiver(raw)
	}

	if version, ok := nestedValue(raw, "version"); ok {
		return nil, &UnsupportedVersionError{Version: fmt.Sprint(version)}
	}

	if looksLikeV1(raw) {
		return nil, &NotV2Error{Reason: "detected legacy v1 config shape"}
	}

	return nil, &NotV2Error{Reason: "missing top-level OBI v2 version field"}
}

// ValidateStandalone checks version support for a standalone OBI extension.
func ValidateStandalone(cfg *Extension) error {
	return validate(cfg, validationModeStandalone)
}

// ValidateReceiver checks version support and receiver section boundaries.
func ValidateReceiver(cfg *Extension) error {
	return validate(cfg, validationModeReceiver)
}

// validate checks version support and deployment-specific section boundaries for
// an already decoded OBI extension.
func validate(cfg *Extension, mode validationMode) error {
	if cfg == nil {
		return errors.New("missing OBI config")
	}
	if cfg.Version != SupportedVersion {
		return &UnsupportedVersionError{Version: cfg.Version}
	}
	if mode == validationModeReceiver {
		for _, section := range []string{"enrich", "correlation", "daemon"} {
			if hasStandaloneSection(cfg, section) {
				return &SectionNotAllowedError{Mode: string(mode), Section: section}
			}
		}
	}
	return nil
}

// parseDocument decodes the full declarative layout and wires Raw fields to the
// corresponding source maps.
func parseDocument(raw map[string]any) (*Document, *Extension, error) {
	var doc Document
	if err := decode(raw, &doc); err != nil {
		return nil, nil, err
	}
	doc.Raw = raw
	if doc.Extensions.OBI == nil {
		return nil, nil, &NotV2Error{Reason: "missing extensions.obi"}
	}

	doc.Extensions.OBI.Raw = nestedMap(raw, "extensions", "obi")
	doc.Extensions.OBI.Capture.Raw = nestedMap(raw, "extensions", "obi", "capture")
	if err := ValidateStandalone(doc.Extensions.OBI); err != nil {
		return nil, nil, err
	}
	return &doc, doc.Extensions.OBI, nil
}

// parseReceiver adapts the receiver-embedded layout into Extension. Capture
// sections are accepted at the top level in receiver configuration files, but the
// resulting value uses the same Extension shape as full documents.
func parseReceiver(raw map[string]any) (*Extension, error) {
	receiver := map[string]any{
		"version":     raw["version"],
		"capture":     map[string]any{},
		"enrich":      raw["enrich"],
		"correlation": raw["correlation"],
		"daemon":      raw["daemon"],
	}

	capture := receiver["capture"].(map[string]any)
	for _, key := range captureKeys() {
		if value, ok := raw[key]; ok {
			capture[key] = value
		}
	}

	var cfg Extension
	if err := decode(receiver, &cfg); err != nil {
		return nil, err
	}
	cfg.Raw = raw
	cfg.Capture.Raw = capture
	if err := ValidateReceiver(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func hasStandaloneSection(cfg *Extension, section string) bool {
	if cfg.Raw != nil {
		_, ok := cfg.Raw[section]
		return ok
	}

	switch section {
	case "enrich":
		return cfg.Enrich != nil
	case "correlation":
		return cfg.Correlation != nil
	case "daemon":
		return cfg.Daemon != nil
	default:
		return false
	}
}

func looksLikeV1(raw map[string]any) bool {
	for _, key := range []string{
		"ebpf",
		"discovery",
		"otel_metrics_export",
		"otel_traces_export",
		"prometheus_export",
		"attributes",
		"routes",
		"network",
		"stats",
		"javaagent",
	} {
		if _, ok := raw[key]; ok {
			return true
		}
	}
	return false
}

// captureKeys lists top-level receiver-embedded sections that belong under
// Extension.Capture in the normalized representation.
func captureKeys() []string {
	return []string{
		"policy",
		"rules",
		"instrumentation",
		"runtimes",
		"network",
		"limits",
		"engine",
		"safety",
		"channels",
		"telemetry",
	}
}

func parseYAML(data []byte) (map[string]any, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing config v2 YAML: %w", err)
	}
	return raw, nil
}

func decode(raw map[string]any, dst any) error {
	buf, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshaling config v2 YAML: %w", err)
	}
	if err := yaml.Unmarshal(buf, dst); err != nil {
		return fmt.Errorf("decoding config v2 YAML: %w", err)
	}
	return nil
}

func nestedMap(raw map[string]any, path ...string) map[string]any {
	value, ok := nestedValue(raw, path...)
	if !ok {
		return nil
	}
	result, _ := value.(map[string]any)
	return result
}

func nestedString(raw map[string]any, path ...string) (string, bool) {
	value, ok := nestedValue(raw, path...)
	if !ok {
		return "", false
	}
	result, ok := value.(string)
	return result, ok
}

func nestedValue(raw map[string]any, path ...string) (any, bool) {
	cur := any(raw)
	for _, key := range path {
		next, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = next[key]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
