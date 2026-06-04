// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

const SupportedVersion = "2.0"

type DeploymentMode string

const (
	DeploymentModeStandalone DeploymentMode = "standalone"
	DeploymentModeReceiver   DeploymentMode = "receiver"
)

type Document struct {
	FileFormat     string         `yaml:"file_format"`
	Resource       map[string]any `yaml:"resource"`
	Propagator     map[string]any `yaml:"propagator"`
	TracerProvider map[string]any `yaml:"tracer_provider"`
	MeterProvider  map[string]any `yaml:"meter_provider"`
	Extensions     Extensions     `yaml:"extensions"`
	Raw            map[string]any `yaml:"-"`
}

type Extensions struct {
	OBI *Extension `yaml:"obi"`
}

type Extension struct {
	Version     string         `yaml:"version"`
	Capture     Capture        `yaml:"capture"`
	Enrich      map[string]any `yaml:"enrich,omitempty"`
	Correlation map[string]any `yaml:"correlation,omitempty"`
	Daemon      map[string]any `yaml:"daemon,omitempty"`
	Raw         map[string]any `yaml:"-"`
}

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

type Rule struct {
	Action      string         `yaml:"action"`
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Match       map[string]any `yaml:"match"`
	Refine      RuleRefinement `yaml:"refine"`
}

type RuleRefinement struct {
	Exports map[string]any `yaml:"exports,omitempty"`
	HTTP    map[string]any `yaml:"http,omitempty"`
}

type NotV2Error struct {
	Reason string
}

func (e *NotV2Error) Error() string {
	if e == nil || e.Reason == "" {
		return "configuration is not OBI config v2"
	}
	return "configuration is not OBI config v2: " + e.Reason
}

func (e *NotV2Error) Is(target error) bool {
	_, ok := target.(*NotV2Error)
	return ok
}

type UnsupportedVersionError struct {
	Version string
}

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("unsupported OBI config version %q", e.Version)
}

type SectionNotAllowedError struct {
	Mode    DeploymentMode
	Section string
}

func (e *SectionNotAllowedError) Error() string {
	if e.Mode == DeploymentModeReceiver {
		return fmt.Sprintf(
			"section %q is not allowed in %s mode; remove it from the receiver config or run this config in standalone mode",
			e.Section,
			e.Mode,
		)
	}
	return fmt.Sprintf("section %q is not allowed in %s mode", e.Section, e.Mode)
}

func ParseYAML(data []byte, mode DeploymentMode) (*Document, *Extension, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("parsing config v2 YAML: %w", err)
	}

	return ParseMap(raw, mode)
}

func ParseMap(raw map[string]any, mode DeploymentMode) (*Document, *Extension, error) {
	if len(raw) == 0 {
		return nil, nil, &NotV2Error{Reason: "missing OBI v2 version field"}
	}

	if version, ok := nestedString(raw, "extensions", "obi", "version"); ok {
		if version != SupportedVersion {
			return nil, nil, &UnsupportedVersionError{Version: version}
		}
		return parseDocument(raw, mode)
	}

	if version, ok := nestedString(raw, "version"); ok {
		if version != SupportedVersion {
			return nil, nil, &UnsupportedVersionError{Version: version}
		}
		return parseReceiver(raw, mode)
	}

	if version, ok := nestedValue(raw, "extensions", "obi", "version"); ok {
		return nil, nil, &UnsupportedVersionError{Version: fmt.Sprint(version)}
	}

	if version, ok := nestedValue(raw, "version"); ok {
		return nil, nil, &UnsupportedVersionError{Version: fmt.Sprint(version)}
	}

	if looksLikeV1(raw) {
		return nil, nil, &NotV2Error{Reason: "detected legacy v1 config shape"}
	}

	return nil, nil, &NotV2Error{Reason: "missing OBI v2 version field"}
}

func Validate(cfg *Extension, mode DeploymentMode) error {
	if cfg == nil {
		return errors.New("missing OBI config")
	}
	if cfg.Version != SupportedVersion {
		return &UnsupportedVersionError{Version: cfg.Version}
	}
	if mode == DeploymentModeReceiver {
		for _, section := range []string{"enrich", "correlation", "daemon"} {
			if hasStandaloneSection(cfg, section) {
				return &SectionNotAllowedError{Mode: mode, Section: section}
			}
		}
	}
	return nil
}

func parseDocument(raw map[string]any, mode DeploymentMode) (*Document, *Extension, error) {
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
	if err := Validate(doc.Extensions.OBI, mode); err != nil {
		return nil, nil, err
	}
	return &doc, doc.Extensions.OBI, nil
}

func parseReceiver(raw map[string]any, mode DeploymentMode) (*Document, *Extension, error) {
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
		return nil, nil, err
	}
	cfg.Raw = raw
	cfg.Capture.Raw = capture
	if err := Validate(&cfg, mode); err != nil {
		return nil, nil, err
	}
	return nil, &cfg, nil
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
