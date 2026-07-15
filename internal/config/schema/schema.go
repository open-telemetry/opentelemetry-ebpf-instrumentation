// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package schema parses OBI configuration documents that use the v2 schema.
//
// Callers choose the parser that matches the deployment target. The package does
// not auto-detect deployment mode because standalone and receiver deployments
// allow different sections:
//   - a full OpenTelemetry declarative configuration document with the OBI
//     extension at extensions.obi, parsed by ParseStandaloneYAML
//   - a receiver-embedded OBI configuration with version and capture sections at
//     the top level, parsed by ParseReceiverYAML
//
// This package validates only the version, shape, and deployment-specific
// section boundaries needed to route the configuration. OBI-owned extension
// sections are modeled locally as structs. OpenTelemetry-owned document sections
// are modeled with otelconf/x so the parser follows the upstream declarative
// configuration schema, including development sections.
package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"

	otelconfx "go.opentelemetry.io/contrib/otelconf/x"
)

const (
	// SupportedFileFormat is the OpenTelemetry declarative configuration file
	// format version handled by this package.
	SupportedFileFormat = "1.0"

	// SupportedVersion is the OBI configuration schema version handled by this
	// package.
	SupportedVersion = "2.0"
)

const (
	sectionEnrich      = "enrich"
	sectionCorrelation = "correlation"
	sectionDaemon      = "daemon"
)

// Document is the top-level OpenTelemetry declarative configuration document
// that contains extensions.obi.
//
// OBI-specific settings are available through Extensions.OBI. OpenTelemetry
// declarative configuration sections are modeled by otelconf/x so OBI follows
// the upstream schema surface instead of carrying a parallel local model.
type Document struct {
	otelconfx.OpenTelemetryConfiguration `yaml:",inline"`
	Extensions                           Extensions `yaml:"extensions"`
	logLevelSet                          bool
}

// UnmarshalYAML decodes OpenTelemetry-owned fields with otelconf/x and the OBI
// extension with the local schema model.
func (d *Document) UnmarshalYAML(node *yaml.Node) error {
	type extensionDocument struct {
		Extensions Extensions `yaml:"extensions"`
	}
	var ext extensionDocument
	_, logLevelSet := mappingValue(node, "log_level")
	if err := node.Decode(&d.OpenTelemetryConfiguration); err != nil {
		return err
	}
	if err := node.Decode(&ext); err != nil {
		return err
	}
	d.Extensions = ext.Extensions
	d.logLevelSet = logLevelSet
	return nil
}

// HasLogLevel reports whether the document explicitly declared top-level
// log_level. otelconf/x defaults omitted log_level to info, so callers need this
// signal to avoid treating the default as user intent.
func (d *Document) HasLogLevel() bool {
	return d != nil && d.logLevelSet
}

// SetLogLevel assigns a top-level log_level value and marks it as explicit.
func (d *Document) SetLogLevel(level otelconfx.SeverityNumber) {
	d.LogLevel = &level
	d.logLevelSet = true
}

// MarshalYAML emits the OpenTelemetry document fields and extensions. The
// explicit wrapper avoids relying on yaml inline behavior for a type with custom
// unmarshaling in the upstream otelconf/x package.
func (d Document) MarshalYAML() (any, error) {
	return struct {
		AttributeLimits            *otelconfx.AttributeLimits                   `yaml:"attribute_limits,omitempty"`
		Disabled                   otelconfx.OpenTelemetryConfigurationDisabled `yaml:"disabled,omitempty"`
		Distribution               otelconfx.Distribution                       `yaml:"distribution,omitempty"`
		FileFormat                 string                                       `yaml:"file_format"`
		InstrumentationDevelopment *otelconfx.ExperimentalInstrumentation       `yaml:"instrumentation/development,omitempty"`
		LogLevel                   *otelconfx.SeverityNumber                    `yaml:"log_level,omitempty"`
		LoggerProvider             *otelconfx.LoggerProvider                    `yaml:"logger_provider,omitempty"`
		MeterProvider              *otelconfx.MeterProvider                     `yaml:"meter_provider,omitempty"`
		Propagator                 *otelconfx.Propagator                        `yaml:"propagator,omitempty"`
		Resource                   *otelconfx.Resource                          `yaml:"resource,omitempty"`
		TracerProvider             *otelconfx.TracerProvider                    `yaml:"tracer_provider,omitempty"`
		Extensions                 Extensions                                   `yaml:"extensions"`
	}{
		AttributeLimits:            d.AttributeLimits,
		Disabled:                   d.Disabled,
		Distribution:               d.Distribution,
		FileFormat:                 d.FileFormat,
		InstrumentationDevelopment: d.InstrumentationDevelopment,
		LogLevel:                   d.LogLevel,
		LoggerProvider:             d.LoggerProvider,
		MeterProvider:              d.MeterProvider,
		Propagator:                 d.Propagator,
		Resource:                   d.Resource,
		TracerProvider:             d.TracerProvider,
		Extensions:                 d.Extensions,
	}, nil
}

// Extensions holds declarative configuration extensions recognized by this
// package.
type Extensions struct {
	OBI *Extension `yaml:"obi"`
}

// Extension is the OBI v2 extension configuration.
//
// Capture is valid in all deployment modes. Enrich, Correlation, and Daemon are
// standalone-only sections and are rejected when parsing receiver-embedded
// configuration. ParseReceiverYAML synthesizes this shape from top-level receiver
// capture sections.
type Extension struct {
	Version     string       `yaml:"version"`
	Capture     Capture      `yaml:"capture"`
	Enrich      *Enrich      `yaml:"enrich,omitempty"`
	Correlation *Correlation `yaml:"correlation,omitempty"`
	Daemon      *Daemon      `yaml:"daemon,omitempty"`
}

// receiverConfig mirrors the receiver-embedded layout, where capture sections
// appear beside version at the top level instead of under an extension.capture
// object.
type receiverConfig struct {
	Version string `yaml:"version"`
	Capture `yaml:",inline"`
}

// ParseStandaloneYAML decodes a standalone OBI v2 declarative document.
//
// The document must contain extensions.obi.version equal to SupportedVersion.
// Missing v2 markers return NotV2Error; present but unsupported markers return
// UnsupportedVersionError.
func ParseStandaloneYAML(data []byte) (*Document, *Extension, error) {
	root, err := parseYAML(data)
	if err != nil {
		return nil, nil, err
	}

	if version, ok := nestedScalar(root, "extensions", "obi", "version"); ok {
		if version != SupportedVersion {
			return nil, nil, &UnsupportedVersionError{Version: version}
		}
		var doc Document
		if err := decode(root, &doc); err != nil {
			return nil, nil, err
		}
		if err := validateFileFormat(doc.FileFormat); err != nil {
			return nil, nil, err
		}
		if doc.Extensions.OBI == nil {
			return nil, nil, &NotV2Error{Reason: "missing extensions.obi"}
		}
		if err := ValidateStandalone(doc.Extensions.OBI); err != nil {
			return nil, nil, err
		}
		return &doc, doc.Extensions.OBI, nil
	}

	if version, ok := nestedVersion(root, "extensions", "obi", "version"); ok {
		return nil, nil, &UnsupportedVersionError{Version: version}
	}

	if _, ok := nestedVersion(root, "version"); ok {
		return nil, nil, &NotV2Error{Reason: "missing extensions.obi.version field"}
	}

	if looksLikeV1(root) {
		return nil, nil, &NotV2Error{Reason: "detected legacy v1 config shape"}
	}

	return nil, nil, &NotV2Error{Reason: "missing extensions.obi.version field"}
}

// ParseReceiverYAML decodes a receiver-embedded OBI v2 configuration.
//
// Receiver capture sections are accepted at the top level and normalized into
// Extension.Capture. Standalone-only keys are rejected by presence before decode
// so null or malformed values still report SectionNotAllowedError.
func ParseReceiverYAML(data []byte) (*Extension, error) {
	root, err := parseYAML(data)
	if err != nil {
		return nil, err
	}

	if _, ok := nestedNode(root, "extensions", "obi"); ok {
		return nil, &ReceiverLayoutError{}
	}

	disallowedSection, hasDisallowedSection := disallowedReceiverSection(root)

	if version, ok := nestedScalar(root, "version"); ok {
		if version != SupportedVersion {
			return nil, &UnsupportedVersionError{Version: version}
		}
		if hasDisallowedSection {
			return nil, &SectionNotAllowedError{Section: disallowedSection}
		}
		var receiver receiverConfig
		if err := decode(root, &receiver); err != nil {
			return nil, err
		}
		cfg := Extension{
			Version: receiver.Version,
			Capture: receiver.Capture,
		}
		if err := ValidateReceiver(&cfg); err != nil {
			return nil, err
		}
		return &cfg, nil
	}

	if version, ok := nestedVersion(root, "version"); ok {
		return nil, &UnsupportedVersionError{Version: version}
	}

	if hasDisallowedSection {
		return nil, &SectionNotAllowedError{Section: disallowedSection}
	}

	if looksLikeV1(root) {
		return nil, &NotV2Error{Reason: "detected legacy v1 config shape"}
	}

	return nil, &NotV2Error{Reason: "missing top-level OBI v2 version field"}
}

// ValidateStandalone checks version support for a standalone OBI extension.
func ValidateStandalone(cfg *Extension) error {
	return validateVersion(cfg)
}

// ValidateReceiver checks version support and receiver section boundaries for an
// already decoded OBI extension.
func ValidateReceiver(cfg *Extension) error {
	if err := validateVersion(cfg); err != nil {
		return err
	}
	if cfg.Enrich != nil {
		return &SectionNotAllowedError{Section: sectionEnrich}
	}
	if cfg.Correlation != nil {
		return &SectionNotAllowedError{Section: sectionCorrelation}
	}
	if cfg.Daemon != nil {
		return &SectionNotAllowedError{Section: sectionDaemon}
	}
	return nil
}

func validateVersion(cfg *Extension) error {
	if cfg == nil {
		return errors.New("missing OBI config")
	}
	if cfg.Version != SupportedVersion {
		return &UnsupportedVersionError{Version: cfg.Version}
	}
	return nil
}

func validateFileFormat(fileFormat string) error {
	if fileFormat != SupportedFileFormat {
		return &UnsupportedFileFormatError{FileFormat: fileFormat}
	}
	return nil
}

func disallowedReceiverSection(root *yaml.Node) (string, bool) {
	if _, ok := mappingValue(root, sectionEnrich); ok {
		return sectionEnrich, true
	}
	if _, ok := mappingValue(root, sectionCorrelation); ok {
		return sectionCorrelation, true
	}
	if _, ok := mappingValue(root, sectionDaemon); ok {
		return sectionDaemon, true
	}
	return "", false
}

func looksLikeV1(root *yaml.Node) bool {
	for _, key := range []string{
		"ebpf",
		"discovery",
		"otel_metrics_export",
		"otel_traces_export",
		"prometheus_export",
		"attributes",
		"routes",
		"stats",
		"javaagent",
	} {
		if _, ok := mappingValue(root, key); ok {
			return true
		}
	}
	return false
}

func parseYAML(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing config v2 YAML: %w", err)
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0], nil
	}
	return &doc, nil
}

func decode(node *yaml.Node, dst any) error {
	if err := node.Decode(dst); err != nil {
		return fmt.Errorf("decoding config v2 YAML: %w", err)
	}
	return nil
}

func nestedScalar(root *yaml.Node, path ...string) (string, bool) {
	value, ok := nestedNode(root, path...)
	if !ok || value.Kind != yaml.ScalarNode || value.ShortTag() != "!!str" {
		return "", false
	}
	return value.Value, true
}

func nestedVersion(root *yaml.Node, path ...string) (string, bool) {
	value, ok := nestedNode(root, path...)
	if !ok {
		return "", false
	}
	if value.Kind == yaml.ScalarNode {
		return value.Value, true
	}
	return value.ShortTag(), true
}

func nestedNode(root *yaml.Node, path ...string) (*yaml.Node, bool) {
	cur := root
	for _, key := range path {
		next, ok := mappingValue(cur, key)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func mappingValue(node *yaml.Node, key string) (*yaml.Node, bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i < len(node.Content)-1; i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1], true
		}
	}
	return nil, false
}
