// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configload // import "go.opentelemetry.io/obi/cmd/obi/internal/configload"

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

// LoadSources merges explicitly supplied settings in increasing order of priority.
// The first source selects the runtime configuration semantics.
func LoadSources(sources []Source) (*obi.Config, string, error) {
	if len(sources) == 0 {
		return Load(nil)
	}

	if len(sources) == 1 {
		cfg, version, err := Load(sources[0].Data)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", sources[0].Path, err)
		}
		return cfg, version, nil
	}

	var base string
	var basePaths []string
	document := map[string]any{}
	pending := mixedOverrides{fields: map[string]func(*obi.Config, *obi.Config){}, document: map[string]any{}}
	for i, source := range sources {
		data := obicfg.ReplaceEnv(source.Data)
		_, _, err := schema.ParseStandaloneYAML(data)
		version := VersionV2
		if _, ok := errors.AsType[*schema.NotV2Error](err); ok {
			version = VersionV1
		} else if err != nil {
			return nil, "", fmt.Errorf("%s: %w", source.Path, err)
		}
		if i == 0 {
			base = version
		}
		values, err := readMapping(data)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", source.Path, err)
		}
		if version != base {
			if err := pending.add(base, version, values, source.Path); err != nil {
				return nil, "", fmt.Errorf("%s: %w", source.Path, err)
			}
			continue
		}

		for path := range pending.fields {
			if hasPath(values, path) {
				delete(pending.fields, path)
			}
		}
		if pending.tracerSource != "" && hasPath(values, "otel_traces_export") {
			return nil, "", fmt.Errorf("%s: otel_traces_export overlaps tracer_provider in %s", source.Path, pending.tracerSource)
		}
		mergeDocument(document, values)
		basePaths = append(basePaths, source.Path)
	}
	if base == VersionV2 && len(pending.fields) != 0 {
		if err := pending.mergeLegacyFields(document); err != nil {
			return nil, "", fmt.Errorf("%s: %w", strings.Join(pending.paths, ", "), err)
		}
		basePaths = append(basePaths, pending.paths...)
	}
	data, err := yaml.Marshal(document)
	if err != nil {
		return nil, "", err
	}
	var cfg *obi.Config
	if base == VersionV1 {
		cfg, err = obi.LoadConfigYAML(data, pending.apply)
	} else {
		cfg, err = loadV2Expanded(data)
	}
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", strings.Join(basePaths, ", "), err)
	}
	return cfg, base, nil
}

func (p *mixedOverrides) apply(cfg *obi.Config) error {
	if len(p.document) == 0 {
		return nil
	}
	data, err := yaml.Marshal(p.document)
	if err != nil {
		return err
	}
	doc, _, err := schema.ParseStandaloneYAML(data)
	if err != nil {
		return fmt.Errorf("%s: %w", strings.Join(p.paths, ", "), err)
	}
	layer, err := convert.DocumentToRuntime(doc)
	if err != nil {
		return fmt.Errorf("%s: %w", strings.Join(p.paths, ", "), err)
	}
	if err := convert.ApplyTracerProvider(cfg, doc.TracerProvider); err != nil {
		return fmt.Errorf("%s: tracer_provider: %w", p.tracerSource, err)
	}
	for _, apply := range p.fields {
		apply(cfg, layer)
	}
	return nil
}

// Decode only the winning legacy scalars. YAML null leaves a scalar at its
// legacy default. Putting those values into the v2 document before conversion
// also subjects them to the same checks as native v2 settings.
func (p *mixedOverrides) mergeLegacyFields(document map[string]any) error {
	layer := obi.DefaultConfig
	for _, setting := range sharedSettings {
		if _, ok := p.fields[setting.v2]; !ok {
			continue
		}
		if raw := p.document[setting.v1]; raw != nil {
			node, ok := raw.(*yaml.Node)
			if !ok {
				return fmt.Errorf("%s: expected a scalar", setting.v1)
			}
			if err := node.Decode(setting.field(&layer)); err != nil {
				return fmt.Errorf("%s: %w", setting.v1, err)
			}
		}
		parts := strings.Split(setting.v2, ".")
		last := len(parts) - 1
		value := map[string]any{parts[last]: setting.field(&layer)}
		for _, key := range slices.Backward(parts[:last]) {
			value = map[string]any{key: value}
		}
		mergeDocument(document, value)
	}
	return nil
}

// Keep YAML scalar tags and spelling until the version-specific loader decodes
// them. For example, an unquoted service name of 001 must not become 1.
type yamlValue struct{ value any }

func (v *yamlValue) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.MappingNode:
		var entries map[string]yamlValue
		if err := n.Decode(&entries); err != nil {
			return err
		}
		v.value = mappingValues(entries)
	case yaml.SequenceNode:
		var entries []yamlValue
		if err := n.Decode(&entries); err != nil {
			return err
		}
		values := make([]any, len(entries))
		for i := range entries {
			values[i] = entries[i].value
		}
		v.value = values
	default:
		scalar := *n
		scalar.Anchor = ""
		v.value = &scalar
	}
	return nil
}

func readMapping(data []byte) (map[string]any, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	// Validate aliases across the whole document before decoding individual
	// mappings, including legacy keys ignored by the v1 loader.
	var checked map[string]any
	if err := root.Decode(&checked); err != nil {
		return nil, err
	}
	var entries map[string]yamlValue
	if err := root.Decode(&entries); err != nil {
		return nil, err
	}
	return mappingValues(entries), nil
}

func mappingValues(entries map[string]yamlValue) map[string]any {
	values := make(map[string]any, len(entries))
	for k, v := range entries {
		values[k] = v.value
	}
	return values
}

func mergeDocument(dst, src map[string]any) {
	for key, value := range src {
		child, mapping := value.(map[string]any)
		old, exists := dst[key].(map[string]any)
		if mapping && exists && len(child) > 0 {
			mergeDocument(old, child)
		} else {
			dst[key] = value
		}
	}
}

func hasPath(values map[string]any, path string) bool {
	key, rest, nested := strings.Cut(path, ".")
	value, ok := values[key]
	if !ok || !nested {
		return ok
	}
	child, ok := value.(map[string]any)
	return !ok || len(child) == 0 || hasPath(child, rest)
}

type sharedSetting struct {
	v1, v2 string
	copy   func(dst, src *obi.Config)
	field  func(*obi.Config) any
}

func scalar[T any](v1, v2 string, field func(*obi.Config) *T) sharedSetting {
	return sharedSetting{
		v1: v1, v2: v2,
		copy:  func(dst, src *obi.Config) { *field(dst) = *field(src) },
		field: func(cfg *obi.Config) any { return field(cfg) },
	}
}

const extension = "extensions.obi."

var sharedSettings = []sharedSetting{
	scalar("channel_buffer_len", extension+"capture.channels.buffer_len", func(c *obi.Config) *int { return &c.ChannelBufferLen }),
	scalar("channel_send_timeout", extension+"capture.channels.send_timeout", func(c *obi.Config) *time.Duration { return &c.ChannelSendTimeout }),
	scalar("channel_send_timeout_panic", extension+"capture.channels.panic_on_send_timeout", func(c *obi.Config) *bool { return &c.ChannelSendTimeoutPanic }),
	scalar("shutdown_timeout", extension+"daemon.shutdown.timeout", func(c *obi.Config) *time.Duration { return &c.ShutdownTimeout }),
	scalar("log_level", "log_level", func(c *obi.Config) *obi.LogLevel { return &c.LogLevel }),
	scalar("log_format", extension+"daemon.logging.format", func(c *obi.Config) *obi.LogFormat { return &c.LogFormat }),
}

type mixedOverrides struct {
	fields       map[string]func(*obi.Config, *obi.Config)
	document     map[string]any
	paths        []string
	tracerSource string
}

func (p *mixedOverrides) add(base, version string, values map[string]any, source string) error {
	p.paths = append(p.paths, source)
	mergeDocument(p.document, values)
	if version == VersionV2 {
		delete(values, "file_format")
		if _, ok := values["tracer_provider"]; ok {
			p.tracerSource = source
			delete(values, "tracer_provider")
		}
	}
	return p.addFields(base, version, values, "")
}

func (p *mixedOverrides) addFields(base, version string, m map[string]any, prefix string) error {
	for _, key := range slices.Sorted(maps.Keys(m)) {
		path := prefix + key
		if version == VersionV2 && path == extension+"version" {
			continue
		}
		switch path {
		case "attributes.select", extension + "capture.attributes.select", extension + "enrich.attributes.select":
			return fmt.Errorf("%s: %s and %s use different attribute selection rules", path, version, base)
		case "otel_metrics_export.instrumentations", "prometheus_export.instrumentations":
			return fmt.Errorf("%s: v1 exporter instrumentation filters do not restrict derived metrics as v2 protocol switches do", path)
		}
		if strings.HasPrefix(path, extension+"capture.instrumentation.") && strings.HasSuffix(path, ".enabled.metrics") {
			return fmt.Errorf("%s: a v1 base cannot apply this protocol switch to derived metrics", path)
		}
		if child, ok := m[key].(map[string]any); ok && len(child) != 0 {
			if err := p.addFields(base, version, child, path+"."); err != nil {
				return err
			}
			continue
		}
		found := false
		for _, setting := range sharedSettings {
			source, target := setting.v1, setting.v2
			if version == VersionV2 {
				source, target = target, source
			}
			if path == source {
				p.fields[target] = setting.copy
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: cannot apply %s setting with %s semantics", path, version, base)
		}
	}
	return nil
}
