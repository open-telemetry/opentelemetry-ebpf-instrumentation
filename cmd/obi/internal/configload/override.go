// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configload // import "go.opentelemetry.io/obi/cmd/obi/internal/configload"

import (
	"fmt"
	"maps"
	"slices"
	"strings"

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

	var cfg *obi.Config
	var base string
	document := map[string]any{}
	pending := mixedOverrides{fields: map[string]func(*obi.Config){}}
	for i, source := range sources {
		data := obicfg.ReplaceEnv(source.Data)
		layer, version, err := loadExpanded(data)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", source.Path, err)
		}
		if len(sources) == 1 {
			return layer, version, nil
		}
		if i == 0 {
			base = version
		}
		values, err := readMapping(data)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", source.Path, err)
		}
		if version != base {
			if err := pending.add(base, version, values, layer, source.Path); err != nil {
				return nil, "", fmt.Errorf("%s: %w", source.Path, err)
			}
			continue
		}

		for path := range pending.fields {
			if hasPath(values, path) {
				delete(pending.fields, path)
			}
		}
		if pending.tracer != nil && hasPath(values, "otel_traces_export") {
			return nil, "", fmt.Errorf("%s: otel_traces_export overlaps tracer_provider in %s", source.Path, pending.tracerSource)
		}
		mergeDocument(document, values)
		if i == 0 {
			cfg = layer
			continue
		}
		merged, err := yaml.Marshal(document)
		if err == nil {
			cfg, _, err = loadExpanded(merged)
		}
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", source.Path, err)
		}
	}
	for _, apply := range pending.fields {
		apply(cfg)
	}
	if pending.tracer != nil {
		if err := convert.ApplyTracerProvider(cfg, pending.tracer.TracerProvider); err != nil {
			return nil, "", fmt.Errorf("%s: tracer_provider: %w", pending.tracerSource, err)
		}
	}
	return cfg, base, nil
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
}

const extension = "extensions.obi."

var sharedSettings = []sharedSetting{
	{"channel_buffer_len", extension + "capture.channels.buffer_len", func(d, s *obi.Config) { d.ChannelBufferLen = s.ChannelBufferLen }},
	{"channel_send_timeout", extension + "capture.channels.send_timeout", func(d, s *obi.Config) { d.ChannelSendTimeout = s.ChannelSendTimeout }},
	{"channel_send_timeout_panic", extension + "capture.channels.panic_on_send_timeout", func(d, s *obi.Config) { d.ChannelSendTimeoutPanic = s.ChannelSendTimeoutPanic }},
	{"shutdown_timeout", extension + "daemon.shutdown.timeout", func(d, s *obi.Config) { d.ShutdownTimeout = s.ShutdownTimeout }},
	{"log_level", "log_level", func(d, s *obi.Config) { d.LogLevel = s.LogLevel }},
	{"log_format", extension + "daemon.logging.format", func(d, s *obi.Config) { d.LogFormat = s.LogFormat }},
}

type mixedOverrides struct {
	fields       map[string]func(*obi.Config)
	tracer       *schema.Document
	tracerYAML   map[string]any
	tracerSource string
}

func (p *mixedOverrides) add(base, version string, values map[string]any, cfg *obi.Config, source string) error {
	if version == VersionV2 {
		delete(values, "file_format")
		if provider, ok := values["tracer_provider"]; ok {
			if p.tracerYAML == nil {
				p.tracerYAML = map[string]any{
					"file_format": schema.SupportedFileFormat,
					"extensions":  map[string]any{"obi": map[string]any{"version": schema.SupportedVersion}},
				}
			}
			mergeDocument(p.tracerYAML, map[string]any{"tracer_provider": provider})
			data, err := yaml.Marshal(p.tracerYAML)
			if err != nil {
				return err
			}
			p.tracer, _, err = schema.ParseStandaloneYAML(data)
			if err != nil {
				return err
			}
			p.tracerSource = source
			delete(values, "tracer_provider")
		}
	}
	return p.addFields(base, version, values, "", cfg)
}

func (p *mixedOverrides) addFields(base, version string, m map[string]any, prefix string, cfg *obi.Config) error {
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
			if err := p.addFields(base, version, child, path+".", cfg); err != nil {
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
				p.fields[target] = func(dst *obi.Config) { setting.copy(dst, cfg) }
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
