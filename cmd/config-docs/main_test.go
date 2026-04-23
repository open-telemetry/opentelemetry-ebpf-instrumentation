// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGenerator(defs map[string]*Schema) *DocGenerator {
	if defs == nil {
		defs = map[string]*Schema{}
	}
	return &DocGenerator{
		root:            &Schema{Defs: defs},
		referencedTypes: make(map[string]bool),
	}
}

func TestSchemaUnmarshalEnvVar(t *testing.T) {
	data := `{"type": "string", "x-env-var": "OTEL_FOO", "description": "A field"}`
	var s Schema
	require.NoError(t, json.Unmarshal([]byte(data), &s))
	assert.Equal(t, "OTEL_FOO", s.EnvVar)
	assert.Equal(t, "A field", s.Description)
}

func TestSchemaUnmarshalNoEnvVar(t *testing.T) {
	data := `{"type": "integer"}`
	var s Schema
	require.NoError(t, json.Unmarshal([]byte(data), &s))
	assert.Empty(t, s.EnvVar)
}

func TestRefToName(t *testing.T) {
	assert.Equal(t, "FooBar", refToName("#/$defs/FooBar"))
	assert.Equal(t, "Simple", refToName("Simple"))
}

func TestIsObjectType(t *testing.T) {
	g := newTestGenerator(nil)

	t.Run("nil schema", func(t *testing.T) {
		assert.False(t, g.isObjectType(nil))
	})

	t.Run("no properties", func(t *testing.T) {
		assert.False(t, g.isObjectType(&Schema{Type: "string"}))
	})

	t.Run("properties with description", func(t *testing.T) {
		s := &Schema{Properties: map[string]*Schema{
			"field": {Type: "string", Description: "A useful field"},
		}}
		assert.True(t, g.isObjectType(s))
	})

	t.Run("properties with env var", func(t *testing.T) {
		s := &Schema{Properties: map[string]*Schema{
			"field": {Type: "string", EnvVar: "MY_VAR"},
		}}
		assert.True(t, g.isObjectType(s))
	})

	t.Run("properties without useful content", func(t *testing.T) {
		s := &Schema{Properties: map[string]*Schema{
			"internal": {Type: "string"},
		}}
		assert.False(t, g.isObjectType(s))
	})
}

func TestTypeString(t *testing.T) {
	g := newTestGenerator(nil)

	tests := []struct {
		name     string
		schema   *Schema
		expected string
	}{
		{"string", &Schema{Type: "string"}, "`string`"},
		{"integer", &Schema{Type: "integer"}, "`integer`"},
		{"boolean", &Schema{Type: "boolean"}, "`boolean`"},
		{"duration", &Schema{Type: "string", Pattern: "^[0-9]+(ms|s|m)$"}, "`duration`"},
		{"string array", &Schema{Type: "array", Items: &Schema{Type: "string"}}, "`string`[]"},
		{"oneOf", &Schema{OneOf: []*Schema{{Type: "string"}}}, "`string`"},
		{"nil", nil, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, g.typeString(tc.schema, tc.schema))
		})
	}
}

func TestTypeStringReferencedTypes(t *testing.T) {
	t.Run("true map renders as map type", func(t *testing.T) {
		g := newTestGenerator(map[string]*Schema{
			"ResourceLabels": {
				Type:                 "object",
				AdditionalProperties: &Schema{Type: "string"},
			},
		})
		orig := &Schema{Ref: "#/$defs/ResourceLabels"}
		resolved := g.resolve(orig)
		result := g.typeString(orig, resolved)
		assert.Equal(t, "`map[string]string`", result)
		assert.False(t, g.referencedTypes["ResourceLabels"])
	})

	t.Run("object with propertyNames links to type def", func(t *testing.T) {
		g := newTestGenerator(map[string]*Schema{
			"ExtraGroupAttributesMap": {
				Type:                 "object",
				PropertyNames:        &Schema{Enum: []any{"k8s_app_meta"}},
				AdditionalProperties: &Schema{Type: "array", Items: &Schema{Type: "string"}},
			},
		})
		orig := &Schema{Ref: "#/$defs/ExtraGroupAttributesMap"}
		resolved := g.resolve(orig)
		result := g.typeString(orig, resolved)
		assert.Contains(t, result, "ExtraGroupAttributesMap")
		assert.Contains(t, result, "#extragroupattributesmap")
		assert.True(t, g.referencedTypes["ExtraGroupAttributesMap"])
	})

	t.Run("simple string type inlined not linked", func(t *testing.T) {
		g := newTestGenerator(map[string]*Schema{
			"GlobAttr": {Type: "string", Format: "glob"},
		})
		orig := &Schema{Ref: "#/$defs/GlobAttr"}
		resolved := g.resolve(orig)
		result := g.typeString(orig, resolved)
		assert.Equal(t, "`glob`", result)
		assert.False(t, g.referencedTypes["GlobAttr"])
	})
}

func TestValuesString(t *testing.T) {
	g := newTestGenerator(nil)

	t.Run("enum values", func(t *testing.T) {
		s := &Schema{Enum: []any{"a", "b", "c"}}
		result := g.valuesString(s, s)
		assert.Equal(t, "`a`, `b`, `c`", result)
	})

	t.Run("examples", func(t *testing.T) {
		s := &Schema{Examples: []any{"30s", "5m"}}
		result := g.valuesString(s, s)
		assert.Equal(t, "`30s`, `5m`, etc", result)
	})

	t.Run("items enum", func(t *testing.T) {
		s := &Schema{Type: "array", Items: &Schema{Enum: []any{"x", "y"}}}
		result := g.valuesString(s, s)
		assert.Equal(t, "`x`, `y`", result)
	})

	t.Run("referenced type skips values", func(t *testing.T) {
		g := newTestGenerator(nil)
		g.referencedTypes["GlobAttr"] = true
		orig := &Schema{Ref: "#/$defs/GlobAttr"}
		resolved := &Schema{Type: "string", Format: "glob", Examples: []any{"app-*"}}
		result := g.valuesString(orig, resolved)
		assert.Empty(t, result)
	})

	t.Run("nil", func(t *testing.T) {
		assert.Empty(t, g.valuesString(nil, nil))
	})
}

func TestDescString(t *testing.T) {
	g := newTestGenerator(nil)

	t.Run("normal description", func(t *testing.T) {
		s := &Schema{Description: "A simple field"}
		assert.Equal(t, "A simple field", g.descString(s, s))
	})

	t.Run("deprecated not in desc", func(t *testing.T) {
		s := &Schema{Description: "Old field", Deprecated: true}
		assert.Equal(t, "Old field", g.descString(s, s))
	})

	t.Run("pipes escaped", func(t *testing.T) {
		s := &Schema{Description: "a | b"}
		assert.Equal(t, "a \\| b", g.descString(s, s))
	})

	t.Run("original preferred over resolved", func(t *testing.T) {
		orig := &Schema{Description: "Original desc"}
		resolved := &Schema{Description: "Resolved desc"}
		assert.Equal(t, "Original desc", g.descString(orig, resolved))
	})

	t.Run("falls back to resolved", func(t *testing.T) {
		orig := &Schema{}
		resolved := &Schema{Description: "Resolved desc"}
		assert.Equal(t, "Resolved desc", g.descString(orig, resolved))
	})

	t.Run("nil", func(t *testing.T) {
		assert.Empty(t, g.descString(nil, nil))
	})
}

func TestDeprecatedString(t *testing.T) {
	g := newTestGenerator(nil)

	assert.Equal(t, "Yes", g.deprecatedString(&Schema{Deprecated: true}, nil))
	assert.Equal(t, "Yes", g.deprecatedString(nil, &Schema{Deprecated: true}))
	assert.Empty(t, g.deprecatedString(&Schema{Deprecated: false}, nil))
	assert.Empty(t, g.deprecatedString(nil, nil))
}

func TestEnvVar(t *testing.T) {
	g := newTestGenerator(nil)

	t.Run("from original", func(t *testing.T) {
		assert.Equal(t, "`ORIG_VAR`", g.envVar(&Schema{EnvVar: "ORIG_VAR"}, &Schema{EnvVar: "RESOLVED_VAR"}))
	})
	t.Run("from resolved", func(t *testing.T) {
		assert.Equal(t, "`RESOLVED_VAR`", g.envVar(&Schema{}, &Schema{EnvVar: "RESOLVED_VAR"}))
	})
	t.Run("dash means none", func(t *testing.T) {
		assert.Empty(t, g.envVar(&Schema{EnvVar: "-"}, &Schema{}))
	})
	t.Run("none", func(t *testing.T) {
		assert.Empty(t, g.envVar(&Schema{}, &Schema{}))
	})
}

func TestGenerate(t *testing.T) {
	schema := &Schema{
		Properties: map[string]*Schema{
			"log_level": {
				Type: "string", Enum: []any{"DEBUG", "INFO"},
				EnvVar: "LOG_LEVEL", Description: "Log level",
			},
			"nested": {Ref: "#/$defs/NestedConfig"},
		},
		Defs: map[string]*Schema{
			"NestedConfig": {
				Description: "Nested configuration",
				Properties: map[string]*Schema{
					"enabled": {Type: "boolean", EnvVar: "NESTED_ENABLED", Description: "Enable nested"},
				},
			},
		},
	}

	gen := &DocGenerator{root: schema, referencedTypes: make(map[string]bool)}
	output := gen.Generate("config-schema.json")

	assert.Contains(t, output, "# OBI Configuration Reference")
	assert.Contains(t, output, "## Top-Level Properties")
	assert.Contains(t, output, "`log_level`")
	assert.Contains(t, output, "`LOG_LEVEL`")
	assert.Contains(t, output, "`DEBUG`, `INFO`")
	assert.Contains(t, output, "## `nested`")
	assert.Contains(t, output, "`nested.enabled`")
	assert.Contains(t, output, "`NESTED_ENABLED`")
}

func TestGenerateFromRealSchema(t *testing.T) {
	data, err := os.ReadFile("../../devdocs/config/config-schema.json")
	if err != nil {
		t.Skip("config-schema.json not found, skipping integration test")
	}

	var schema Schema
	require.NoError(t, json.Unmarshal(data, &schema))

	gen := &DocGenerator{root: &schema, referencedTypes: make(map[string]bool)}
	output := gen.Generate("config-schema.json")

	// Basic structural checks
	assert.Contains(t, output, "# OBI Configuration Reference")
	assert.Contains(t, output, "## Table of Contents")
	assert.Contains(t, output, "## Top-Level Properties")
	assert.Contains(t, output, "`OTEL_EBPF_LOG_LEVEL`")
	assert.Contains(t, output, "## `ebpf`")
	assert.Contains(t, output, "## `discovery`")
	assert.Contains(t, output, "## `attributes`")
	assert.Contains(t, output, "## `network`")
	assert.Contains(t, output, "## Type Definitions")

	// open_port and target_pids should NOT be sections
	assert.NotContains(t, output, "## `open_port`")
	assert.NotContains(t, output, "## `target_pids`")

	// Complex types should link to type definitions
	assert.Contains(t, output, "ExtraGroupAttributesMap")
	assert.Contains(t, output, "### ExtraGroupAttributesMap")
	assert.Contains(t, output, "Known keys")
	assert.Contains(t, output, "### IntEnum")

	// True maps should NOT appear in type definitions
	assert.NotContains(t, output, "### ResourceLabels")
	assert.NotContains(t, output, "### Selection")

	// Simple types should show values inline in property tables
	assert.Contains(t, output, "`glob`")
	assert.Contains(t, output, "`regex`")
}

func TestWriteTypeDefinitions(t *testing.T) {
	g := &DocGenerator{
		root: &Schema{
			Defs: map[string]*Schema{
				"MyEnum": {
					Type:        "string",
					Enum:        []any{"a", "b"},
					Description: "My enum type",
				},
				"MyObject": {
					Type:                 "object",
					PropertyNames:        &Schema{Enum: []any{"key1", "key2"}},
					AdditionalProperties: &Schema{Type: "string"},
					Description:          "Object with known keys",
				},
			},
		},
		referencedTypes: map[string]bool{
			"MyEnum":   true,
			"MyObject": true,
		},
	}

	var b strings.Builder
	g.writeTypeDefinitions(&b)
	output := b.String()

	assert.Contains(t, output, "## Type Definitions")
	assert.Contains(t, output, "### MyEnum")
	assert.Contains(t, output, "`a`, `b`")
	assert.Contains(t, output, "### MyObject")
	assert.Contains(t, output, "**Known keys:** `key1`, `key2`")
	assert.Contains(t, output, "**Value type:** `string`")
}

func TestWrapBareURLs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no urls", "hello world", "hello world"},
		{"single url", "see https://example.com for details", "see <https://example.com> for details"},
		{"already wrapped", "see <https://example.com> ok", "see <https://example.com> ok"},
		{"multiple urls", "see https://a.com and https://b.com here", "see <https://a.com> and <https://b.com> here"},
		{"url at end", "see https://example.com", "see <https://example.com>"},
		{"mixed wrapped and bare", "see <https://a.com> and https://b.com here", "see <https://a.com> and <https://b.com> here"},
		{"http url", "see http://example.com here", "see <http://example.com> here"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, wrapBareURLs(tc.input))
		})
	}
}

func TestDefaultString(t *testing.T) {
	g := newTestGenerator(nil)

	t.Run("nil", func(t *testing.T) {
		assert.Empty(t, g.defaultString(nil))
		assert.Empty(t, g.defaultString(&Schema{}))
	})

	t.Run("string", func(t *testing.T) {
		assert.Equal(t, "`hello`", g.defaultString(&Schema{Default: "hello"}))
	})

	t.Run("integer", func(t *testing.T) {
		assert.Equal(t, "`42`", g.defaultString(&Schema{Default: float64(42)}))
	})

	t.Run("bool", func(t *testing.T) {
		assert.Equal(t, "`true`", g.defaultString(&Schema{Default: true}))
	})

	t.Run("scalar array", func(t *testing.T) {
		assert.Equal(t, "`a`, `b`", g.defaultString(&Schema{Default: []any{"a", "b"}}))
	})

	t.Run("complex array uses json", func(t *testing.T) {
		result := g.defaultString(&Schema{Default: []any{map[string]any{"k": "v"}}})
		assert.Contains(t, result, `"k"`)
		assert.Contains(t, result, `"v"`)
	})

	t.Run("map uses json", func(t *testing.T) {
		result := g.defaultString(&Schema{Default: map[string]any{"key": "val"}})
		assert.Contains(t, result, `"key"`)
		assert.Contains(t, result, `"val"`)
	})
}
