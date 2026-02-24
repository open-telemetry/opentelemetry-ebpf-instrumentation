// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/parser"
	"go/token"
	"reflect"
	"testing"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"
)

func TestExtractTagValue(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		key      string
		expected string
	}{
		{
			name:     "simple yaml tag",
			tag:      `yaml:"field_name"`,
			key:      "yaml",
			expected: "field_name",
		},
		{
			name:     "yaml tag with options",
			tag:      `yaml:"field_name,omitempty"`,
			key:      "yaml",
			expected: "field_name,omitempty",
		},
		{
			name:     "env tag",
			tag:      `env:"OTEL_EBPF_SOME_VAR"`,
			key:      "env",
			expected: "OTEL_EBPF_SOME_VAR",
		},
		{
			name:     "multiple tags - extract yaml",
			tag:      `yaml:"field" env:"ENV_VAR" json:"jsonfield"`,
			key:      "yaml",
			expected: "field",
		},
		{
			name:     "multiple tags - extract env",
			tag:      `yaml:"field" env:"ENV_VAR" json:"jsonfield"`,
			key:      "env",
			expected: "ENV_VAR",
		},
		{
			name:     "missing tag",
			tag:      `yaml:"field"`,
			key:      "env",
			expected: "",
		},
		{
			name:     "empty tag",
			tag:      "",
			key:      "yaml",
			expected: "",
		},
		{
			name:     "inline yaml tag",
			tag:      `yaml:",inline"`,
			key:      "yaml",
			expected: ",inline",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractTagValue(tc.tag, tc.key)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExprToTypeName(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "simple identifier",
			code:     "MyType",
			expected: "MyType",
		},
		{
			name:     "selector expression",
			code:     "pkg.MyType",
			expected: "MyType",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expr, err := parser.ParseExpr(tc.code)
			require.NoError(t, err)
			result := exprToTypeName(expr)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractConstValueAndType(t *testing.T) {
	tests := []struct {
		name          string
		code          string
		inheritedType string
		expectedType  string
		expectedValue any
	}{
		{
			name:          "string literal with inherited type",
			code:          `"value"`,
			inheritedType: "MyType",
			expectedType:  "MyType",
			expectedValue: "value",
		},
		{
			name:          "type conversion call",
			code:          `LogLevel("DEBUG")`,
			inheritedType: "",
			expectedType:  "LogLevel",
			expectedValue: "DEBUG",
		},
		{
			name:          "iota reference returns nil",
			code:          `iota`,
			inheritedType: "MyType",
			expectedType:  "",
			expectedValue: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expr, err := parser.ParseExpr(tc.code)
			require.NoError(t, err)
			typeName, value := extractConstValueAndType(expr, tc.inheritedType)
			assert.Equal(t, tc.expectedType, typeName)
			assert.Equal(t, tc.expectedValue, value)
		})
	}
}

func TestProcessSchemaDeprecation(t *testing.T) {
	tests := []struct {
		name               string
		description        string
		expectedDeprecated bool
		expectedDesc       string
	}{
		{
			name:               "deprecated at start",
			description:        "Deprecated: use NewField instead",
			expectedDeprecated: true,
			expectedDesc:       "use NewField instead",
		},
		{
			name:               "deprecated only",
			description:        "deprecated",
			expectedDeprecated: true,
			expectedDesc:       "",
		},
		{
			name:               "deprecated in multiline",
			description:        "Some description\nDeprecated: use something else",
			expectedDeprecated: true,
			expectedDesc:       "Some description\nuse something else",
		},
		{
			name:               "not deprecated",
			description:        "This is a normal field",
			expectedDeprecated: false,
			expectedDesc:       "This is a normal field",
		},
		{
			name:               "empty description",
			description:        "",
			expectedDeprecated: false,
			expectedDesc:       "",
		},
		{
			name:               "deprecated case insensitive",
			description:        "DEPRECATED: old field",
			expectedDeprecated: true,
			expectedDesc:       "old field",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			schema := &jsonschema.Schema{
				Description: tc.description,
			}
			processSchemaDeprecation(schema)
			assert.Equal(t, tc.expectedDeprecated, schema.Deprecated)
			assert.Equal(t, tc.expectedDesc, schema.Description)
		})
	}
}

func TestSortSchema(t *testing.T) {
	t.Run("sorts properties alphabetically", func(t *testing.T) {
		schema := &jsonschema.Schema{
			Properties: jsonschema.NewProperties(),
		}
		schema.Properties.Set("zebra", &jsonschema.Schema{Type: "string"})
		schema.Properties.Set("alpha", &jsonschema.Schema{Type: "string"})
		schema.Properties.Set("mango", &jsonschema.Schema{Type: "string"})

		sortSchemaNode(schema)

		var keys []string
		for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
			keys = append(keys, pair.Key)
		}
		assert.Equal(t, []string{"alpha", "mango", "zebra"}, keys)
	})

	t.Run("sorts enum values", func(t *testing.T) {
		schema := &jsonschema.Schema{
			Enum: []any{"c", "a", "b"},
		}

		sortSchemaNode(schema)

		assert.Equal(t, []any{"a", "b", "c"}, schema.Enum)
	})

	t.Run("handles nil schema", func(_ *testing.T) {
		// Should not panic
		sortSchemaNode(nil)
	})

	t.Run("sorts nested properties", func(t *testing.T) {
		nested := &jsonschema.Schema{
			Properties: jsonschema.NewProperties(),
		}
		nested.Properties.Set("z_nested", &jsonschema.Schema{Type: "string"})
		nested.Properties.Set("a_nested", &jsonschema.Schema{Type: "string"})

		schema := &jsonschema.Schema{
			Properties: jsonschema.NewProperties(),
		}
		schema.Properties.Set("parent", nested)

		visitNestedSchemas(schema, sortSchemaNode)

		var nestedKeys []string
		for pair := nested.Properties.Oldest(); pair != nil; pair = pair.Next() {
			nestedKeys = append(nestedKeys, pair.Key)
		}
		assert.Equal(t, []string{"a_nested", "z_nested"}, nestedKeys)
	})
}

func TestCustomMapper(t *testing.T) {
	t.Run("maps time.Duration to string schema", func(t *testing.T) {
		g := NewSchemaGenerator()
		mapper := g.customMapper()
		durationType := reflect.TypeOf(time.Duration(0))
		schema := mapper(durationType)

		require.NotNil(t, schema)
		assert.Equal(t, "string", schema.Type)
		assert.Contains(t, schema.Description, "Duration")
		assert.NotEmpty(t, schema.Pattern)
		assert.NotEmpty(t, schema.Examples)
	})

	t.Run("returns nil for regular types", func(t *testing.T) {
		g := NewSchemaGenerator()
		mapper := g.customMapper()
		stringType := reflect.TypeOf("")
		schema := mapper(stringType)
		assert.Nil(t, schema)
	})

	t.Run("handles function types", func(t *testing.T) {
		g := NewSchemaGenerator()
		mapper := g.customMapper()
		funcType := reflect.TypeOf(func() {})
		schema := mapper(funcType)

		require.NotNil(t, schema)
		assert.Equal(t, "null", schema.Type)
	})

	t.Run("returns enum schema for registered types", func(t *testing.T) {
		g := NewSchemaGenerator()
		g.enums["TestEnum"] = []any{"value1", "value2"}
		mapper := g.customMapper()

		// Create a named type for testing
		type TestEnum string
		testType := reflect.TypeOf(TestEnum(""))

		schema := mapper(testType)

		require.NotNil(t, schema)
		assert.Equal(t, "string", schema.Type)
		assert.Equal(t, []any{"value1", "value2"}, schema.Enum)
	})
}

func TestExtractEnums(t *testing.T) {
	g := NewSchemaGenerator()

	src := `
package test

type LogLevel string

const (
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
)

type TracePrinter string

const (
	TracePrinterDisabled TracePrinter = TracePrinter("disabled")
	TracePrinterJSON     TracePrinter = TracePrinter("json")
)

// unexported consts should be ignored
const (
	unexportedConst LogLevel = "HIDDEN"
)
`

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	g.extractFileMetadata(file)

	// Check LogLevel enums
	assert.Contains(t, g.enums, "LogLevel")
	assert.ElementsMatch(t, []any{"DEBUG", "INFO", "WARN"}, g.enums["LogLevel"])

	// Check TracePrinter enums
	assert.Contains(t, g.enums, "TracePrinter")
	assert.ElementsMatch(t, []any{"disabled", "json"}, g.enums["TracePrinter"])
}

func TestExtractStructMetadata(t *testing.T) {
	g := NewSchemaGenerator()

	src := `
package test

type Config struct {
	Endpoint string ` + "`yaml:\"endpoint\" env:\"OTEL_ENDPOINT\"`" + `
	Timeout  int    ` + "`yaml:\"timeout\" env:\"OTEL_TIMEOUT\"`" + `
	NoEnv    string ` + "`yaml:\"no_env\"`" + `
	Nested   NestedConfig ` + "`yaml:\",inline\"`" + `
}

type NestedConfig struct {
	Value string ` + "`yaml:\"value\" env:\"NESTED_VALUE\"`" + `
}
`

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	require.NoError(t, err)

	g.extractFileMetadata(file)

	// Check Config env vars
	require.Contains(t, g.envVars, "Config")
	assert.Equal(t, "OTEL_ENDPOINT", g.envVars["Config"]["endpoint"])
	assert.Equal(t, "OTEL_TIMEOUT", g.envVars["Config"]["timeout"])
	assert.NotContains(t, g.envVars["Config"], "no_env")

	// Check NestedConfig env vars
	require.Contains(t, g.envVars, "NestedConfig")
	assert.Equal(t, "NESTED_VALUE", g.envVars["NestedConfig"]["value"])

	// Check inline field tracking
	assert.Contains(t, g.inlineFields, "Config")
	assert.Contains(t, g.inlineFields["Config"], "NestedConfig")
}

func TestAddEnvVarsToProperties(t *testing.T) {
	schema := &jsonschema.Schema{
		Properties: jsonschema.NewProperties(),
	}
	schema.Properties.Set("endpoint", &jsonschema.Schema{Type: "string"})
	schema.Properties.Set("timeout", &jsonschema.Schema{Type: "integer"})
	schema.Properties.Set("other", &jsonschema.Schema{Type: "string"})

	envVars := map[string]string{
		"endpoint": "OTEL_ENDPOINT",
		"timeout":  "OTEL_TIMEOUT",
	}

	addEnvVarsToProperties(schema, envVars)

	// Check endpoint has x-env-var
	endpointSchema, ok := schema.Properties.Get("endpoint")
	require.True(t, ok)
	assert.Equal(t, "OTEL_ENDPOINT", endpointSchema.Extras["x-env-var"])

	// Check timeout has x-env-var
	timeoutSchema, ok := schema.Properties.Get("timeout")
	require.True(t, ok)
	assert.Equal(t, "OTEL_TIMEOUT", timeoutSchema.Extras["x-env-var"])

	// Check other does not have x-env-var
	otherSchema, ok := schema.Properties.Get("other")
	require.True(t, ok)
	assert.Nil(t, otherSchema.Extras)
}

func TestProcessDeprecated(t *testing.T) {
	t.Run("processes nested schemas", func(t *testing.T) {
		schema := &jsonschema.Schema{
			Description: "Deprecated: root is deprecated",
			Properties:  jsonschema.NewProperties(),
			Definitions: map[string]*jsonschema.Schema{
				"Nested": {
					Description: "Deprecated: nested is deprecated",
				},
			},
		}
		nestedProp := &jsonschema.Schema{
			Description: "Deprecated: property is deprecated",
		}
		schema.Properties.Set("nested_prop", nestedProp)

		processDeprecated(schema)

		assert.True(t, schema.Deprecated)
		assert.True(t, schema.Definitions["Nested"].Deprecated)
		prop, _ := schema.Properties.Get("nested_prop")
		assert.True(t, prop.Deprecated)
	})

	t.Run("handles nil schema", func(_ *testing.T) {
		// Should not panic
		processDeprecated(nil)
	})
}

func TestProcessInlineFields(t *testing.T) {
	g := NewSchemaGenerator()
	g.inlineFields["ParentType"] = []string{"InlineType"}

	// Create schema with definitions
	schema := &jsonschema.Schema{
		Definitions: map[string]*jsonschema.Schema{
			"ParentType": {
				Properties: jsonschema.NewProperties(),
			},
			"InlineType": {
				Properties: jsonschema.NewProperties(),
			},
		},
	}

	// Add properties to inline type
	schema.Definitions["InlineType"].Properties.Set("inline_field", &jsonschema.Schema{Type: "string"})

	// Add a property to parent that should not be overwritten
	schema.Definitions["ParentType"].Properties.Set("parent_field", &jsonschema.Schema{Type: "string"})

	g.processInlineFields(schema)

	// Check that inline_field was merged into ParentType
	parentSchema := schema.Definitions["ParentType"]
	_, hasInlineField := parentSchema.Properties.Get("inline_field")
	assert.True(t, hasInlineField, "inline_field should be merged into ParentType")

	// Check that parent_field still exists
	_, hasParentField := parentSchema.Properties.Get("parent_field")
	assert.True(t, hasParentField, "parent_field should still exist")
}

func TestSortSchemaProperties(t *testing.T) {
	schema := &jsonschema.Schema{
		Properties: jsonschema.NewProperties(),
		Definitions: map[string]*jsonschema.Schema{
			"DefA": {
				Properties: jsonschema.NewProperties(),
				Enum:       []any{"z", "a", "m"},
			},
		},
	}
	schema.Properties.Set("z_prop", &jsonschema.Schema{Type: "string"})
	schema.Properties.Set("a_prop", &jsonschema.Schema{Type: "string"})
	schema.Definitions["DefA"].Properties.Set("z_def", &jsonschema.Schema{Type: "string"})
	schema.Definitions["DefA"].Properties.Set("a_def", &jsonschema.Schema{Type: "string"})

	sortSchemaProperties(schema)

	// Check root properties are sorted
	var rootKeys []string
	for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
		rootKeys = append(rootKeys, pair.Key)
	}
	assert.Equal(t, []string{"a_prop", "z_prop"}, rootKeys)

	// Check definition properties are sorted
	var defKeys []string
	for pair := schema.Definitions["DefA"].Properties.Oldest(); pair != nil; pair = pair.Next() {
		defKeys = append(defKeys, pair.Key)
	}
	assert.Equal(t, []string{"a_def", "z_def"}, defKeys)

	// Check enum values are sorted
	assert.Equal(t, []any{"a", "m", "z"}, schema.Definitions["DefA"].Enum)
}

func TestBuildInlineTypeSchemas(t *testing.T) {
	t.Run("finds MetadataGlobMap and MetadataRegexMap from obi.Config", func(t *testing.T) {
		result := buildInlineTypeSchemas(reflect.TypeOf(obi.Config{}))

		// Should find MetadataGlobMap
		schemaFunc, found := result["MetadataGlobMap"]
		assert.True(t, found, "should find MetadataGlobMap")
		if found {
			schema := schemaFunc()
			assert.NotNil(t, schema)
			assert.Equal(t, "object", schema.Type)
		}

		// Should find MetadataRegexMap
		schemaFunc, found = result["MetadataRegexMap"]
		assert.True(t, found, "should find MetadataRegexMap")
		if found {
			schema := schemaFunc()
			assert.NotNil(t, schema)
			assert.Equal(t, "object", schema.Type)
		}
	})

	t.Run("handles struct with no inline fields", func(t *testing.T) {
		type SimpleStruct struct {
			Name string `yaml:"name"`
		}
		result := buildInlineTypeSchemas(reflect.TypeOf(SimpleStruct{}))
		assert.Empty(t, result)
	})

	t.Run("handles pointer types", func(t *testing.T) {
		result := buildInlineTypeSchemas(reflect.TypeOf(&obi.Config{}))

		// Should still find inline types
		_, found := result["MetadataGlobMap"]
		assert.True(t, found, "should find MetadataGlobMap even with pointer root type")
	})
}

// testJSONSchemaType is a test type that implements JSONSchema()
type testJSONSchemaType struct{}

func (testJSONSchemaType) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Description: "test schema",
	}
}

func TestHasJSONSchemaMethod(t *testing.T) {
	t.Run("returns true for type implementing JSONSchema", func(t *testing.T) {
		result := hasJSONSchemaMethod(reflect.TypeOf(testJSONSchemaType{}))
		assert.True(t, result)
	})

	t.Run("returns false for type not implementing JSONSchema", func(t *testing.T) {
		type noSchema struct{}
		result := hasJSONSchemaMethod(reflect.TypeOf(noSchema{}))
		assert.False(t, result)
	})

	t.Run("returns true for string type", func(t *testing.T) {
		// Plain string doesn't implement JSONSchema
		result := hasJSONSchemaMethod(reflect.TypeOf(""))
		assert.False(t, result)
	})
}

func TestCallJSONSchemaMethod(t *testing.T) {
	t.Run("calls JSONSchema on type with value receiver", func(t *testing.T) {
		schema := callJSONSchemaMethod(reflect.TypeOf(testJSONSchemaType{}))
		require.NotNil(t, schema)
		assert.Equal(t, "string", schema.Type)
		assert.Equal(t, "test schema", schema.Description)
	})

	t.Run("returns nil for type without JSONSchema", func(t *testing.T) {
		type noSchema struct{}
		schema := callJSONSchemaMethod(reflect.TypeOf(noSchema{}))
		assert.Nil(t, schema)
	})
}
