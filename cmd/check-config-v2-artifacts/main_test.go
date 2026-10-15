// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestRunCurrentArtifacts(t *testing.T) {
	err := run([]string{
		"-schema", filepath.Join("..", "..", defaultSchemaPath),
		"-default-reference", filepath.Join("..", "..", defaultReferencePath),
		"-runnable-example", filepath.Join("..", "..", defaultRunnableExamplePath),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSelectionRuleSpansSchema(t *testing.T) {
	schemaPath := filepath.Join("..", "..", defaultSchemaPath)
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaData, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
		pattern = regexp.MustCompile(`\\u([[:xdigit:]]{4})`).ReplaceAllString(pattern, `\x{$1}`)
		return regexp.Compile(pattern)
	})
	const schemaURL = "https://opentelemetry.io/obi/schemas/obi-extension.schema.json"
	if err := compiler.AddResource(schemaURL, schemaDocument); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		action  string
		spans   any
		wantErr bool
	}{
		{name: "include with spans", action: "include", spans: []any{map[string]any{"name": "custom", "on": map[string]any{"function": "example.Func"}}}},
		{name: "exclude with empty spans", action: "exclude", spans: []any{}},
		{name: "exclude with spans", action: "exclude", spans: []any{map[string]any{"name": "custom", "on": map[string]any{"function": "example.Func"}}}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := map[string]any{
				"action": tc.action,
				"match":  map[string]any{"process": map[string]any{"language_glob": []any{"java"}}},
			}
			if tc.spans != nil {
				rule["refine"] = map[string]any{"spans": tc.spans}
			}
			err := schema.Validate(map[string]any{
				"version": "2.0",
				"capture": map[string]any{"rules": []any{rule}},
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("schema validation error = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestCheckSchemaArtifactRejectsWrongVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema.json")
	writeFile(t, path, `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://opentelemetry.io/obi/schemas/obi-extension.schema.json",
  "title": "OBI Extension Configuration",
  "type": "object",
  "properties": {
    "version": {
      "const": "1.0"
    }
  },
  "$defs": {}
}
`)

	err := checkSchemaArtifact(path)
	if err == nil {
		t.Fatal("expected schema version failure")
	}
	if !strings.Contains(err.Error(), "properties.version.const") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckLogFieldNameSchemaRejectsControlGap(t *testing.T) {
	field := func(pattern string) map[string]any {
		return map[string]any{
			"minLength": json.Number("1"),
			"pattern":   pattern,
		}
	}
	root := map[string]any{
		"$defs": map[string]any{
			"TraceAnnotation": map[string]any{
				"properties": map[string]any{
					"field_names": map[string]any{
						"properties": map[string]any{
							"trace_id": field(`^[^\s=\u0000-\u001F\u007F]+$`),
							"span_id":  field(logFieldNamePattern),
						},
					},
				},
			},
		},
	}

	err := checkLogFieldNameSchema(root)
	if err == nil {
		t.Fatal("expected log field name pattern failure")
	}
	if !strings.Contains(err.Error(), "trace_id pattern") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckDefaultReferenceArtifactRejectsStandaloneDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reference.yaml")
	writeFile(t, path, `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
`)

	err := checkDefaultReferenceArtifact(path)
	if err == nil {
		t.Fatal("expected standalone document failure")
	}
	if !strings.Contains(err.Error(), "must not be a standalone document") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckRunnableExampleArtifactRejectsReceiverShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receiver.yaml")
	writeFile(t, path, "version: \"2.0\"\ncapture: {}\n")

	err := checkRunnableExampleArtifact(path)
	if err == nil {
		t.Fatal("expected standalone parser failure")
	}
	if !strings.Contains(err.Error(), "missing extensions.obi.version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckRunnableExampleArtifactRejectsMissingExporter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "standalone.yaml")
	writeFile(t, path, `
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
`)

	err := checkRunnableExampleArtifact(path)
	if err == nil {
		t.Fatal("expected runtime validation failure")
	}
	if !strings.Contains(err.Error(), "you need to define at least one exporter") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeFile(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
