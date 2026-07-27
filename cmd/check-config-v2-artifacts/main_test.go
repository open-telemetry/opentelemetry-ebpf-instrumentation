// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCurrentArtifacts(t *testing.T) {
	err := run([]string{
		"-schema", filepath.Join("..", "..", defaultSchemaPath),
		"-example", filepath.Join("..", "..", defaultExamplePath),
	})
	if err != nil {
		t.Fatal(err)
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

func TestCheckExampleArtifactRejectsReceiverShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receiver.yaml")
	writeFile(t, path, "version: \"2.0\"\ncapture: {}\n")

	err := checkExampleArtifact(path)
	if err == nil {
		t.Fatal("expected standalone parser failure")
	}
	if !strings.Contains(err.Error(), "missing extensions.obi.version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeFile(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
