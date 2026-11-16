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
		"-default-reference", filepath.Join("..", "..", defaultReferencePath),
		"-runnable-example", filepath.Join("..", "..", defaultRunnableExamplePath),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestConnectionInfoFeatureIsInConfigSchemaEnum(t *testing.T) {
	root, err := readJSONMap(filepath.Join("..", "..", defaultSchemaPath))
	if err != nil {
		t.Fatal(err)
	}
	if !hasMetricFeature(root, "application_service_graph_connection_info") {
		t.Fatal("connection-info feature must be accepted by the config v2 schema")
	}
}

func TestConnectionInfoFeatureMustBeInMetricsFeatureEnum(t *testing.T) {
	root := map[string]any{
		"unrelated": map[string]any{"enum": []any{"application_service_graph_connection_info"}},
		"$defs": map[string]any{"Capture": map[string]any{
			"properties": map[string]any{"metrics": map[string]any{
				"properties": map[string]any{"features": map[string]any{
					"items": map[string]any{"oneOf": []any{
						map[string]any{"enum": []any{"application_service_graph"}},
					}},
				}},
			}},
		}},
	}
	if hasMetricFeature(root, "application_service_graph_connection_info") {
		t.Fatal("an unrelated enum must not satisfy metrics.features")
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
