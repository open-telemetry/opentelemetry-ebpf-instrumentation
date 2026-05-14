// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/internal/configconv"
	"go.opentelemetry.io/obi/pkg/obi"
)

func main() {
	schemaPath := flag.String("schema", "", "write the v2 schema to this path")
	examplePath := flag.String("example", "", "write the default v2 example to this path")
	flag.Parse()

	if *schemaPath == "" && *examplePath == "" {
		log.Fatal("at least one of -schema or -example must be set")
	}

	if *schemaPath != "" {
		writeJSON(*schemaPath, schema())
	}

	if *examplePath != "" {
		doc, err := configconv.RuntimeToDocument(&obi.DefaultConfig)
		if err != nil {
			log.Fatalf("building default v2 example: %v", err)
		}
		writeYAML(*examplePath, doc)
	}
}

func writeJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("marshal json %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		log.Fatalf("write json %s: %v", path, err)
	}
}

func writeYAML(path string, v any) {
	data, err := yaml.Marshal(v)
	if err != nil {
		log.Fatalf("marshal yaml %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write yaml %s: %v", path, err)
	}
}

func schema() map[string]any {
	return map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"$id":                  "https://opentelemetry.io/obi/schemas/obi-extension.schema.json",
		"title":                "OBI Extension Configuration",
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"version"},
		"properties": map[string]any{
			"version": map[string]any{
				"type":  "string",
				"const": "2.0",
			},
			"capture": map[string]any{
				"type":                 "object",
				"additionalProperties": true,
			},
			"enrich": map[string]any{
				"type":                 "object",
				"additionalProperties": true,
			},
			"correlation": map[string]any{
				"type":                 "object",
				"additionalProperties": true,
			},
			"daemon": map[string]any{
				"type":                 "object",
				"additionalProperties": true,
			},
		},
	}
}
