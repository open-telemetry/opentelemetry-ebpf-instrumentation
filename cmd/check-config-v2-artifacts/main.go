// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"go.opentelemetry.io/obi/internal/config/convert"
	configschema "go.opentelemetry.io/obi/internal/config/schema"
)

const (
	defaultSchemaPath  = "devdocs/config/version-2.0/obi-extension.schema.json"
	defaultExamplePath = "devdocs/config/version-2.0/examples/default-configuration.yaml"
)

func run(args []string) error {
	flags := flag.NewFlagSet("check-config-v2-artifacts", flag.ContinueOnError)
	schemaPath := flags.String("schema", defaultSchemaPath, "path to the hidden config v2 OBI extension schema")
	examplePath := flags.String("example", defaultExamplePath, "path to the hidden config v2 default example")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	if err := checkSchemaArtifact(*schemaPath); err != nil {
		return err
	}
	if err := checkExampleArtifact(*examplePath); err != nil {
		return err
	}

	fmt.Printf("config v2 artifacts verified: %s, %s\n", *schemaPath, *examplePath)
	return nil
}

func checkSchemaArtifact(path string) error {
	root, err := readJSONMap(path)
	if err != nil {
		return err
	}

	if got := stringValue(root, "$schema"); got != "https://json-schema.org/draft/2020-12/schema" {
		return fmt.Errorf("%s: unexpected $schema %q", path, got)
	}
	if got := stringValue(root, "$id"); got == "" {
		return fmt.Errorf("%s: missing $id", path)
	}
	if got := stringValue(root, "title"); got == "" {
		return fmt.Errorf("%s: missing title", path)
	}
	if got := stringValue(root, "type"); got != "object" {
		return fmt.Errorf("%s: unexpected root type %q", path, got)
	}
	if _, ok := mapValue(root, "$defs"); !ok {
		return fmt.Errorf("%s: missing $defs", path)
	}

	properties, ok := mapValue(root, "properties")
	if !ok {
		return fmt.Errorf("%s: missing properties", path)
	}
	version, ok := mapValue(properties, "version")
	if !ok {
		return fmt.Errorf("%s: missing properties.version", path)
	}
	if got := stringValue(version, "const"); got != configschema.SupportedVersion {
		return fmt.Errorf("%s: unexpected properties.version.const %q", path, got)
	}

	return nil
}

func checkExampleArtifact(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	doc, ext, err := configschema.ParseStandaloneYAML(data)
	if err != nil {
		return fmt.Errorf("%s: parse standalone config v2 example: %w", path, err)
	}
	if doc == nil || ext == nil {
		return fmt.Errorf("%s: missing standalone config v2 document or extension", path)
	}
	if ext.Version != configschema.SupportedVersion {
		return fmt.Errorf("%s: unexpected extension version %q", path, ext.Version)
	}
	cfg, err := convert.DocumentToRuntime(doc)
	if err != nil {
		return fmt.Errorf("%s: import standalone config v2 example: %w", path, err)
	}
	if cfg == nil {
		return fmt.Errorf("%s: imported standalone config v2 example produced nil runtime config", path)
	}

	return nil
}

func readJSONMap(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("parse %s: trailing JSON content", path)
	}
	return root, nil
}

func mapValue(root map[string]any, key string) (map[string]any, bool) {
	value, ok := root[key].(map[string]any)
	return value, ok
}

func stringValue(root map[string]any, key string) string {
	value, ok := root[key].(string)
	if !ok {
		return ""
	}
	return value
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
