// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/convert"
	configschema "go.opentelemetry.io/obi/internal/config/schema"
)

const (
	defaultSchemaPath          = "devdocs/config/version-2.0/obi-extension.schema.json"
	defaultReferencePath       = "devdocs/config/version-2.0/examples/default-values-reference.fragment.yaml"
	defaultRunnableExamplePath = "devdocs/config/version-2.0/examples/default-configuration.yaml"
	logFieldNamePattern        = `^[^=\u0000-\u0020\u007F-\u00A0\u1680\u2000-\u200A\u2028-\u2029\u202F\u205F\u3000]+$`
	logFieldNameMinLength      = int64(1)
)

func run(args []string) error {
	flags := flag.NewFlagSet("check-config-v2-artifacts", flag.ContinueOnError)
	schemaPath := flags.String("schema", defaultSchemaPath, "path to the hidden config v2 OBI extension schema")
	referencePath := flags.String(
		"default-reference",
		defaultReferencePath,
		"path to the config v2 default-values reference fragment",
	)
	runnableExamplePath := flags.String(
		"runnable-example",
		defaultRunnableExamplePath,
		"path to the runnable standalone config v2 example",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	if err := checkSchemaArtifact(*schemaPath); err != nil {
		return err
	}
	if err := checkDefaultReferenceArtifact(*referencePath); err != nil {
		return err
	}
	if err := checkRunnableExampleArtifact(*runnableExamplePath); err != nil {
		return err
	}

	fmt.Printf(
		"config v2 artifacts verified: %s, %s, %s\n",
		*schemaPath,
		*referencePath,
		*runnableExamplePath,
	)
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
	if err := checkLogFieldNameSchema(root); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	return nil
}

func checkLogFieldNameSchema(root map[string]any) error {
	definitions, ok := mapValue(root, "$defs")
	if !ok {
		return errors.New("missing $defs")
	}
	traceAnnotation, ok := mapValue(definitions, "TraceAnnotation")
	if !ok {
		return errors.New("missing $defs.TraceAnnotation")
	}
	properties, ok := mapValue(traceAnnotation, "properties")
	if !ok {
		return errors.New("missing $defs.TraceAnnotation.properties")
	}
	fieldNames, ok := mapValue(properties, "field_names")
	if !ok {
		return errors.New("missing log field_names schema")
	}
	fields, ok := mapValue(fieldNames, "properties")
	if !ok {
		return errors.New("missing log field_names properties")
	}

	for _, name := range []string{"trace_id", "span_id"} {
		field, ok := mapValue(fields, name)
		if !ok {
			return fmt.Errorf("missing log field_names.%s schema", name)
		}
		if got := stringValue(field, "pattern"); got != logFieldNamePattern {
			return fmt.Errorf("unexpected log field_names.%s pattern %q", name, got)
		}
		if got, ok := integerValue(field, "minLength"); !ok || got != logFieldNameMinLength {
			return fmt.Errorf("unexpected log field_names.%s minLength", name)
		}
	}

	return nil
}

func checkDefaultReferenceArtifact(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("%s: parse config v2 default-values reference: %w", path, err)
	}
	if _, ok := root["file_format"]; ok {
		return fmt.Errorf("%s: default-values reference must not be a standalone document", path)
	}

	document := append([]byte("file_format: \"1.0\"\n"), data...)
	doc, ext, err := configschema.ParseStandaloneYAML(document)
	if err != nil {
		return fmt.Errorf("%s: parse config v2 default-values reference: %w", path, err)
	}
	if doc == nil || ext == nil {
		return fmt.Errorf("%s: missing config v2 reference document or extension", path)
	}
	if ext.Version != configschema.SupportedVersion {
		return fmt.Errorf("%s: unexpected extension version %q", path, ext.Version)
	}
	cfg, err := convert.DocumentToRuntime(doc)
	if err != nil {
		return fmt.Errorf("%s: import config v2 default-values reference: %w", path, err)
	}
	if cfg == nil {
		return fmt.Errorf("%s: imported config v2 default-values reference produced nil runtime config", path)
	}

	return nil
}

func checkRunnableExampleArtifact(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	doc, ext, err := configschema.ParseStandaloneYAML(data)
	if err != nil {
		return fmt.Errorf("%s: parse runnable standalone config v2 example: %w", path, err)
	}
	if doc == nil || ext == nil {
		return fmt.Errorf("%s: missing runnable config v2 document or extension", path)
	}
	if ext.Version != configschema.SupportedVersion {
		return fmt.Errorf("%s: unexpected extension version %q", path, ext.Version)
	}
	cfg, err := convert.DocumentToRuntime(doc)
	if err != nil {
		return fmt.Errorf("%s: import runnable standalone config v2 example: %w", path, err)
	}
	if err := cfg.ValidateStatic(); err != nil {
		return fmt.Errorf("%s: validate runnable standalone config v2 example: %w", path, err)
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

func integerValue(root map[string]any, key string) (int64, bool) {
	value, ok := root[key].(json.Number)
	if !ok {
		return 0, false
	}
	integer, err := value.Int64()
	return integer, err == nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
