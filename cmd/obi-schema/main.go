// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// obi-schema generates a JSON schema from the OBI configuration struct.
// Usage:
//
//	go run ./cmd/obi-schema > config-schema.json
//	go run ./cmd/obi-schema -output schema.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/invopop/jsonschema"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/obi"
)

// enumRegistry maps type names to their valid enum values.
// This is populated by scanning source files at startup.
var enumRegistry = make(map[string][]any)

// envVarRegistry maps (typeName, yamlFieldName) to environment variable names.
// This is populated by scanning source files at startup.
var envVarRegistry = make(map[string]map[string]string)

// inlineFieldRegistry maps typeName to a list of inline field type names.
// This is populated by scanning source files at startup.
var inlineFieldRegistry = make(map[string][]string)

// packagesToScan lists packages that contain types used in the config
var packagesToScan = []string{
	"pkg/obi",
	"pkg/config",
	"pkg/export",
	"pkg/export/debug",
	"pkg/export/imetrics",
	"pkg/export/instrumentations",
	"pkg/export/otel/otelcfg",
	"pkg/export/otel",
	"pkg/export/otel/perapp",
	"pkg/export/prom",
	"pkg/kube/kubeflags",
	"pkg/internal/netolly/flow",
	"pkg/transform",
	"pkg/filter",
	"pkg/appolly/services",
}

func scanModuleEnums() {
	moduleRoot := findModuleRoot(filepath.Dir("../.."))
	if moduleRoot == "" {
		fmt.Fprintln(os.Stderr, "Warning: could not find module root for enum extraction")
		return
	}

	for _, pkg := range packagesToScan {
		pkgPath := filepath.Join(moduleRoot, pkg)
		if err := scanPackageForEnums(pkgPath); err != nil {
			// exit and error
			fmt.Fprintf(os.Stderr, "Error scanning package %s for enums: %v\n", pkg, err)
			os.Exit(1)
		}
	}
}

func scanModuleEnvVars() {
	moduleRoot := findModuleRoot(filepath.Dir("../.."))
	if moduleRoot == "" {
		fmt.Fprintln(os.Stderr, "Warning: could not find module root for env var extraction")
		return
	}

	for _, pkg := range packagesToScan {
		pkgPath := filepath.Join(moduleRoot, pkg)
		if err := scanPackageForEnvVars(pkgPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning package %s for env vars: %v\n", pkg, err)
			os.Exit(1)
		}
	}
}

func scanPackageForEnvVars(pkgPath string) error {
	entries, err := os.ReadDir(pkgPath)
	if err != nil {
		return err
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		filePath := filepath.Join(pkgPath, entry.Name())
		file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", filePath, err)
		}
		extractEnvVarsFromFile(file)
	}
	return nil
}

func extractEnvVarsFromFile(file *ast.File) {
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}

		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			typeName := typeSpec.Name.Name
			if envVarRegistry[typeName] == nil {
				envVarRegistry[typeName] = make(map[string]string)
			}

			for _, field := range structType.Fields.List {
				if field.Tag == nil {
					continue
				}

				tag := strings.Trim(field.Tag.Value, "`")
				yamlName := extractTagValue(tag, "yaml")
				envVar := extractTagValue(tag, "env")

				// Check for inline fields (yaml:",inline")
				if strings.Contains(yamlName, "inline") || yamlName == ",inline" {
					// Get the type name of the inline field
					inlineTypeName := exprToTypeName(field.Type)
					if inlineTypeName != "" {
						inlineFieldRegistry[typeName] = append(inlineFieldRegistry[typeName], inlineTypeName)
					}
					continue
				}

				if yamlName != "" && envVar != "" {
					// Remove options from yaml tag (e.g., "field,omitempty" -> "field")
					if idx := strings.Index(yamlName, ","); idx != -1 {
						yamlName = yamlName[:idx]
					}
					// Remove options from env tag (e.g., "VAR,expand" -> "VAR")
					if idx := strings.Index(envVar, ","); idx != -1 {
						envVar = envVar[:idx]
					}
					// Skip env vars that are just variable expansions
					if !strings.HasPrefix(envVar, "${") {
						envVarRegistry[typeName][yamlName] = envVar
					}
				}
			}
		}
	}
}

// extractTagValue extracts the value for a given key from a struct tag string.
func extractTagValue(tag, key string) string {
	// Look for key:"value"
	search := key + `:"`
	idx := strings.Index(tag, search)
	if idx == -1 {
		return ""
	}
	start := idx + len(search)
	end := strings.Index(tag[start:], `"`)
	if end == -1 {
		return ""
	}
	return tag[start : start+end]
}

func findModuleRoot(start string) string {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func scanPackageForEnums(pkgPath string) error {
	entries, err := os.ReadDir(pkgPath)
	if err != nil {
		return err
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		// Skip test files
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		filePath := filepath.Join(pkgPath, entry.Name())
		file, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", filePath, err)
		}
		extractEnumsFromFile(file)
	}
	return nil
}

func extractEnumsFromFile(file *ast.File) {
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}

		// Track the current type for iota-style declarations
		var currentType string

		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			// Get the type name from this spec or inherit from previous
			if valueSpec.Type != nil {
				currentType = exprToTypeName(valueSpec.Type)
			}

			// Extract the string value from the const
			for i, name := range valueSpec.Names {
				if name.Name == "_" || !name.IsExported() {
					continue
				}

				if i < len(valueSpec.Values) {
					typeName, value := extractConstValueAndType(valueSpec.Values[i], currentType)
					if typeName != "" && value != nil {
						enumRegistry[typeName] = append(enumRegistry[typeName], value)
					}
				}
			}
		}
	}
}

func exprToTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// extractConstValueAndType extracts both the type name and value from a const expression.
// It handles patterns like:
//   - TypeName("value") - type conversion with string literal
//   - "value" - bare string literal (uses inherited type)
func extractConstValueAndType(expr ast.Expr, inheritedType string) (typeName string, value any) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		// Bare string literal - use inherited type
		if e.Kind == token.STRING {
			return inheritedType, strings.Trim(e.Value, `"`)
		}
	case *ast.CallExpr:
		// Type conversion like LogLevel("DEBUG") or TracePrinter("disabled")
		callTypeName := exprToTypeName(e.Fun)
		if callTypeName != "" && len(e.Args) == 1 {
			if lit, ok := e.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				return callTypeName, strings.Trim(lit.Value, `"`)
			}
		}
	case *ast.BinaryExpr:
		// For iota-based enums with bit operations, we can't easily extract
		// the runtime value
		return "", nil
	case *ast.Ident:
		// Reference to another const (like iota)
		return "", nil
	}
	return "", nil
}

func main() {
	outputFile := flag.String("output", "", "Output file path (default: stdout)")
	flag.Parse()
	reflector := &jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true,
		AllowAdditionalProperties:  true,
		ExpandedStruct:             true,
		FieldNameTag:               "yaml",
		Mapper:                     customMapper,
	}
	if err := reflector.AddGoComments("go.opentelemetry.io/obi", "./"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not add Go comments: %v\n", err)
	}

	scanModuleEnums()
	scanModuleEnvVars()
	schema := reflector.Reflect(&obi.Config{})
	schema.Title = "OBI Configuration Schema"
	schema.Description = "JSON Schema for OpenTelemetry eBPF Instrumentation (OBI) configuration"

	// Process inline fields first (merge properties from inline types)
	processInlineFields(schema)

	// Process deprecated annotations from comments
	processDeprecated(schema)

	// Add environment variable annotations
	processEnvVars(schema)

	// Sort properties for deterministic output
	sortSchemaProperties(schema)

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling schema: %v\n", err)
		os.Exit(1)
	}

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Schema written to %s\n", *outputFile)
	} else {
		fmt.Println(string(data))
	}
}

// inlineTypeSchemas maps inline type names to functions that return their schema.
// This is needed because these types implement JSONSchema() and aren't in definitions.
var inlineTypeSchemas = map[string]func() *jsonschema.Schema{
	"MetadataGlobMap":  func() *jsonschema.Schema { return services.MetadataGlobMap(nil).JSONSchema() },
	"MetadataRegexMap": func() *jsonschema.Schema { return services.MetadataRegexMap(nil).JSONSchema() },
}

// processInlineFields merges properties from inline field types into their parent schemas.
func processInlineFields(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	// Process each definition that has inline fields
	for typeName, inlineTypes := range inlineFieldRegistry {
		defSchema, ok := schema.Definitions[typeName]
		if !ok {
			continue
		}

		for _, inlineTypeName := range inlineTypes {
			// First try to get from definitions
			inlineSchema, ok := schema.Definitions[inlineTypeName]
			if !ok {
				// Try to get from our inline type schema registry
				if schemaFunc, found := inlineTypeSchemas[inlineTypeName]; found {
					inlineSchema = schemaFunc()
				}
			}

			if inlineSchema == nil {
				continue
			}

			// Merge properties from inline schema into parent schema
			if inlineSchema.Properties != nil && defSchema.Properties != nil {
				for pair := inlineSchema.Properties.Oldest(); pair != nil; pair = pair.Next() {
					// Only add if not already present
					if _, exists := defSchema.Properties.Get(pair.Key); !exists {
						defSchema.Properties.Set(pair.Key, pair.Value)
					}
				}
			}
		}
	}
}

// processEnvVars walks through all schemas and adds x-env-var extension
// for properties that have corresponding environment variables.
func processEnvVars(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	// Process definitions - these are named types
	for typeName, defSchema := range schema.Definitions {
		if envVars, ok := envVarRegistry[typeName]; ok {
			addEnvVarsToProperties(defSchema, envVars)
		}
		// Recursively process nested schemas
		processEnvVars(defSchema)
	}

	// Process root schema properties (for Config type)
	if envVars, ok := envVarRegistry["Config"]; ok {
		addEnvVarsToProperties(schema, envVars)
	}
}

// addEnvVarsToProperties adds x-env-var extension to properties that have env vars.
func addEnvVarsToProperties(schema *jsonschema.Schema, envVars map[string]string) {
	if schema == nil || schema.Properties == nil {
		return
	}

	for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
		propName := pair.Key
		propSchema := pair.Value

		if envVar, ok := envVars[propName]; ok {
			if propSchema.Extras == nil {
				propSchema.Extras = make(map[string]any)
			}
			propSchema.Extras["x-env-var"] = envVar
		}
	}
}

// sortSchemaProperties sorts all properties and enums in the schema alphabetically for deterministic output.
func sortSchemaProperties(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	// Sort the root schema
	sortSchema(schema)

	// Sort all definitions
	for _, defSchema := range schema.Definitions {
		sortSchema(defSchema)
	}
}

// sortSchema sorts properties and enum values of a schema alphabetically.
func sortSchema(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	// Sort enum values if present
	if len(schema.Enum) > 0 {
		sort.Slice(schema.Enum, func(i, j int) bool {
			return fmt.Sprint(schema.Enum[i]) < fmt.Sprint(schema.Enum[j])
		})
	}

	// Sort properties if present
	if schema.Properties != nil {
		var keys []string
		for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
			keys = append(keys, pair.Key)
		}
		sort.Strings(keys)

		newProps := jsonschema.NewProperties()
		for _, key := range keys {
			if val, ok := schema.Properties.Get(key); ok {
				newProps.Set(key, val)
				sortSchema(val)
			}
		}
		schema.Properties = newProps
	}

	// Recursively sort nested schemas
	sortSchema(schema.Items)
	sortSchema(schema.AdditionalProperties)
	for _, s := range schema.AllOf {
		sortSchema(s)
	}
	for _, s := range schema.AnyOf {
		sortSchema(s)
	}
	for _, s := range schema.OneOf {
		sortSchema(s)
	}
}

// processDeprecated walks through all schemas and extracts "Deprecated:" from
// descriptions, setting the Deprecated field accordingly.
func processDeprecated(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	// Process the schema's own description
	processSchemaDeprecation(schema)

	// Process properties
	if schema.Properties != nil {
		for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
			processDeprecated(pair.Value)
		}
	}

	// Process definitions
	for _, defSchema := range schema.Definitions {
		processDeprecated(defSchema)
	}

	// Process nested schemas
	for _, s := range schema.AllOf {
		processDeprecated(s)
	}
	for _, s := range schema.AnyOf {
		processDeprecated(s)
	}
	for _, s := range schema.OneOf {
		processDeprecated(s)
	}
	processDeprecated(schema.Not)
	processDeprecated(schema.If)
	processDeprecated(schema.Then)
	processDeprecated(schema.Else)
	processDeprecated(schema.Items)
	processDeprecated(schema.Contains)
	processDeprecated(schema.AdditionalProperties)
	for _, s := range schema.PrefixItems {
		processDeprecated(s)
	}
	for _, s := range schema.PatternProperties {
		processDeprecated(s)
	}
	for _, s := range schema.DependentSchemas {
		processDeprecated(s)
	}
}

// processSchemaDeprecation checks if a schema's description contains
// "Deprecated:" and sets the Deprecated field accordingly.
func processSchemaDeprecation(schema *jsonschema.Schema) {
	if schema == nil || schema.Description == "" {
		return
	}

	desc := schema.Description
	lowerDesc := strings.ToLower(desc)

	// Check for "Deprecated:" at the start of the description
	if strings.HasPrefix(lowerDesc, "deprecated:") {
		schema.Deprecated = true
		schema.Description = strings.TrimSpace(desc[len("deprecated:"):])
		return
	}
	if lowerDesc == "deprecated" {
		schema.Deprecated = true
		schema.Description = ""
		return
	}

	// Check for "Deprecated:" at the start of any line (for multi-line comments)
	lines := strings.Split(desc, "\n")
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		lowerLine := strings.ToLower(trimmedLine)

		if strings.HasPrefix(lowerLine, "deprecated:") {
			schema.Deprecated = true
			// Remove the deprecated line and merge remaining content
			deprecationMsg := strings.TrimSpace(trimmedLine[len("deprecated:"):])
			// Keep lines before, skip the "Deprecated:" line, keep lines after
			var newLines []string
			newLines = append(newLines, lines[:i]...)
			if deprecationMsg != "" {
				newLines = append(newLines, deprecationMsg)
			}
			newLines = append(newLines, lines[i+1:]...)
			schema.Description = strings.TrimSpace(strings.Join(newLines, "\n"))
			return
		}
		if lowerLine == "deprecated" {
			schema.Deprecated = true
			var newLines []string
			newLines = append(newLines, lines[:i]...)
			newLines = append(newLines, lines[i+1:]...)
			schema.Description = strings.TrimSpace(strings.Join(newLines, "\n"))
			return
		}
	}
}

// jsonSchemaPropertyType is the interface used by invopop/jsonschema to detect
// types that provide their own JSONSchema implementation.
var jsonSchemaPropertyType = reflect.TypeOf((*interface{ JSONSchema() *jsonschema.Schema })(nil)).Elem()

// customMapper handles types that the default reflector cannot process
// and provides enum values for string-typed constants.
func customMapper(t reflect.Type) *jsonschema.Schema {
	// Skip types that implement JSONSchema() - let the reflector handle them
	if t.Implements(jsonSchemaPropertyType) || reflect.PointerTo(t).Implements(jsonSchemaPropertyType) {
		return nil
	}

	// Skip function types - they are not serializable in JSON/YAML
	if t.Kind() == reflect.Func {
		return &jsonschema.Schema{
			Type:        "null",
			Description: "Function type (not serializable)",
		}
	}

	// Handle time.Duration as a string (Go duration format)
	if t == reflect.TypeOf(time.Duration(0)) {
		return &jsonschema.Schema{
			Type:        "string",
			Description: "Duration in Go format (e.g., '30s', '5m', '1ms')",
			Pattern:     "^[0-9]+(ms|s|m)$",
			Examples:    []any{"30s", "5m", "1ms"},
		}
	}

	// Check if this type has enum values in our registry
	typeName := t.Name()
	if values, ok := enumRegistry[typeName]; ok && len(values) > 0 {
		return &jsonschema.Schema{
			Type: "string",
			Enum: values,
		}
	}

	return nil
}
