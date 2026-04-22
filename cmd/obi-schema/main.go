// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// obi-schema generates a JSON schema from the OBI configuration struct.
// Usage:
//
//	go run ./cmd/obi-schema > config-schema.json
//	go run ./cmd/obi-schema -output schema.json
package main

import (
	"bytes"
	"encoding"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/invopop/jsonschema"

	"go.opentelemetry.io/obi/pkg/obi"
)

// SchemaGenerator holds the state for schema generation.
type SchemaGenerator struct {
	// enums maps type names to their valid enum values.
	enums map[string][]any
	// envVars maps (typeName, yamlFieldName) to environment variable names.
	envVars map[string]map[string]string
	// inlineFields maps typeName to a list of inline field type names.
	inlineFields map[string][]string
	// noYaml tracks (typeName, propertyName) for fields with no yaml tag.
	noYaml map[string]map[string]bool
	// goFieldNames maps (typeName, propertyKey) to the Go field name,
	// so we can strip it from descriptions.
	goFieldNames map[string]map[string]string
}

// NewSchemaGenerator creates a new SchemaGenerator with initialized registries.
func NewSchemaGenerator() *SchemaGenerator {
	return &SchemaGenerator{
		enums:        make(map[string][]any),
		envVars:      make(map[string]map[string]string),
		inlineFields: make(map[string][]string),
		noYaml:       make(map[string]map[string]bool),
		goFieldNames: make(map[string]map[string]string),
	}
}

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
	"pkg/transform",
	"pkg/filter",
	"pkg/appolly/services",
	"pkg/appolly/meta",
	"pkg/internal/pipe/geoip",
	"pkg/internal/pipe/rdns",
}

// scanSourceFiles scans all Go source files in packagesToScan and extracts metadata.
func (g *SchemaGenerator) scanSourceFiles() {
	moduleRoot := findModuleRoot(filepath.Dir("../.."))
	if moduleRoot == "" {
		fmt.Fprintln(os.Stderr, "Warning: could not find module root")
		return
	}

	fset := token.NewFileSet()
	for _, pkg := range packagesToScan {
		pkgPath := filepath.Join(moduleRoot, pkg)
		entries, err := os.ReadDir(pkgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading package %s: %v\n", pkg, err)
			os.Exit(1)
		}

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
				fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", filePath, err)
				os.Exit(1)
			}
			g.extractFileMetadata(file)
		}
	}
}

// extractFileMetadata extracts all metadata from a Go source file in a single pass.
func (g *SchemaGenerator) extractFileMetadata(file *ast.File) {
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}

		switch genDecl.Tok {
		case token.CONST:
			g.extractEnumsFromDecl(genDecl)
		case token.TYPE:
			g.extractStructMetadataFromDecl(genDecl)
		}
	}
}

// extractEnumsFromDecl extracts enum values from a const declaration.
func (g *SchemaGenerator) extractEnumsFromDecl(genDecl *ast.GenDecl) {
	var currentType string

	for _, spec := range genDecl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}

		if valueSpec.Type != nil {
			currentType = exprToTypeName(valueSpec.Type)
		}

		for i, name := range valueSpec.Names {
			if name.Name == "_" || !name.IsExported() {
				continue
			}

			if i < len(valueSpec.Values) {
				typeName, value := extractConstValueAndType(valueSpec.Values[i], currentType)
				if typeName != "" && value != nil {
					g.enums[typeName] = append(g.enums[typeName], value)
				}
			}
		}
	}
}

// extractStructMetadataFromDecl extracts env vars and inline fields from a type declaration.
func (g *SchemaGenerator) extractStructMetadataFromDecl(genDecl *ast.GenDecl) {
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
		if g.envVars[typeName] == nil {
			g.envVars[typeName] = make(map[string]string)
		}

		for _, field := range structType.Fields.List {
			if field.Tag == nil {
				continue
			}

			tag := strings.Trim(field.Tag.Value, "`")
			yamlName := extractTagValue(tag, "yaml")

			// Handle inline fields
			if strings.Contains(yamlName, "inline") || yamlName == ",inline" {
				g.extractInlineField(typeName, field)
				continue
			}

			// If no yaml tag, fall back to the Go field name (which is what
			// the JSON schema reflector uses as the property key).
			if yamlName == "" && len(field.Names) > 0 {
				yamlName = field.Names[0].Name
				// Track that this field has no yaml tag
				if g.noYaml[typeName] == nil {
					g.noYaml[typeName] = make(map[string]bool)
				}
				g.noYaml[typeName][yamlName] = true
			}

			// Track Go field name -> property key mapping for description cleanup.
			// Remove options from yaml name for the property key.
			propKey := yamlName
			if idx := strings.Index(propKey, ","); idx != -1 {
				propKey = propKey[:idx]
			}
			if len(field.Names) > 0 && field.Names[0].Name != propKey {
				if g.goFieldNames[typeName] == nil {
					g.goFieldNames[typeName] = make(map[string]string)
				}
				g.goFieldNames[typeName][propKey] = field.Names[0].Name
			}

			// Handle env vars
			g.extractEnvVar(typeName, tag, yamlName)
		}
	}
}

// extractInlineField records an inline field relationship.
func (g *SchemaGenerator) extractInlineField(parentType string, field *ast.Field) {
	inlineTypeName := exprToTypeName(field.Type)
	if inlineTypeName != "" {
		g.inlineFields[parentType] = append(g.inlineFields[parentType], inlineTypeName)
	}
}

// extractEnvVar extracts environment variable mapping from a struct field.
func (g *SchemaGenerator) extractEnvVar(typeName, tag, yamlName string) {
	envVar := extractTagValue(tag, "env")
	if yamlName == "" || envVar == "" {
		return
	}

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
		g.envVars[typeName][yamlName] = envVar
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

	g := NewSchemaGenerator()

	// Scan source files to populate registries
	g.scanSourceFiles()

	reflector := &jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true,
		AllowAdditionalProperties:  true,
		ExpandedStruct:             true,
		FieldNameTag:               "yaml",
		Mapper:                     g.customMapper(),
	}
	if err := reflector.AddGoComments("go.opentelemetry.io/obi", "./", jsonschema.WithFullComment()); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not add Go comments: %v\n", err)
	}

	schema := reflector.Reflect(&obi.Config{})
	schema.Title = "OBI Configuration Schema"
	schema.Description = "JSON Schema for OpenTelemetry eBPF Instrumentation (OBI) configuration"

	// Process inline fields first (merge properties from inline types)
	g.processInlineFields(schema)

	// Process deprecated annotations from comments
	processDeprecated(schema)

	// Add environment variable annotations
	g.processEnvVars(schema)

	// Normalize descriptions: collapse newlines into single spaces
	normalizeDescriptions(schema)

	// Mark fields with no yaml tag and strip Go field name prefixes from descriptions
	g.processFieldAnnotations(schema)

	// Add default values from DefaultConfig
	addDefaults(schema)

	// Sort properties for deterministic output
	sortSchemaProperties(schema)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(schema); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding schema: %v\n", err)
		os.Exit(1)
	}

	// The jsonschema library's custom MarshalJSON methods use json.Marshal
	// internally, which HTML-escapes <, >, and & even though they're valid
	// in JSON strings. Undo that escaping for readability.
	data := buf.String()
	data = strings.ReplaceAll(data, `\u003c`, `<`)
	data = strings.ReplaceAll(data, `\u003e`, `>`)
	data = strings.ReplaceAll(data, `\u0026`, `&`)

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(data), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Schema written to %s\n", *outputFile)
	} else {
		fmt.Print(data)
	}
}

// jsonSchemaer is the interface for types that provide custom JSON schemas.
type jsonSchemaer interface {
	JSONSchema() *jsonschema.Schema
}

// buildInlineTypeSchemas uses reflection to find inline fields that implement JSONSchema().
// It walks the type hierarchy starting from rootType and returns a map of type name to schema function.
func buildInlineTypeSchemas(rootType reflect.Type) map[string]func() *jsonschema.Schema {
	result := make(map[string]func() *jsonschema.Schema)
	visited := make(map[reflect.Type]bool)

	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		// Unwrap pointers
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}

		// Handle slices and arrays - walk the element type
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			walk(t.Elem())
			return
		}

		// Handle maps - walk the value type
		if t.Kind() == reflect.Map {
			walk(t.Elem())
			return
		}

		// Only process structs
		if t.Kind() != reflect.Struct {
			return
		}

		// Avoid infinite recursion
		if visited[t] {
			return
		}
		visited[t] = true

		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			yamlTag := field.Tag.Get("yaml")

			// Check if this is an inline field
			if strings.Contains(yamlTag, "inline") {
				fieldType := field.Type
				// Handle pointer types
				for fieldType.Kind() == reflect.Pointer {
					fieldType = fieldType.Elem()
				}

				// Check if it implements JSONSchema()
				if hasJSONSchemaMethod(fieldType) {
					typeName := fieldType.Name()
					// Capture fieldType in closure
					ft := fieldType
					result[typeName] = func() *jsonschema.Schema {
						return callJSONSchemaMethod(ft)
					}
				}
			}

			// Recursively walk nested types
			walk(field.Type)
		}
	}

	walk(rootType)
	return result
}

// hasJSONSchemaMethod checks if a type implements the JSONSchema() method.
func hasJSONSchemaMethod(t reflect.Type) bool {
	return t.Implements(jsonSchemaerType) || reflect.PointerTo(t).Implements(jsonSchemaerType)
}

// callJSONSchemaMethod calls the JSONSchema() method on a zero value of the given type.
func callJSONSchemaMethod(t reflect.Type) *jsonschema.Schema {
	// Try value receiver first
	method, ok := t.MethodByName("JSONSchema")
	if ok {
		zero := reflect.Zero(t)
		results := method.Func.Call([]reflect.Value{zero})
		if len(results) == 1 {
			if schema, ok := results[0].Interface().(*jsonschema.Schema); ok {
				return schema
			}
		}
	}

	// Try pointer receiver
	method, ok = reflect.PointerTo(t).MethodByName("JSONSchema")
	if ok {
		zero := reflect.New(t)
		results := method.Func.Call([]reflect.Value{zero})
		if len(results) == 1 {
			if schema, ok := results[0].Interface().(*jsonschema.Schema); ok {
				return schema
			}
		}
	}

	return nil
}

// processInlineFields merges properties from inline field types into their parent schemas.
func (g *SchemaGenerator) processInlineFields(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	// Build inline type schemas dynamically using reflection
	inlineTypeSchemas := buildInlineTypeSchemas(reflect.TypeFor[obi.Config]())

	// Process each definition that has inline fields
	for typeName, inlineTypes := range g.inlineFields {
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
func (g *SchemaGenerator) processEnvVars(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	// Process definitions - these are named types
	for typeName, defSchema := range schema.Definitions {
		if envVars, ok := g.envVars[typeName]; ok {
			addEnvVarsToProperties(defSchema, envVars)
		}
		// Recursively process nested schemas
		g.processEnvVars(defSchema)
	}

	// Process root schema properties (for Config type)
	if envVars, ok := g.envVars["Config"]; ok {
		addEnvVarsToProperties(schema, envVars)
	}
}

// processFieldAnnotations walks all types and their properties to:
//   - mark fields with no yaml tag (x-no-yaml: true)
//   - strip Go field name prefixes from descriptions
func (g *SchemaGenerator) processFieldAnnotations(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}

	process := func(typeName string, target *jsonschema.Schema) {
		if target == nil || target.Properties == nil {
			return
		}
		noYamlFields := g.noYaml[typeName]
		goNames := g.goFieldNames[typeName]

		for pair := target.Properties.Oldest(); pair != nil; pair = pair.Next() {
			propSchema := pair.Value

			// Mark fields with no yaml tag
			if noYamlFields[pair.Key] {
				if propSchema.Extras == nil {
					propSchema.Extras = make(map[string]any)
				}
				propSchema.Extras["x-no-yaml"] = true
			}

			// Strip Go field name prefix from description
			if propSchema.Description != "" {
				propSchema.Description = stripNamePrefix(propSchema.Description, pair.Key, goNames[pair.Key])
			}
		}
	}

	// Process root schema (Config type)
	process("Config", schema)

	// Process all definitions
	for typeName, defSchema := range schema.Definitions {
		process(typeName, defSchema)
	}
}

// stripNamePrefix removes a Go field or property name prefix from a description.
// Go doc comments conventionally start with the field name (e.g. "Exec allows selecting...").
func stripNamePrefix(desc, propKey, goName string) string {
	// Try the Go field name first (e.g. "Exec" for yaml key "executable_path")
	if goName != "" {
		if rest, ok := strings.CutPrefix(desc, goName); ok {
			rest = strings.TrimSpace(rest)
			if len(rest) > 0 {
				return strings.ToUpper(rest[:1]) + rest[1:]
			}
		}
	}
	// Try the property key (for fields without yaml tag, key = Go name)
	if rest, ok := strings.CutPrefix(desc, propKey); ok {
		rest = strings.TrimSpace(rest)
		if len(rest) > 0 {
			return strings.ToUpper(rest[:1]) + rest[1:]
		}
	}
	return desc
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

// visitNestedSchemas recursively visits all nested schemas and calls the visitor function.
func visitNestedSchemas(schema *jsonschema.Schema, visitor func(*jsonschema.Schema)) {
	if schema == nil {
		return
	}
	visitor(schema)

	// Visit properties
	if schema.Properties != nil {
		for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
			visitNestedSchemas(pair.Value, visitor)
		}
	}

	// Visit definitions
	for _, s := range schema.Definitions {
		visitNestedSchemas(s, visitor)
	}

	// Visit single nested schemas
	for _, s := range []*jsonschema.Schema{
		schema.Not, schema.If, schema.Then, schema.Else,
		schema.Items, schema.Contains, schema.AdditionalProperties,
	} {
		visitNestedSchemas(s, visitor)
	}

	// Visit schema slices
	for _, list := range [][]*jsonschema.Schema{
		schema.AllOf, schema.AnyOf, schema.OneOf, schema.PrefixItems,
	} {
		for _, s := range list {
			visitNestedSchemas(s, visitor)
		}
	}

	// Visit schema maps
	for _, m := range []map[string]*jsonschema.Schema{
		schema.PatternProperties, schema.DependentSchemas,
	} {
		for _, s := range m {
			visitNestedSchemas(s, visitor)
		}
	}
}

// sortSchemaProperties sorts all properties and enums in the schema alphabetically for deterministic output.
func sortSchemaProperties(schema *jsonschema.Schema) {
	visitNestedSchemas(schema, sortSchemaNode)
}

// sortSchemaNode sorts properties and enum values of a single schema node.
func sortSchemaNode(schema *jsonschema.Schema) {
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
			}
		}
		schema.Properties = newProps
	}
}

// processDeprecated walks through all schemas and extracts "Deprecated:" from
// descriptions, setting the Deprecated field accordingly.
func processDeprecated(schema *jsonschema.Schema) {
	visitNestedSchemas(schema, processSchemaDeprecation)
}

// processSchemaDeprecation checks if a schema's description contains
// "Deprecated:" and sets the Deprecated field accordingly.
func processSchemaDeprecation(schema *jsonschema.Schema) {
	if schema == nil || schema.Description == "" {
		return
	}

	lines := strings.Split(schema.Description, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(lower, "deprecated:") {
			schema.Deprecated = true
			msg := strings.TrimSpace(trimmed[len("deprecated:"):])
			lines[i] = msg
			schema.Description = strings.TrimSpace(strings.Join(lines, "\n"))
			return
		}
		if lower == "deprecated" {
			schema.Deprecated = true
			lines = append(lines[:i], lines[i+1:]...)
			schema.Description = strings.TrimSpace(strings.Join(lines, "\n"))
			return
		}
	}
}

// normalizeDescriptions collapses newlines in all schema descriptions into single spaces.
func normalizeDescriptions(schema *jsonschema.Schema) {
	visitNestedSchemas(schema, func(s *jsonschema.Schema) {
		if s == nil || s.Description == "" {
			return
		}
		s.Description = strings.ReplaceAll(s.Description, "\n", " ")
	})
}

// jsonSchemaerType is the reflect.Type for the jsonSchemaer interface.
var jsonSchemaerType = reflect.TypeFor[jsonSchemaer]()

// customMapper returns a mapper function that handles types the default reflector cannot process
// and provides enum values for string-typed constants.
func (g *SchemaGenerator) customMapper() func(reflect.Type) *jsonschema.Schema {
	return func(t reflect.Type) *jsonschema.Schema {
		// Skip types that implement JSONSchema() - let the reflector handle them
		if t.Implements(jsonSchemaerType) || reflect.PointerTo(t).Implements(jsonSchemaerType) {
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
		if t == reflect.TypeFor[time.Duration]() {
			return &jsonschema.Schema{
				Type:        "string",
				Description: "Duration in Go format (e.g., '30s', '5m', '1ms')",
				Pattern:     "^[0-9]+(ms|s|m)$",
				Examples:    []any{"30s", "5m", "1ms"},
			}
		}

		// Check if this type has enum values in our registry
		typeName := t.Name()
		if values, ok := g.enums[typeName]; ok && len(values) > 0 {
			return &jsonschema.Schema{
				Type: "string",
				Enum: values,
			}
		}

		return nil
	}
}

// addDefaults extracts default values from obi.DefaultConfig and sets
// them on matching schema properties via the standard "default" keyword.
func addDefaults(schema *jsonschema.Schema) {
	defaults := structToMap(reflect.ValueOf(obi.DefaultConfig), "yaml")
	applyDefaults(schema, defaults, schema)
}

// applyDefaults recursively walks schema properties and sets defaults from the map.
func applyDefaults(schema *jsonschema.Schema, defaults map[string]any, root *jsonschema.Schema) {
	if schema == nil || schema.Properties == nil || defaults == nil {
		return
	}
	for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
		val, ok := defaults[pair.Key]
		if !ok {
			continue
		}
		propSchema := pair.Value

		// Resolve $ref to get the actual schema
		resolved := propSchema
		if propSchema.Ref != "" {
			refName := propSchema.Ref[strings.LastIndex(propSchema.Ref, "/")+1:]
			if defSchema, exists := root.Definitions[refName]; exists {
				resolved = defSchema
			}
		}

		// If the value is a nested map, recurse into its properties if the
		// schema has them; otherwise skip (complex defaults don't display well).
		if nestedMap, isMap := val.(map[string]any); isMap {
			if resolved.Properties != nil && resolved.Properties.Len() > 0 {
				applyDefaults(resolved, nestedMap, root)
			}
			continue
		}

		// Skip zero/empty values
		if isZeroDefault(val) {
			continue
		}
		propSchema.Default = val
	}
}

// structToMap converts a struct value to a map using the specified tag for keys.
// It handles time.Duration specially, formatting as a human-readable string.
func structToMap(v reflect.Value, tagName string) map[string]any {
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}

	result := make(map[string]any)
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}

		tag := field.Tag.Get(tagName)
		if tag == "-" {
			continue
		}

		// Parse tag name
		name := tag
		if idx := strings.Index(name, ","); idx != -1 {
			name = name[:idx]
		}

		fieldVal := v.Field(i)

		// Handle inline (embedded) structs
		if strings.Contains(tag, "inline") {
			if fieldVal.Kind() == reflect.Struct || (fieldVal.Kind() == reflect.Pointer && !fieldVal.IsNil()) {
				nested := structToMap(fieldVal, tagName)
				maps.Copy(result, nested)
			}
			continue
		}

		// If no yaml tag, use field name
		if name == "" {
			name = field.Name
		}

		result[name] = formatValue(fieldVal)
	}

	return result
}

// textMarshalerType is the reflect.Type for encoding.TextMarshaler.
var textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()

// formatValue converts a reflect.Value to a schema-friendly representation.
func formatValue(v reflect.Value) any {
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	// Handle time.Duration -> string
	if v.Type() == reflect.TypeFor[time.Duration]() {
		d := time.Duration(v.Int())
		return formatDuration(d)
	}

	// Handle types implementing encoding.TextMarshaler (e.g. enum types like
	// TCBackend, HTTPParsingAction) — use their text representation instead
	// of the underlying numeric value.
	if v.Type().Implements(textMarshalerType) {
		if text, err := v.Interface().(encoding.TextMarshaler).MarshalText(); err == nil && len(text) > 0 {
			return string(text)
		}
	}
	if reflect.PointerTo(v.Type()).Implements(textMarshalerType) && v.CanAddr() {
		if text, err := v.Addr().Interface().(encoding.TextMarshaler).MarshalText(); err == nil && len(text) > 0 {
			return string(text)
		}
	}

	switch v.Kind() {
	case reflect.Struct:
		return structToMap(v, "yaml")
	case reflect.Slice:
		if v.IsNil() || v.Len() == 0 {
			return nil
		}
		result := make([]any, v.Len())
		for i := 0; i < v.Len(); i++ {
			result[i] = formatValue(v.Index(i))
		}
		return result
	case reflect.Map:
		if v.IsNil() || v.Len() == 0 {
			return nil
		}
		result := make(map[string]any)
		for _, key := range v.MapKeys() {
			result[fmt.Sprint(key.Interface())] = formatValue(v.MapIndex(key))
		}
		return result
	case reflect.String:
		return v.String()
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint()
	case reflect.Float32, reflect.Float64:
		return v.Float()
	case reflect.Func:
		return nil
	default:
		return fmt.Sprint(v.Interface())
	}
}

// formatDuration formats a time.Duration as a compact string like "30s", "5m", "1ms".
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// isZeroDefault returns true for values that shouldn't be shown as defaults.
// We keep false, 0, and other scalar zero values since they can be meaningful
// (e.g. "disabled by default"). Only nil and empty collections are skipped.
func isZeroDefault(v any) bool {
	switch val := v.(type) {
	case nil:
		return true
	case string:
		return val == ""
	case []any:
		return len(val) == 0
	case map[string]any:
		return len(val) == 0
	}
	return false
}
