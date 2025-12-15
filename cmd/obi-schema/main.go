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
	"runtime"
	"strings"
	"time"

	"github.com/invopop/jsonschema"

	"go.opentelemetry.io/obi/pkg/obi"
)

// enumRegistry maps type names to their valid enum values.
// This is populated by scanning source files at startup.
var enumRegistry = make(map[string][]any)

// defaultValues maps "TypeName.PropertyName" to their default values from DefaultConfig.
// TypeName is the struct type name, PropertyName is the field name.
var defaultValues = make(map[string]any)

func init() {
	// Find the module root by looking for go.mod
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintln(os.Stderr, "Warning: could not determine source location for enum extraction")
		return
	}

	moduleRoot := findModuleRoot(filepath.Dir(thisFile))
	if moduleRoot == "" {
		fmt.Fprintln(os.Stderr, "Warning: could not find module root for enum extraction")
		return
	}

	// Scan packages that contain enum types used in the config
	packagesToScan := []string{
		"pkg/obi",
		"pkg/config",
		"pkg/export",
		"pkg/export/debug",
		"pkg/export/imetrics",
		"pkg/export/instrumentations",
		"pkg/export/otel/otelcfg",
		"pkg/export/otel",
		"pkg/kube/kubeflags",
		"pkg/internal/netolly/flow",
	}

	for _, pkg := range packagesToScan {
		pkgPath := filepath.Join(moduleRoot, pkg)
		if err := scanPackageForEnums(pkgPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: error scanning %s: %v\n", pkg, err)
		}
	}

	// Extract default values from DefaultConfig
	//extractDefaults(reflect.ValueOf(obi.DefaultConfig))
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
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, pkgPath, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			extractEnumsFromFile(file)
		}
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

// extractDefaults recursively extracts default values from a struct value.
// It populates the defaultValues map with "TypeName.PropertyName" as keys.
func extractDefaults(v reflect.Value) {
	// Handle pointers by dereferencing
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}

	// Only process structs
	if v.Kind() != reflect.Struct {
		return
	}

	t := v.Type()
	typeName := t.Name()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get the property name (matching jsonschema library behavior)
		propName := getFieldName(field)
		if propName == "" {
			continue
		}

		// Build the key as "TypeName.PropertyName"
		key := typeName + "." + propName

		// Store default value based on field type
		storeDefaultValue(key, fieldValue, field.Type)

		// Recursively process nested structs
		actualValue := fieldValue
		actualType := field.Type
		if actualValue.Kind() == reflect.Ptr {
			if !actualValue.IsNil() {
				actualValue = actualValue.Elem()
				actualType = actualType.Elem()
			} else {
				continue
			}
		}
		//if actualValue.Kind() == reflect.Struct && !isSpecialType(actualType) {
		//	extractDefaults(fieldValue)
		//}
	}
}

// getFieldName returns the schema property name for a struct field.
// This matches the behavior of invopop/jsonschema: use json tag if present,
// otherwise use the struct field name.
func getFieldName(field reflect.StructField) string {
	// Check json tag first (matching jsonschema library behavior)
	if tag := field.Tag.Get("json"); tag != "" {
		parts := strings.Split(tag, ",")
		if parts[0] != "" && parts[0] != "-" {
			return parts[0]
		}
		if parts[0] == "-" {
			return ""
		}
	}
	// Fall back to struct field name (jsonschema library default)
	return field.Name
}

// isSpecialType returns true for types that should be treated as leaf values.
// func isSpecialType(t reflect.Type) bool {
// 	// Handle time.Duration specially
// 	if t == reflect.TypeOf(time.Duration(0)) {
// 		return true
// 	}
// 	// Handle time.Time specially
// 	if t == reflect.TypeOf(time.Time{}) {
// 		return true
// 	}
// 	return false
// }

// storeDefaultValue stores the default value for a field if it's non-zero.
func storeDefaultValue(path string, v reflect.Value, t reflect.Type) {
	// Handle pointers
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		v = v.Elem()
		t = t.Elem()
	}

	// Skip zero values (we only want actual defaults)
	if v.IsZero() {
		return
	}

	// Convert to JSON-friendly value
	var value any
	switch v.Kind() {
	case reflect.String:
		value = v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Special handling for time.Duration
		if t == reflect.TypeOf(time.Duration(0)) {
			value = time.Duration(v.Int()).String()
		} else {
			value = v.Int()
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value = v.Uint()
	case reflect.Float32, reflect.Float64:
		value = v.Float()
	case reflect.Bool:
		value = v.Bool()
	case reflect.Slice:
		if v.Len() > 0 {
			slice := make([]any, v.Len())
			for i := 0; i < v.Len(); i++ {
				elem := v.Index(i)
				if elem.Kind() == reflect.String {
					slice[i] = elem.String()
				} else if elem.CanInterface() {
					slice[i] = fmt.Sprintf("%v", elem.Interface())
				}
			}
			value = slice
		}
	default:
		// For complex types, skip for now
		return
	}

	if value != nil {
		defaultValues[path] = value
	}
}

// applyDefaults applies default values to the generated schema.
func applyDefaults(schema *jsonschema.Schema) {
	// Apply defaults to the root schema (Config type)
	applyDefaultsToSchema(schema, "Config")

	// Apply defaults to all definitions
	for defName, defSchema := range schema.Definitions {
		applyDefaultsToSchema(defSchema, defName)
	}
}

// applyDefaultsToSchema applies defaults to schema properties.
// typeName is the struct type name that this schema corresponds to.
func applyDefaultsToSchema(schema *jsonschema.Schema, typeName string) {
	if schema == nil || schema.Properties == nil {
		return
	}

	// Process properties in this schema
	for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
		propName := pair.Key
		propSchema := pair.Value

		// Build the key as "TypeName.PropertyName"
		key := typeName + "." + propName

		// Apply default if we have one
		if defaultVal, ok := defaultValues[key]; ok {
			propSchema.Default = defaultVal
		}
	}
}

func main() {
	outputFile := flag.String("output", "", "Output file path (default: stdout)")
	flag.Parse()

	reflector := &jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true,
		AllowAdditionalProperties:  true,
		ExpandedStruct:             true,
		Mapper:                     customMapper,
	}
	if err := reflector.AddGoComments("go.opentelemetry.io/obi", "./"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not add Go comments: %v\n", err)
	}

	schema := reflector.Reflect(&obi.Config{})
	schema.Title = "OBI Configuration Schema"
	schema.Description = "JSON Schema for OpenTelemetry eBPF Instrumentation (OBI) configuration"

	// Apply default values from DefaultConfig
	applyDefaults(schema)

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling schema: %v\n", err)
		os.Exit(1)
	}

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Schema written to %s\n", *outputFile)
	} else {
		fmt.Println(string(data))
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
			Description: "Duration in Go format (e.g., '30s', '5m', '1h')",
			Pattern:     "^[0-9]+(ms|s|m|h|d)$",
			Examples:    []any{"30s", "5m", "1h30m"},
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
