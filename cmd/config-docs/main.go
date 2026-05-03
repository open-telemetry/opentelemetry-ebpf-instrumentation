// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// config-docs generates a Markdown configuration reference from the OBI JSON schema.
// Usage:
//
//	go run ./cmd/config-docs -schema devdocs/config/config-schema.json > devdocs/config/CONFIG.md
//	go run ./cmd/config-docs -schema devdocs/config/config-schema.json -output devdocs/config/CONFIG.md
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Schema represents a JSON Schema node (subset relevant for doc generation).
type Schema struct {
	Ref                        string             `json:"$ref,omitempty"`
	Defs                       map[string]*Schema `json:"$defs,omitempty"`
	Title                      string             `json:"title,omitempty"`
	Description                string             `json:"description,omitempty"`
	Type                       any                `json:"type,omitempty"` // string or []string
	Properties                 map[string]*Schema `json:"properties,omitempty"`
	Items                      *Schema            `json:"items,omitempty"`
	Enum                       []any              `json:"enum,omitempty"`
	OneOf                      []*Schema          `json:"oneOf,omitempty"`
	Pattern                    string             `json:"pattern,omitempty"`
	Examples                   []any              `json:"examples,omitempty"`
	Format                     string             `json:"format,omitempty"`
	Deprecated                 bool               `json:"deprecated,omitempty"`
	AdditionalProperties       any                `json:"additionalProperties,omitempty"` // bool or *Schema
	AdditionalPropertiesSchema *Schema            `json:"-"`
	PropertyNames              *Schema            `json:"propertyNames,omitempty"`
	MaxLength                  *int               `json:"maxLength,omitempty"`
	Default                    any                `json:"default,omitempty"`
	UniqueItems                bool               `json:"uniqueItems,omitempty"`
	Extras                     map[string]any     `json:"-"`
	EnvVar                     string             `json:"-"`
	NoYaml                     bool               `json:"-"`
}

// UnmarshalJSON custom unmarshals to capture x-env-var and x-no-yaml.
func (s *Schema) UnmarshalJSON(data []byte) error {
	type Alias Schema
	aux := &struct {
		*Alias
		EnvVar any  `json:"x-env-var,omitempty"`
		NoYaml bool `json:"x-no-yaml,omitempty"`
	}{Alias: (*Alias)(s)}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if aux.EnvVar != nil {
		if v, ok := aux.EnvVar.(string); ok {
			s.EnvVar = v
		}
	}
	s.NoYaml = aux.NoYaml

	// Pre-parse AdditionalProperties into a *Schema if it's not a bool.
	if s.AdditionalProperties != nil {
		if _, isBool := s.AdditionalProperties.(bool); !isBool {
			apBytes, err := json.Marshal(s.AdditionalProperties)
			if err == nil {
				var apSchema Schema
				if json.Unmarshal(apBytes, &apSchema) == nil {
					s.AdditionalPropertiesSchema = &apSchema
				}
			}
		}
	}

	return nil
}

type propEntry struct {
	name   string
	schema *Schema
}

// DocGenerator holds the parsed schema and generates markdown docs.
type DocGenerator struct {
	root *Schema
	// referencedTypes collects $def names that are referenced from property
	// tables but not rendered as their own config sections. These get
	// documented in a "Type Definitions" appendix.
	referencedTypes map[string]bool
}

func main() {
	schemaFile := flag.String("schema", "devdocs/config/config-schema.json", "Path to the JSON schema file")
	outputFile := flag.String("output", "", "Output file path (default: stdout)")
	flag.Parse()

	data, err := os.ReadFile(*schemaFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading schema file: %v\n", err)
		os.Exit(1)
	}

	var schema Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing schema: %v\n", err)
		os.Exit(1)
	}

	gen := &DocGenerator{root: &schema, referencedTypes: make(map[string]bool)}

	schemaLink := *schemaFile
	if *outputFile != "" {
		if rel, err := filepath.Rel(filepath.Dir(*outputFile), *schemaFile); err == nil {
			schemaLink = rel
		}
	}
	output := gen.Generate(schemaLink)

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(output), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Config docs written to %s\n", *outputFile)
	} else {
		fmt.Print(output)
	}
}

// Generate produces the full markdown document. schemaLink is the relative
// path from the output file to the schema file, used for the source link.
func (g *DocGenerator) Generate(schemaLink string) string {
	var b strings.Builder

	b.WriteString("# OBI Configuration Reference\n\n")
	b.WriteString("Complete configuration reference for OpenTelemetry eBPF Instrumentation (OBI).\n")
	b.WriteString("Configuration is provided via YAML file and/or environment variables.\n\n")
	fmt.Fprintf(&b, "Generated from [`%s`](%s).\n\n", schemaLink, schemaLink)
	b.WriteString("---\n\n")

	// Collect top-level simple properties and object properties
	var simpleProps []propEntry
	var objectProps []propEntry

	for name, prop := range g.root.Properties {
		resolved := g.resolve(prop)
		if g.isObjectType(resolved) {
			objectProps = append(objectProps, propEntry{name, prop})
		} else {
			simpleProps = append(simpleProps, propEntry{name, prop})
		}
	}
	sort.Slice(simpleProps, func(i, j int) bool { return simpleProps[i].name < simpleProps[j].name })
	sort.Slice(objectProps, func(i, j int) bool { return objectProps[i].name < objectProps[j].name })

	// Table of Contents
	b.WriteString("## Table of Contents\n\n")
	b.WriteString("- [Top-Level Properties](#top-level-properties)\n")
	for _, p := range objectProps {
		anchor := strings.ReplaceAll(p.name, "_", "-")
		fmt.Fprintf(&b, "- [`%s`](#%s)\n", p.name, anchor)
	}
	b.WriteString("- [Type Definitions](#type-definitions)\n")
	b.WriteString("\n---\n\n")

	// Top-level simple properties
	b.WriteString("## Top-Level Properties\n\n")
	g.writePropertiesTable(&b, simpleProps, "")
	b.WriteString("\n")

	// Object sections
	for _, p := range objectProps {
		g.writeObjectSection(&b, p.name, p.schema, 2)
	}

	// Type Definitions appendix
	g.writeTypeDefinitions(&b)

	return strings.TrimRight(b.String(), "\n") + "\n"
}

// writeObjectSection writes a markdown section for an object-typed property.
func (g *DocGenerator) writeObjectSection(b *strings.Builder, name string, schema *Schema, depth int) {
	resolved := g.resolve(schema)
	hashes := strings.Repeat("#", depth)

	fmt.Fprintf(b, "%s `%s`\n\n", hashes, name)

	if resolved.Description != "" {
		b.WriteString(wrapBareURLs(resolved.Description) + "\n\n")
	}
	if resolved.Deprecated {
		b.WriteString("**Deprecated.**\n\n")
	}

	var simpleProps []propEntry
	var objectProps []propEntry

	if resolved.Properties != nil {
		for pName, pSchema := range resolved.Properties {
			pResolved := g.resolve(pSchema)
			if g.isObjectType(pResolved) {
				objectProps = append(objectProps, propEntry{pName, pSchema})
			} else {
				simpleProps = append(simpleProps, propEntry{pName, pSchema})
			}
		}
	}
	sort.Slice(simpleProps, func(i, j int) bool { return simpleProps[i].name < simpleProps[j].name })
	sort.Slice(objectProps, func(i, j int) bool { return objectProps[i].name < objectProps[j].name })

	if len(simpleProps) > 0 {
		g.writePropertiesTable(b, simpleProps, name)
		b.WriteString("\n")
	}

	nextDepth := min(depth+1, 4)
	for _, op := range objectProps {
		fullName := name + "." + op.name
		g.writeObjectSection(b, fullName, op.schema, nextDepth)
	}
}

// writePropertiesTable writes a markdown table of non-object properties.
func (g *DocGenerator) writePropertiesTable(b *strings.Builder, props []propEntry, parentPath string) {
	b.WriteString("| YAML Path | Type | Env Var | Default | Values | Deprecated | Description |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")

	for _, p := range props {
		resolved := g.resolve(p.schema)
		yamlPath := p.name
		if parentPath != "" {
			yamlPath = parentPath + "." + p.name
		}

		typStr := g.typeString(p.schema, resolved)
		envVar := g.envVar(p.schema, resolved)
		defVal := g.defaultString(p.schema)
		values := g.valuesString(p.schema, resolved)
		deprecated := g.deprecatedString(p.schema, resolved)
		desc := g.descString(p.schema, resolved)

		// Fields with no yaml tag are env-var only
		yamlCol := fmt.Sprintf("`%s`", yamlPath)
		if p.schema.NoYaml {
			yamlCol = ""
		}

		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			yamlCol, typStr, envVar, defVal, values, deprecated, desc)
	}
}

// writeTypeDefinitions writes the "Type Definitions" appendix for all
// referenced non-section types.
func (g *DocGenerator) writeTypeDefinitions(b *strings.Builder) {
	if len(g.referencedTypes) == 0 {
		return
	}

	b.WriteString("---\n\n## Type Definitions\n\n")

	// Iterate until no new types are discovered (writing a type def
	// may reference additional types, e.g. IntEnum -> IntRange).
	written := make(map[string]bool)
	for {
		var names []string
		for name := range g.referencedTypes {
			if !written[name] {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			break
		}
		sort.Strings(names)
		for _, name := range names {
			written[name] = true
			def, ok := g.root.Defs[name]
			if !ok {
				continue
			}
			g.writeTypeDef(b, name, def)
		}
	}
}

// writeTypeDef writes a single type definition entry.
func (g *DocGenerator) writeTypeDef(b *strings.Builder, name string, s *Schema) {
	fmt.Fprintf(b, "### %s\n\n", name)

	if s.Description != "" {
		desc := strings.ReplaceAll(s.Description, "\n", " ")
		b.WriteString(wrapBareURLs(desc) + "\n\n")
	}

	typeStr := schemaTypeStr(s)

	switch {
	case len(s.OneOf) > 0:
		g.writeOneOfDef(b, s)
	case len(s.Enum) > 0:
		b.WriteString("**Type:** `string`\n\n")
		b.WriteString("**Allowed values:** ")
		var vals []string
		for _, e := range s.Enum {
			vals = append(vals, fmt.Sprintf("`%v`", e))
		}
		b.WriteString(strings.Join(vals, ", ") + "\n\n")
	case typeStr == "array" && s.Items != nil:
		g.writeArrayTypeDef(b, s)
	case typeStr == "object":
		g.writeObjectTypeDef(b, s)
	case typeStr == "string":
		g.writeStringTypeDef(b, s)
	default:
		if typeStr != "" {
			fmt.Fprintf(b, "**Type:** `%s`\n\n", typeStr)
		}
	}

	if len(s.Examples) > 0 {
		var vals []string
		for _, e := range s.Examples {
			vals = append(vals, fmt.Sprintf("`%v`", e))
		}
		b.WriteString("**Examples:** " + strings.Join(vals, ", ") + "\n\n")
	}
}

func (g *DocGenerator) writeOneOfDef(b *strings.Builder, s *Schema) {
	b.WriteString("**One of:**\n\n")
	for _, alt := range s.OneOf {
		desc := alt.Description
		if desc == "" && len(alt.Enum) > 0 {
			var vals []string
			for _, e := range alt.Enum {
				vals = append(vals, fmt.Sprintf("`%v`", e))
			}
			desc = strings.Join(vals, ", ")
		}
		if alt.Pattern != "" {
			if desc != "" {
				desc += " "
			}
			desc += "(pattern: `" + alt.Pattern + "`)"
		}
		if desc != "" {
			b.WriteString("- " + desc + "\n")
		}
	}
	b.WriteString("\n")
}

func (g *DocGenerator) writeArrayTypeDef(b *strings.Builder, s *Schema) {
	itemResolved := g.resolve(s.Items)
	if itemResolved != nil && len(itemResolved.Enum) > 0 {
		b.WriteString("**Type:** array\n\n")
		b.WriteString("**Allowed items:** ")
		var vals []string
		for _, e := range itemResolved.Enum {
			vals = append(vals, fmt.Sprintf("`%v`", e))
		}
		b.WriteString(strings.Join(vals, ", ") + "\n\n")
	} else if itemResolved != nil {
		inner := schemaTypeStr(itemResolved)
		if inner != "" {
			fmt.Fprintf(b, "**Type:** `%s[]`\n\n", inner)
		} else {
			b.WriteString("**Type:** array\n\n")
		}
	}
}

func (g *DocGenerator) writeObjectTypeDef(b *strings.Builder, s *Schema) {
	// Known keys via propertyNames
	if s.PropertyNames != nil && len(s.PropertyNames.Enum) > 0 {
		b.WriteString("**Known keys:** ")
		var vals []string
		for _, e := range s.PropertyNames.Enum {
			vals = append(vals, fmt.Sprintf("`%v`", e))
		}
		b.WriteString(strings.Join(vals, ", ") + "\n\n")
	}

	// Value type via additionalProperties
	if valType := g.mapValueType(s); valType != "" {
		fmt.Fprintf(b, "**Value type:** `%s`\n\n", valType)
	}

	// If it has properties (like IntEnum.Ranges), document the structure
	if len(s.Properties) > 0 {
		var props []propEntry
		for pName, pSchema := range s.Properties {
			props = append(props, propEntry{pName, pSchema})
		}
		sort.Slice(props, func(i, j int) bool { return props[i].name < props[j].name })

		b.WriteString("| Field | Type | Values | Description |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, p := range props {
			resolved := g.resolve(p.schema)
			typStr := g.typeDefFieldType(p.schema, resolved)
			values := g.valuesString(p.schema, resolved)
			desc := g.descString(p.schema, resolved)
			fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", p.name, typStr, values, desc)
		}
		b.WriteString("\n")
	}

	// If no structure info was written, at least say it's an object
	if s.PropertyNames == nil && g.mapValueType(s) == "" && len(s.Properties) == 0 {
		b.WriteString("**Type:** `object`\n\n")
	}
}

func (g *DocGenerator) writeStringTypeDef(b *strings.Builder, s *Schema) {
	extra := ""
	if s.Format != "" {
		extra = " (format: `" + s.Format + "`)"
	}
	if s.Pattern != "" {
		extra = " (pattern: `" + s.Pattern + "`)"
	}
	fmt.Fprintf(b, "**Type:** `string`%s\n\n", extra)
}

// typeDefFieldType renders types for fields inside Type Definitions.
// Unlike typeString, it always links $ref types to their own definition
// entries, because within a Type Definition the reader needs to know
// the exact named type.
func (g *DocGenerator) typeDefFieldType(original, resolved *Schema) string {
	if resolved == nil {
		return ""
	}
	// Array with $ref items: link non-simple item types
	if schemaTypeStr(resolved) == "array" && resolved.Items != nil && resolved.Items.Ref != "" {
		itemResolved := g.resolve(resolved.Items)
		if !g.isSimpleType(itemResolved) {
			name := refToName(resolved.Items.Ref)
			g.referencedTypes[name] = true
			return fmt.Sprintf("[`%s`](#%s)[]", name, strings.ToLower(name))
		}
	}
	// Direct $ref: link non-simple types
	if original != nil && original.Ref != "" && !g.isSimpleType(resolved) {
		name := refToName(original.Ref)
		g.referencedTypes[name] = true
		return fmt.Sprintf("[`%s`](#%s)", name, strings.ToLower(name))
	}
	// Fall back to normal rendering (inlines simple types)
	return g.typeString(original, resolved)
}

// resolve follows $ref pointers to the actual schema definition.
func (g *DocGenerator) resolve(s *Schema) *Schema {
	if s == nil {
		return nil
	}
	if s.Ref != "" {
		refName := refToName(s.Ref)
		if def, ok := g.root.Defs[refName]; ok {
			return def
		}
	}
	return s
}

// refToName extracts the definition name from a $ref string like "#/$defs/FooBar".
func refToName(ref string) string {
	parts := strings.Split(ref, "/")
	return parts[len(parts)-1]
}

// isObjectType returns true if the resolved schema represents a complex object
// with its own properties worth documenting as a section.
func (g *DocGenerator) isObjectType(s *Schema) bool {
	if s == nil || len(s.Properties) == 0 {
		return false
	}
	for _, prop := range s.Properties {
		resolved := g.resolve(prop)
		if resolved == nil {
			continue
		}
		if resolved.EnvVar != "" || resolved.Description != "" || len(resolved.Properties) > 0 {
			return true
		}
	}
	return false
}

// isSimpleType returns true if a schema can be fully represented inline in a
// table row (its type, enums/examples/pattern fit in a Values column).
// Simple types: strings, integers, booleans, oneOf with only string alternatives,
// and arrays of simple items. Complex types: objects with properties/propertyNames.
func (g *DocGenerator) isSimpleType(s *Schema) bool {
	if s == nil {
		return false
	}
	typeStr := schemaTypeStr(s)
	switch typeStr {
	case "string", "integer", "number", "boolean":
		return true
	}
	// oneOf where all alternatives are strings
	if len(s.OneOf) > 0 {
		for _, alt := range s.OneOf {
			altType := schemaTypeStr(alt)
			if altType != "" && altType != "string" {
				return false
			}
		}
		return true
	}
	// arrays of simple items
	if typeStr == "array" && s.Items != nil {
		itemResolved := g.resolve(s.Items)
		return g.isSimpleType(itemResolved)
	}
	return false
}

// typeString returns a human-readable type string.
func (g *DocGenerator) typeString(original, resolved *Schema) string {
	if resolved == nil {
		return ""
	}

	// Non-section objects: true maps vs complex referenced types
	if schemaTypeStr(resolved) == "object" && !g.isObjectType(resolved) {
		// True map: no propertyNames constraints, has additionalProperties, no properties
		if resolved.PropertyNames == nil && resolved.AdditionalProperties != nil && len(resolved.Properties) == 0 {
			if valType := g.mapValueType(resolved); valType != "" {
				return "`map[string]" + valType + "`"
			}
			return "`map`"
		}
		// Complex referenced type: link to Type Definitions
		if original != nil && original.Ref != "" {
			name := refToName(original.Ref)
			g.referencedTypes[name] = true
			return fmt.Sprintf("[`%s`](#%s)", name, strings.ToLower(name))
		}
		return "`object`"
	}

	// oneOf: inline if simple, link if complex
	if len(resolved.OneOf) > 0 {
		if g.isSimpleType(resolved) {
			return "`string`"
		}
		if original != nil && original.Ref != "" {
			name := refToName(original.Ref)
			g.referencedTypes[name] = true
			return fmt.Sprintf("[`%s`](#%s)", name, strings.ToLower(name))
		}
		return "`string`"
	}

	typeStr := schemaTypeStr(resolved)

	switch typeStr {
	case "array":
		if resolved.Items != nil {
			itemResolved := g.resolve(resolved.Items)
			// If items reference a non-simple named type, link to its definition
			if resolved.Items.Ref != "" && !g.isSimpleType(itemResolved) {
				name := refToName(resolved.Items.Ref)
				g.referencedTypes[name] = true
				return fmt.Sprintf("[`%s`](#%s)[]", name, strings.ToLower(name))
			}
			inner := g.typeString(resolved.Items, itemResolved)
			return inner + "[]"
		}
		return "`array`"
	case "object":
		if len(resolved.Properties) == 0 {
			if valType := g.mapValueType(resolved); valType != "" {
				return "`map[string]" + valType + "`"
			}
			return "`map`"
		}
		return "`object`"
	case "string":
		if resolved.Format == "regex" {
			return "`regex`"
		}
		if resolved.Format == "glob" {
			return "`glob`"
		}
		if resolved.Format == "uri" {
			return "`uri`"
		}
		if resolved.Format == "ip" {
			return "`ip`"
		}
		if resolved.Pattern == "^[0-9]+(ms|s|m)$" {
			return "`duration`"
		}
		return "`string`"
	case "integer":
		return "`integer`"
	case "number":
		return "`number`"
	case "boolean":
		return "`boolean`"
	default:
		if typeStr != "" {
			return "`" + typeStr + "`"
		}
		return ""
	}
}

// mapValueType tries to determine the value type of a map schema from additionalProperties.
func (g *DocGenerator) mapValueType(s *Schema) string {
	apSchema := s.AdditionalPropertiesSchema
	if apSchema == nil {
		// Also handle the case where AdditionalProperties is already a *Schema
		// (e.g. when constructed programmatically rather than via JSON).
		if ps, ok := s.AdditionalProperties.(*Schema); ok {
			apSchema = ps
		} else {
			return ""
		}
	}
	resolved := g.resolve(apSchema)
	if resolved == nil {
		return ""
	}
	typeStr := schemaTypeStr(resolved)
	if typeStr == "array" && resolved.Items != nil {
		itemResolved := g.resolve(resolved.Items)
		if itemResolved != nil {
			inner := schemaTypeStr(itemResolved)
			if inner != "" {
				return inner + "[]"
			}
		}
		return "array"
	}
	if typeStr != "" {
		return typeStr
	}
	return ""
}

func schemaTypeStr(s *Schema) string {
	if s.Type == nil {
		return ""
	}
	switch v := s.Type.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			if str, ok := v[0].(string); ok {
				return str
			}
		}
	}
	return ""
}

// envVar extracts the environment variable, checking both the original and resolved schemas.
func (g *DocGenerator) envVar(original, resolved *Schema) string {
	if original != nil && original.EnvVar != "" && original.EnvVar != "-" {
		return "`" + original.EnvVar + "`"
	}
	if resolved != nil && resolved.EnvVar != "" && resolved.EnvVar != "-" {
		return "`" + resolved.EnvVar + "`"
	}
	return ""
}

// valuesString builds a string showing enum values, pattern, examples, etc.
func (g *DocGenerator) valuesString(original, resolved *Schema) string {
	s := resolved
	if s == nil {
		return ""
	}

	// For referenced types that link to Type Definitions, don't repeat values here
	if original != nil && original.Ref != "" && g.referencedTypes[refToName(original.Ref)] {
		return ""
	}

	// Collect enum values from oneOf
	if len(s.OneOf) > 0 {
		var allEnums []string
		for _, alt := range s.OneOf {
			for _, e := range alt.Enum {
				allEnums = append(allEnums, fmt.Sprintf("`%v`", e))
			}
		}
		if len(allEnums) > 0 {
			return strings.Join(unique(allEnums), ", ")
		}
		var descs []string
		for _, alt := range s.OneOf {
			if alt.Description != "" {
				descs = append(descs, alt.Description)
			}
		}
		if len(descs) > 0 {
			return strings.Join(descs, "; ")
		}
	}

	// Direct enums
	if len(s.Enum) > 0 {
		var vals []string
		for _, e := range s.Enum {
			vals = append(vals, fmt.Sprintf("`%v`", e))
		}
		return strings.Join(vals, ", ")
	}

	// Items enum or examples (for array types)
	if s.Items != nil {
		itemResolved := g.resolve(s.Items)
		if itemResolved != nil && len(itemResolved.Enum) > 0 {
			var vals []string
			for _, e := range itemResolved.Enum {
				vals = append(vals, fmt.Sprintf("`%v`", e))
			}
			return strings.Join(vals, ", ")
		}
		if itemResolved != nil && len(itemResolved.Examples) > 0 {
			var vals []string
			for _, e := range itemResolved.Examples {
				vals = append(vals, fmt.Sprintf("`%v`", e))
			}
			return strings.Join(vals, ", ") + ", etc"
		}
	}

	// Examples (non-exhaustive)
	if len(s.Examples) > 0 {
		var vals []string
		for _, e := range s.Examples {
			vals = append(vals, fmt.Sprintf("`%v`", e))
		}
		return strings.Join(vals, ", ") + ", etc"
	}

	return ""
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// defaultString returns the default value formatted for display, or empty if none.
func (g *DocGenerator) defaultString(s *Schema) string {
	if s == nil || s.Default == nil {
		return ""
	}
	switch v := s.Default.(type) {
	case string:
		return "`" + v + "`"
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("`%d`", int64(v))
		}
		return fmt.Sprintf("`%g`", v)
	case bool:
		return fmt.Sprintf("`%t`", v)
	case []any:
		// For arrays of scalars, show inline. For arrays containing
		// objects/maps, use compact JSON to keep it readable.
		allScalar := true
		for _, e := range v {
			switch e.(type) {
			case map[string]any, []any:
				allScalar = false
			}
		}
		if allScalar {
			var vals []string
			for _, e := range v {
				vals = append(vals, fmt.Sprintf("`%v`", e))
			}
			return strings.Join(vals, ", ")
		}
		data, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return "`" + string(data) + "`"
	case map[string]any:
		data, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return "`" + string(data) + "`"
	default:
		return fmt.Sprintf("`%v`", v)
	}
}

// deprecatedString returns "Yes" if either schema is deprecated, empty otherwise.
func (g *DocGenerator) deprecatedString(original, resolved *Schema) string {
	if (original != nil && original.Deprecated) || (resolved != nil && resolved.Deprecated) {
		return "Yes"
	}
	return ""
}

// descString returns a cleaned-up description, preferring the original over resolved.
func (g *DocGenerator) descString(original, resolved *Schema) string {
	desc := ""
	if original != nil && original.Description != "" {
		desc = original.Description
	} else if resolved != nil {
		desc = resolved.Description
	}
	desc = strings.ReplaceAll(desc, "\n", " ")
	desc = strings.ReplaceAll(desc, "|", "\\|") // escape pipes for markdown tables
	// Wrap bare URLs in angle brackets to satisfy MD034
	desc = wrapBareURLs(desc)
	return desc
}

// urlPrefixes lists the URL schemes to detect as bare URLs.
var urlPrefixes = []string{"https://", "http://"}

// wrapBareURLs wraps bare URLs in angle brackets for markdown lint compliance (MD034).
// It scans left-to-right, handling multiple URLs and already-wrapped URLs.
func wrapBareURLs(s string) string {
	pos := 0
	for pos < len(s) {
		nextIdx := -1
		nextPrefixLen := 0

		for _, prefix := range urlPrefixes {
			idx := strings.Index(s[pos:], prefix)
			if idx < 0 {
				continue
			}

			idx += pos
			if nextIdx == -1 || idx < nextIdx {
				nextIdx = idx
				nextPrefixLen = len(prefix)
			}
		}

		if nextIdx < 0 {
			break
		}

		if nextIdx > 0 && s[nextIdx-1] == '<' {
			pos = nextIdx + nextPrefixLen
			continue
		}

		end := len(s)
		for i := nextIdx; i < len(s); i++ {
			if s[i] == ' ' || s[i] == ')' || s[i] == '>' {
				end = i
				break
			}
		}

		url := s[nextIdx:end]
		s = s[:nextIdx] + "<" + url + ">" + s[end:]
		pos = nextIdx + len(url) + 2
	}
	return s
}
