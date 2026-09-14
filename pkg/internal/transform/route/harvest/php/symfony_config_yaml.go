// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import (
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

func extractSymfonyYAMLFile(
	projectRoot, filePath, routePrefix string,
	traversal *symfonyConfigTraversal,
	attributes map[string][]string,
	imported map[string]struct{},
	routes routeSet,
) {
	if !traversal.enter(filePath, routePrefix) {
		return
	}

	defer traversal.leave(filePath)

	data, _, err := langtools.ReadMetadataFile(filePath, maxPHPFileBytes)
	if err != nil || data == nil {
		return
	}

	var document yaml.Node
	if yaml.Unmarshal(data, &document) != nil || len(document.Content) == 0 {
		return
	}

	extractSymfonyYAMLMapping(
		projectRoot,
		filepath.Dir(filePath),
		document.Content[0],
		routePrefix,
		traversal,
		attributes,
		imported,
		routes,
	)
}

func extractSymfonyYAMLMapping(
	projectRoot, baseDirectory string,
	node *yaml.Node,
	routePrefix string,
	traversal *symfonyConfigTraversal,
	attributes map[string][]string,
	imported map[string]struct{},
	routes routeSet,
) {
	if node.Kind != yaml.MappingNode {
		return
	}

	for pos := 1; pos < len(node.Content); pos += 2 {
		routeDefinition := node.Content[pos]
		if routeDefinition.Kind != yaml.MappingNode {
			continue
		}

		if routePath := symfonyYAMLPath(routeDefinition); routePath != "" {
			routes.add(joinRoutes(routePrefix, routePath))
		}

		resource := yamlScalar(routeDefinition, "resource")
		if resource == "" {
			continue
		}

		importPath, ok := localSymfonyResource(projectRoot, baseDirectory, resource)
		if !ok {
			continue
		}

		importPrefix := joinRoutes(routePrefix, yamlScalar(routeDefinition, "prefix"))
		if isSymfonyAttributeImport(routeDefinition) {
			addImportedSymfonyAttributes(importPath, importPrefix, attributes, imported, routes)
			continue
		}

		if isYAMLFile(importPath) {
			extractSymfonyYAMLFile(projectRoot, importPath, importPrefix, traversal, attributes, imported, routes)
		}
	}
}

func symfonyYAMLPath(definition *yaml.Node) string {
	if path := yamlScalar(definition, "path"); path != "" {
		return path
	}

	// Symfony used pattern as the route path field before introducing path.
	return yamlScalar(definition, "pattern")
}

func isSymfonyAttributeImport(definition *yaml.Node) bool {
	typeName := strings.ToLower(yamlScalar(definition, "type"))
	return typeName == "attribute" || typeName == "annotation"
}

// yamlScalar retrieves a named scalar value from a YAML mapping, for example:
// route:
//
//	path: /users
//	methods: [GET]
//
// yamlScalar(route, "path")    -> "/users"
// yamlScalar(route, "methods") -> ""
func yamlScalar(mapping *yaml.Node, name string) string {
	for pos := 0; pos+1 < len(mapping.Content); pos += 2 {
		if mapping.Content[pos].Value == name && mapping.Content[pos+1].Kind == yaml.ScalarNode {
			return mapping.Content[pos+1].Value
		}
	}
	return ""
}
