// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestExtractSymfonyYAMLFile(t *testing.T) {
	root := t.TempDir()
	valid := writeSymfonyTestFile(t, root, "config/valid.yaml", "route:\n  path: /users\n")
	malformed := writeSymfonyTestFile(t, root, "config/malformed.yaml", "route: [\n")
	traversal := newSymfonyConfigTraversal()
	routes := newRouteSet()

	extractSymfonyYAMLFile(root, valid, "/api", traversal, nil, nil, routes)
	extractSymfonyYAMLFile(root, valid, "/api", traversal, nil, nil, routes)
	extractSymfonyYAMLFile(root, valid, "/v2", traversal, nil, nil, routes)
	extractSymfonyYAMLFile(root, malformed, "", traversal, nil, nil, routes)
	missing := filepath.Join(root, "config", "missing.yaml")
	extractSymfonyYAMLFile(root, missing, "", traversal, nil, nil, routes)

	assert.Equal(t, routeSet{"/api/users": {}, "/v2/users": {}}, routes)
	assert.Contains(t, traversal.visited, symfonyConfigVisit{filePath: valid, routePrefix: "/api"})
	assert.Contains(t, traversal.visited, symfonyConfigVisit{filePath: valid, routePrefix: "/v2"})
	assert.Contains(t, traversal.visited, symfonyConfigVisit{filePath: malformed})
	assert.Contains(t, traversal.visited, symfonyConfigVisit{filePath: missing})
	assert.Empty(t, traversal.active)
}

func TestExtractSymfonyYAMLFileDetectsImportCycles(t *testing.T) {
	root := t.TempDir()
	entry := writeSymfonyTestFile(t, root, "config/routes.yaml", `
self_import:
  resource: routes.yaml
  prefix: /loop
`)
	traversal := newSymfonyConfigTraversal()
	routes := newRouteSet()

	extractSymfonyYAMLFile(root, entry, "", traversal, nil, nil, routes)

	assert.Empty(t, routes)
	assert.Empty(t, traversal.active)
}

func TestExtractSymfonyYAMLMapping(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "config")
	routes := newRouteSet()

	extractSymfonyYAMLMapping(root, base, &yaml.Node{Kind: yaml.SequenceNode}, "", newSymfonyConfigTraversal(), nil, nil, routes)
	extractSymfonyYAMLMapping(
		root,
		base,
		parseSymfonyYAML(t, `
scalar_definition: ignored
modern:
  path: /modern
legacy:
  pattern: /legacy
unsupported_import:
  resource: '@Bundle/routes.yaml'
`),
		"/api",
		newSymfonyConfigTraversal(),
		nil,
		nil,
		routes,
	)

	assert.Equal(t, routeSet{"/api/modern": {}, "/api/legacy": {}}, routes)
}

func TestSymfonyYAMLPath(t *testing.T) {
	assert.Equal(t, "/modern", symfonyYAMLPath(parseSymfonyYAMLDefinition(t, "route:\n  path: /modern\n  pattern: /legacy\n")))
	assert.Equal(t, "/legacy", symfonyYAMLPath(parseSymfonyYAMLDefinition(t, "route:\n  pattern: /legacy\n")))
	assert.Empty(t, symfonyYAMLPath(parseSymfonyYAMLDefinition(t, "route:\n  controller: App\\Controller\n")))
}

func TestIsSymfonyAttributeImport(t *testing.T) {
	for _, typeName := range []string{"attribute", "ATTRIBUTE", "annotation", "Annotation"} {
		definition := parseSymfonyYAMLDefinition(t, "route:\n  type: "+typeName+"\n")
		assert.True(t, isSymfonyAttributeImport(definition), typeName)
	}

	assert.False(t, isSymfonyAttributeImport(parseSymfonyYAMLDefinition(t, "route:\n  type: service\n")))
	assert.False(t, isSymfonyAttributeImport(parseSymfonyYAMLDefinition(t, "route:\n  resource: routes.yaml\n")))
}

func TestSymfonyYAMLResource(t *testing.T) {
	tests := []struct {
		name       string
		definition string
		expected   string
	}{
		{name: "scalar", definition: "route:\n  resource: ../src/Controller/\n", expected: "../src/Controller/"},
		{name: "mapping", definition: "route:\n  resource: {path: ../src/Controller/, namespace: App\\Controller}\n", expected: "../src/Controller/"},
		{name: "mapping without path", definition: "route:\n  resource: {namespace: App\\Controller}\n"},
		{name: "sequence", definition: "route:\n  resource: [../src/Controller/]\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, symfonyYAMLResource(parseSymfonyYAMLDefinition(t, test.definition)))
		})
	}
}

func TestYAMLScalar(t *testing.T) {
	definition := parseSymfonyYAMLDefinition(t, `
route:
  path: /users
  methods: [GET]
`)

	assert.Equal(t, "/users", yamlScalar(definition, "path"))
	assert.Empty(t, yamlScalar(definition, "methods"))
	assert.Empty(t, yamlScalar(definition, "missing"))
}

func parseSymfonyYAML(t *testing.T, contents string) *yaml.Node {
	t.Helper()

	var document yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(contents), &document))
	require.NotEmpty(t, document.Content)
	return document.Content[0]
}

func parseSymfonyYAMLDefinition(t *testing.T, contents string) *yaml.Node {
	t.Helper()

	mapping := parseSymfonyYAML(t, contents)
	require.Len(t, mapping.Content, 2)
	return mapping.Content[1]
}
