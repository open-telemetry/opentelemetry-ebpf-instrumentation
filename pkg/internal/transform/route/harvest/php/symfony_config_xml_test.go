// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"encoding/xml"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractSymfonyXMLFile(t *testing.T) {
	root := t.TempDir()
	entry := writeSymfonyTestFile(t, root, "app/config/routing.xml", `
<routes xmlns="http://symfony.com/schema/routing">
  <route id="modern" path="/users"/>
  <route id="legacy" pattern="/members"/>
  <route id="missing"/>
  <import resource="imports/admin.xml" prefix="/api"/>
  <import resource="routing.xml" prefix="/cycle"/>
</routes>`)
	writeSymfonyTestFile(t, root, "app/config/imports/admin.xml", `<routes><route id="admin" path="/admin"/></routes>`)
	malformed := writeSymfonyTestFile(t, root, "app/config/malformed.xml", `<routes><route path="/before"/><broken`)
	traversal := newSymfonyConfigTraversal()
	routes := newRouteSet()

	extractSymfonyXMLFile(root, entry, "/root", traversal, nil, nil, routes)
	extractSymfonyXMLFile(root, entry, "/root", traversal, nil, nil, routes)
	extractSymfonyXMLFile(root, malformed, "", traversal, nil, nil, routes)
	extractSymfonyXMLFile(root, filepath.Join(root, "missing.xml"), "", traversal, nil, nil, routes)

	assert.Equal(t, routeSet{
		"/root/users":     {},
		"/root/members":   {},
		"/root/api/admin": {},
		"/before":         {},
	}, routes)
	assert.Contains(t, traversal.visited, symfonyConfigVisit{filePath: entry, routePrefix: "/root"})
	assert.Empty(t, traversal.active)
}

func TestSymfonyXMLPath(t *testing.T) {
	assert.Equal(t, "/modern", symfonyXMLPath(symfonyXMLStart("route", "path", "/modern", "pattern", "/legacy")))
	assert.Equal(t, "/legacy", symfonyXMLPath(symfonyXMLStart("route", "pattern", "/legacy")))
	assert.Empty(t, symfonyXMLPath(symfonyXMLStart("route", "id", "missing")))
}

func TestExtractSymfonyXMLImport(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "app", "config")
	writeSymfonyTestFile(t, root, "app/config/imported.xml", `<routes><route path="/users"/></routes>`)
	writeSymfonyTestFile(t, root, "app/config/imported.yaml", "members:\n  path: /members\n")
	controller := filepath.Join(root, "src", "Controller", "UserController.php")
	attributes := map[string][]string{controller: {"/profile"}}
	imported := map[string]struct{}{}
	routes := newRouteSet()
	traversal := newSymfonyConfigTraversal()

	extractSymfonyXMLImport(root, base, "/api", symfonyXMLStart("import", "resource", "imported.xml", "prefix", "/v1"), traversal, attributes, imported, routes)
	extractSymfonyXMLImport(root, base, "/v2", symfonyXMLStart("import", "resource", "imported.xml"), traversal, attributes, imported, routes)
	extractSymfonyXMLImport(root, base, "/yaml", symfonyXMLStart("import", "resource", "imported.yaml"), traversal, attributes, imported, routes)
	extractSymfonyXMLImport(root, base, "", symfonyXMLStart("import", "resource", "../../src/Controller", "type", "ATTRIBUTE", "prefix", "/v3"), traversal, attributes, imported, routes)
	extractSymfonyXMLImport(root, base, "", symfonyXMLStart("import", "resource", "../../../outside.xml"), traversal, attributes, imported, routes)

	assert.Equal(t, routeSet{
		"/api/v1/users": {},
		"/v2/users":     {},
		"/yaml/members": {},
		"/v3/profile":   {},
	}, routes)
	assert.Equal(t, map[string]struct{}{controller: {}}, imported)
}

func TestIsSymfonyXMLAttributeImport(t *testing.T) {
	for _, typeName := range []string{"attribute", "ATTRIBUTE", "annotation", "Annotation"} {
		assert.True(t, isSymfonyXMLAttributeImport(symfonyXMLStart("import", "type", typeName)), typeName)
	}

	assert.False(t, isSymfonyXMLAttributeImport(symfonyXMLStart("import", "type", "service")))
	assert.False(t, isSymfonyXMLAttributeImport(symfonyXMLStart("import")))
}

func TestXMLAttribute(t *testing.T) {
	start := symfonyXMLStart("route", "id", "users", "path", "/users")

	assert.Equal(t, "users", xmlAttribute(start, "id"))
	assert.Equal(t, "/users", xmlAttribute(start, "path"))
	assert.Empty(t, xmlAttribute(start, "missing"))
}

func symfonyXMLStart(name string, attributes ...string) xml.StartElement {
	start := xml.StartElement{Name: xml.Name{Local: name}}
	for position := 0; position+1 < len(attributes); position += 2 {
		start.Attr = append(start.Attr, xml.Attr{
			Name:  xml.Name{Local: attributes[position]},
			Value: attributes[position+1],
		})
	}
	return start
}
