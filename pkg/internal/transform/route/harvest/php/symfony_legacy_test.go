// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractSymfonyLegacyRoutes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "app", "config", "routing.php")
	file := phpFile{
		path: path,
		tokens: lexPHP([]byte(`
            use Symfony\Component\Routing\Route;
            /** @Route("/annotated") @Rest\Get("/rest") */
            function annotated() {}
            $route = new Route('/configured');
        `)),
	}
	routes := newRouteSet()

	extractSymfonyLegacyRoutes(file, root, true, routes)

	assert.Equal(t, routeSet{
		"/annotated":  {},
		"/rest":       {},
		"/configured": {},
	}, routes)
}

func TestExtractSymfonyLegacyConfigRoutes(t *testing.T) {
	root := t.TempDir()
	writeSymfonyTestFile(t, root, "app/config/routing.yml", `
legacy:
  pattern: /legacy
`)
	writeSymfonyTestFile(t, root, "app/config/routing.xml", `
<routes>
  <route id="health" path="/health"/>
  <import resource="imports/admin.xml" prefix="/api"/>
</routes>`)
	writeSymfonyTestFile(t, root, "app/config/imports/admin.xml", `<routes><route id="admin" pattern="/admin"/></routes>`)
	routes := newRouteSet()

	extractSymfonyLegacyConfigRoutes(root, routes)

	assert.Equal(t, routeSet{
		"/legacy":    {},
		"/health":    {},
		"/api/admin": {},
	}, routes)
}
