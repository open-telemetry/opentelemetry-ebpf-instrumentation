// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractSymfonyConfigRoutes(t *testing.T) {
	root := t.TempDir()
	writeSymfonyTestFile(t, root, "config/routes.yaml", `
direct:
  path: /status
admin:
  resource: imports/admin.yml
  prefix: /api
controllers:
  resource: ../src/Controller/
  type: ATTRIBUTE
  prefix: /v1
`)
	writeSymfonyTestFile(t, root, "config/imports/admin.yml", `
admin_users:
  path: /admin/users
`)
	controller := filepath.Join(root, "src", "Controller", "UserController.php")
	attributes := map[string][]string{
		controller:                              {"/users"},
		filepath.Join(root, "src", "Other.php"): {"/ignored"},
	}
	routes := newRouteSet()

	imported := extractSymfonyConfigRoutes(root, attributes, routes)

	assert.Equal(t, routeSet{
		"/status":          {},
		"/api/admin/users": {},
		"/v1/users":        {},
	}, routes)
	assert.Equal(t, map[string]struct{}{controller: {}}, imported)
}
