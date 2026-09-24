// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddImportedSymfonyAttributes(t *testing.T) {
	root := t.TempDir()
	resource := filepath.Join(root, "src", "Controller")
	exact := resource
	child := filepath.Join(resource, "Admin", "Users.php")
	sibling := filepath.Join(root, "src", "ControllerExtra", "Ignored.php")
	attributes := map[string][]string{
		exact:   {"/exact"},
		child:   {"/users", "/members"},
		sibling: {"/ignored"},
	}
	imported := map[string]struct{}{}
	routes := newRouteSet()

	addImportedSymfonyAttributes(resource, "/api", attributes, imported, routes)

	assert.Equal(t, routeSet{
		"/api/exact":   {},
		"/api/users":   {},
		"/api/members": {},
	}, routes)
	assert.Equal(t, map[string]struct{}{exact: {}, child: {}}, imported)
}

func TestIsPathWithinResource(t *testing.T) {
	root := t.TempDir()
	resource := filepath.Join(root, "Controller")

	assert.True(t, isPathWithinResource(resource, resource))
	assert.True(t, isPathWithinResource(filepath.Join(resource, "Admin", "Users.php"), resource))
	assert.True(t, isPathWithinResource(filepath.Join(resource, "Users.php"), resource+string(filepath.Separator)))
	assert.False(t, isPathWithinResource(filepath.Join(root, "ControllerExtra", "Users.php"), resource))
	assert.False(t, isPathWithinResource(filepath.Join(root, "Other", "Users.php"), resource))
}
