// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProjectDirectoryForFile(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{path: "/app/config/environment.rb", expected: "/app"},
		{path: "/app/config/routes.rb", expected: "/app/config"},
		{path: "/app/environment.rb", expected: "/app"},
		{path: "/app/bin/rails", expected: "/app/bin"},
		{path: "config/environment.rb", expected: "."},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, projectDirectoryForFile(test.path))
	}
}

func TestProjectPathLooksLikeFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{path: "config.ru", expected: true},
		{path: "/app/config.ru", expected: true},
		{path: "/app/app.rb", expected: true},
		{path: "/app/bin/rails", expected: false},
		{path: "/app", expected: false},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, projectPathLooksLikeFile(test.path))
	}
}

func TestGemDependencyRoots(t *testing.T) {
	assert.Nil(t, gemDependencyRoots("/app", nil))
	assert.Equal(t, []string{"/gems/home"}, gemDependencyRoots("/app", map[string]string{
		gemHome: "/gems/home",
	}))
	assert.Equal(t, []string{"/gems/home", "/gems/a", "/gems/b"}, gemDependencyRoots(
		"/app",
		map[string]string{gemHome: "/gems/home", gemPath: "/gems/a:/gems/b"},
	))
	assert.Equal(t, []string{"/app/vendor/bundle"}, gemDependencyRoots("/app", map[string]string{
		gemHome: "vendor/bundle",
	}))
}

func TestPathInDependencyRoot(t *testing.T) {
	roots := []string{"/gems/a", "/gems/b"}
	assert.True(t, pathInDependencyRoot("/app", "/gems/a/lib/foo.rb", roots))
	assert.True(t, pathInDependencyRoot("/gems/b", "foo.rb", roots))
	assert.False(t, pathInDependencyRoot("/app", "/gems/aa/foo.rb", roots))
	assert.False(t, pathInDependencyRoot("/app", "/other/foo.rb", roots))
}

func TestServiceNameFromProjectDirectory(t *testing.T) {
	assert.Equal(t, "orders", serviceNameFromProjectDirectory("/app/orders", "/app"))
	assert.Empty(t, serviceNameFromProjectDirectory("/app", "/app"))
	assert.Empty(t, serviceNameFromProjectDirectory("/", "/srv"))
}
