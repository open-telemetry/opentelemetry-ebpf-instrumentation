// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSymfonyYAMLEntries(t *testing.T) {
	t.Run("discovers supported regular files", func(t *testing.T) {
		root := t.TempDir()
		routesYAML := writeSymfonyTestFile(t, root, "config/routes.yaml", "routes: {}")
		routesYML := writeSymfonyTestFile(t, root, "config/routes.yml", "routes: {}")
		alpha := writeSymfonyTestFile(t, root, "config/routes/alpha.YAML", "routes: {}")
		beta := writeSymfonyTestFile(t, root, "config/routes/beta.yml", "routes: {}")
		writeSymfonyTestFile(t, root, "config/routes/ignored.xml", "<routes/>")
		require.NoError(t, os.Mkdir(filepath.Join(root, "config", "routes", "directory.yaml"), 0o750))

		assert.Equal(t, []string{routesYAML, routesYML, alpha, beta}, symfonyYAMLEntries(root))
	})

	t.Run("missing config", func(t *testing.T) {
		assert.Nil(t, symfonyYAMLEntries(t.TempDir()))
	})
}

func TestLocalSymfonyResourceRejectsEmptyResource(t *testing.T) {
	root := t.TempDir()

	path, ok := localSymfonyResource(root, filepath.Join(root, "config"), "")

	assert.Empty(t, path)
	assert.False(t, ok)
}

func TestLocalSymfonyResource(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "config", "routes")

	path, ok := localSymfonyResource(root, base, "../imports/admin.yaml")
	assert.True(t, ok)
	assert.Equal(t, filepath.Join(root, "config", "imports", "admin.yaml"), path)

	for _, resource := range []string{
		" ", "*.yaml", "route?.yaml", "{one,two}.yaml", "@Bundle/routes.yaml",
		filepath.Join(root, "absolute.yaml"), "../../../outside.yaml",
	} {
		t.Run(resource, func(t *testing.T) {
			path, ok := localSymfonyResource(root, base, resource)
			assert.Empty(t, path)
			assert.False(t, ok)
		})
	}
}

func TestExistingFiles(t *testing.T) {
	root := t.TempDir()
	first := writeSymfonyTestFile(t, root, "first.yaml", "route: {}")
	second := writeSymfonyTestFile(t, root, "second.yml", "route: {}")
	directory := filepath.Join(root, "directory.yaml")
	require.NoError(t, os.Mkdir(directory, 0o750))

	assert.Equal(t, []string{second, first}, existingFiles(second, filepath.Join(root, "missing"), directory, first))
}

func TestIsYAMLFile(t *testing.T) {
	for _, path := range []string{"routes.yaml", "routes.yml", "ROUTES.YAML", "/config/routes.YmL", ".yaml"} {
		assert.True(t, isYAMLFile(path), path)
	}
	for _, path := range []string{"routes.xml", "routes.yaml.bak", "routes"} {
		assert.False(t, isYAMLFile(path), path)
	}
}
