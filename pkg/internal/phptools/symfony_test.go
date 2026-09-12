// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSymfonyProjectName(t *testing.T) {
	t.Run("Composer requirement", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "my_app")
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))

		composer, composerFound := readComposerJSON(filepath.Join(dir, "composer.json"))
		require.True(t, composerFound)
		name, found := symfonyProjectName(dir, composer)

		assert.True(t, found)
		assert.Equal(t, "my_app", name)
	})

	t.Run("not Symfony", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "orders")
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{
            "require":{"symfony/console":"^7.4","symfony/http-kernel":"^7.4"}
        }`))

		composer, composerFound := readComposerJSON(filepath.Join(dir, "composer.json"))
		require.True(t, composerFound)
		name, found := symfonyProjectName(dir, composer)

		assert.False(t, found)
		assert.Empty(t, name)
	})

	t.Run("bundle configuration without Composer requirement", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "orders")
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{}`))
		writePHPFile(t, filepath.Join(dir, "config", "bundles.php"), []byte(`<?php
return [Symfony\Bundle\FrameworkBundle\FrameworkBundle::class => ['all' => true]];
`))

		composer, composerFound := readComposerJSON(filepath.Join(dir, "composer.json"))
		require.True(t, composerFound)
		name, found := symfonyProjectName(dir, composer)

		assert.False(t, found)
		assert.Empty(t, name)
	})

	t.Run("invalid directory name", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "-")
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))

		composer, composerFound := readComposerJSON(filepath.Join(dir, "composer.json"))
		require.True(t, composerFound)
		name, found := symfonyProjectName(dir, composer)

		assert.False(t, found)
		assert.Empty(t, name)
	})
}

func TestComposerIdentifiesSymfony(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     bool
	}{
		{name: "framework bundle", contents: `{"require":{"symfony/framework-bundle":"^7.4"}}`, want: true},
		{name: "legacy framework package", contents: `{"require":{"symfony/symfony":"^3.4"}}`, want: true},
		{name: "Flex requirement", contents: `{"flex-require":{"symfony/framework-bundle":"*"}}`, want: true},
		{name: "unrelated Symfony components", contents: `{"require":{"symfony/console":"^7.4","symfony/http-kernel":"^7.4"}}`},
		{name: "development requirement", contents: `{"require-dev":{"symfony/framework-bundle":"^7.4"}}`},
		{name: "template name only", contents: `{"name":"symfony/skeleton"}`},
		{name: "empty", contents: `{}`},
		{name: "malformed", contents: `{"require":`},
		{name: "invalid requirements", contents: `{"require":[]}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "composer.json")
			require.NoError(t, os.WriteFile(path, []byte(test.contents), 0o600))
			composer, _ := readComposerJSON(path)

			assert.Equal(t, test.want, composerIdentifiesSymfony(composer))
		})
	}

	t.Run("missing", func(t *testing.T) {
		composer, found := readComposerJSON(filepath.Join(t.TempDir(), "composer.json"))
		assert.False(t, found)
		assert.False(t, composerIdentifiesSymfony(composer))
	})
}

func TestRequiresSymfony(t *testing.T) {
	assert.False(t, requiresSymfony(nil))
	assert.False(t, requiresSymfony(map[string]string{
		"symfony/console": "^7.4",
	}))
	assert.True(t, requiresSymfony(map[string]string{
		symfonyFrameworkBundlePackage: "^7.4",
	}))
	assert.True(t, requiresSymfony(map[string]string{
		symfonyFrameworkPackage: "^3.4",
	}))
}

func TestSymfonyTemplateName(t *testing.T) {
	for _, name := range []string{
		symfonySkeletonPackage,
		"  " + symfonySkeletonPackage + "  ",
	} {
		assert.True(t, symfonyTemplateName(name))
	}

	for _, name := range []string{"", "acme/orders", "symfony/framework-bundle", "symfony/skeleton-app"} {
		assert.False(t, symfonyTemplateName(name))
	}
}
