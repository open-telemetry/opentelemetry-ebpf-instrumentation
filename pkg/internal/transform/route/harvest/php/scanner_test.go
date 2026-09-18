// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkPHPFilesVisitsEligibleFiles(t *testing.T) {
	root := t.TempDir()
	writeScannerFile(t, filepath.Join(root, "a.PHP"), `$app->get('/a');`)
	writeScannerFile(t, filepath.Join(root, "nested", "b.php"), `Route::get('/b');`)
	writeScannerFile(t, filepath.Join(root, "ignored.txt"), `Route::get('/ignored');`)

	visited := map[string][]string{}
	err := walkPHPFiles(context.Background(), root, func(file phpFile) {
		relative, relErr := filepath.Rel(root, file.path)
		require.NoError(t, relErr)
		visited[filepath.ToSlash(relative)] = flatTokenValues(file.tokens)
	})

	require.NoError(t, err)
	assert.Equal(t, map[string][]string{
		"a.PHP":        {"$app", "->", "get", "(", "/a", ")", ";"},
		"nested/b.php": {"Route", "::", "get", "(", "/b", ")", ";"},
	}, visited)
}

func TestIsRegularPHPFile(t *testing.T) {
	root := t.TempDir()
	writeScannerFile(t, filepath.Join(root, "route.PHP"), "<?php")
	writeScannerFile(t, filepath.Join(root, "route.txt"), "<?php")
	require.NoError(t, os.Mkdir(filepath.Join(root, "directory.php"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(root, "route.PHP"), filepath.Join(root, "linked.php")))

	entries, err := os.ReadDir(root)
	require.NoError(t, err)

	eligible := map[string]bool{}
	for _, entry := range entries {
		eligible[entry.Name()] = isRegularPHPFile(filepath.Join(root, entry.Name()), entry)
	}

	assert.Equal(t, map[string]bool{
		"directory.php": false,
		"linked.php":    false,
		"route.PHP":     true,
		"route.txt":     false,
	}, eligible)
}

func TestShouldSkipDirectory(t *testing.T) {
	root := t.TempDir()
	skipped := []string{
		".git", ".hg", ".svn", "bootstrap/cache", "node_modules", "storage",
		"test", "tests", "spec", "specs", "fixtures", "examples", "var/cache", "vendor",
		"src/vendor",
	}
	for _, relative := range skipped {
		assert.True(t, shouldSkipDirectory(root, filepath.Join(root, filepath.FromSlash(relative))), "directory %s", relative)
	}

	allowed := []string{".", "src", "cache", "bootstrap", "var", "src/example"}
	for _, relative := range allowed {
		assert.False(t, shouldSkipDirectory(root, filepath.Join(root, filepath.FromSlash(relative))), "directory %s", relative)
	}
}

func TestWalkPHPFilesSkipsExcludedTrees(t *testing.T) {
	root := t.TempDir()
	for _, relative := range []string{
		"vendor/package/routes.php",
		"node_modules/package/routes.php",
		"tests/routes.php",
		"bootstrap/cache/routes.php",
		"storage/routes.php",
		"var/cache/routes.php",
	} {
		writeScannerFile(t, filepath.Join(root, filepath.FromSlash(relative)), `Route::get('/excluded');`)
	}
	writeScannerFile(t, filepath.Join(root, "src", "routes.php"), `Route::get('/included');`)

	var visited []string
	err := walkPHPFiles(context.Background(), root, func(file phpFile) {
		relative, relErr := filepath.Rel(root, file.path)
		require.NoError(t, relErr)
		visited = append(visited, filepath.ToSlash(relative))
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"src/routes.php"}, visited)
}

func TestWalkPHPFilesVisitsIncompletePHP(t *testing.T) {
	root := t.TempDir()
	writeScannerFile(t, filepath.Join(root, "routes.php"), `Route::get('/valid'); if (true) {`)

	var visited []phpFile
	err := walkPHPFiles(context.Background(), root, func(file phpFile) {
		visited = append(visited, file)
	})

	require.NoError(t, err)
	require.Len(t, visited, 1)
	assert.Contains(t, flatTokenValues(visited[0].tokens), "/valid")
}

func TestWalkPHPFilesDoesNotFollowSymbolicLinks(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	externalFile := filepath.Join(external, "external.php")
	writeScannerFile(t, externalFile, `Route::get('/external');`)
	require.NoError(t, os.Symlink(externalFile, filepath.Join(root, "linked-file.php")))
	require.NoError(t, os.Symlink(external, filepath.Join(root, "linked-directory")))
	writeScannerFile(t, filepath.Join(root, "local.php"), `Route::get('/local');`)

	var visited []string
	err := walkPHPFiles(context.Background(), root, func(file phpFile) {
		visited = append(visited, filepath.Base(file.path))
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"local.php"}, visited)
}

func TestWalkPHPFilesSkipsOversizedFiles(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "oversized.php"), make([]byte, maxPHPFileBytes+1), 0o600))
	writeScannerFile(t, filepath.Join(root, "route.php"), `Route::get('/route');`)

	var visited []string
	err := walkPHPFiles(context.Background(), root, func(file phpFile) {
		visited = append(visited, filepath.Base(file.path))
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"route.php"}, visited)
}

func TestWalkPHPFilesStopsWhenContextIsCanceled(t *testing.T) {
	root := t.TempDir()
	writeScannerFile(t, filepath.Join(root, "route.php"), `Route::get('/route');`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	visited := false
	err := walkPHPFiles(ctx, root, func(phpFile) {
		visited = true
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, visited)
}

func TestWalkPHPFilesReturnsRootError(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	visited := false

	err := walkPHPFiles(context.Background(), root, func(phpFile) {
		visited = true
	})

	require.ErrorContains(t, err, "scan PHP project")
	assert.False(t, visited)
}

func writeScannerFile(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

func flatTokenValues(tokens []token) []string {
	values := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		values = append(values, tok.value)
	}
	return values
}
