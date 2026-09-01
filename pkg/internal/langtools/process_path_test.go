// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package langtools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveProcessPath(t *testing.T) {
	t.Run("rejects symlink components for proc roots", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))

		outside := filepath.Join(t.TempDir(), "outside")
		require.NoError(t, os.MkdirAll(outside, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(outside, "app.jar"), nil, 0o644))
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "app", "escape")))

		oldProcRootPath := procRootPath
		procRootPath = func(string) bool { return true }
		t.Cleanup(func() { procRootPath = oldProcRootPath })

		path, ok := ResolveProcessPath(root, "/app", "escape/app.jar")

		assert.False(t, ok)
		assert.Empty(t, path)
	})
}

func TestStatProcessPath(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "config"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "service.js"), nil, 0o644))

	t.Run("regular file", func(t *testing.T) {
		path, info, ok := StatProcessPath(root, "/app", "service.js")

		assert.True(t, ok)
		assert.Equal(t, filepath.Join(root, "app", "service.js"), path)
		assert.True(t, info.Mode().IsRegular())
	})

	t.Run("directory", func(t *testing.T) {
		path, info, ok := StatProcessPath(root, "/app", "config")

		assert.True(t, ok)
		assert.Equal(t, filepath.Join(root, "app", "config"), path)
		assert.True(t, info.IsDir())
	})

	t.Run("missing path", func(t *testing.T) {
		path, info, ok := StatProcessPath(root, "/app", "missing")

		assert.False(t, ok)
		assert.Empty(t, path)
		assert.Nil(t, info)
	})

	t.Run("symlink escape", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "outside.js")
		require.NoError(t, os.WriteFile(outside, nil, 0o644))
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "app", "escape.js")))

		path, info, ok := StatProcessPath(root, "/app", "escape.js")

		assert.False(t, ok)
		assert.Empty(t, path)
		assert.Nil(t, info)
	})
}
