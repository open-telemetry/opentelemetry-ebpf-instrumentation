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
