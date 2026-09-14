// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package langtools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadMetadataFile(t *testing.T) {
	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "metadata.json")
		require.NoError(t, os.WriteFile(path, []byte("metadata"), 0o600))

		data, found, err := ReadMetadataFile(path, 8)

		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, []byte("metadata"), data)
	})

	t.Run("missing file", func(t *testing.T) {
		data, found, err := ReadMetadataFile(filepath.Join(t.TempDir(), "missing"), 8)

		require.NoError(t, err)
		assert.False(t, found)
		assert.Nil(t, data)
	})

	t.Run("oversized file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "metadata.json")
		require.NoError(t, os.WriteFile(path, []byte("too large"), 0o600))

		data, found, err := ReadMetadataFile(path, 8)

		require.NoError(t, err)
		assert.True(t, found)
		assert.Nil(t, data)
	})

	t.Run("symbolic link", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		path := filepath.Join(dir, "metadata.json")
		require.NoError(t, os.WriteFile(target, []byte("metadata"), 0o600))
		require.NoError(t, os.Symlink(target, path))

		data, found, err := ReadMetadataFile(path, 8)

		require.NoError(t, err)
		assert.True(t, found)
		assert.Nil(t, data)
	})
}
