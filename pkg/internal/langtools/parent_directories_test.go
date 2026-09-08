// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package langtools

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkParentDirectories(t *testing.T) {
	boundary := filepath.Join(t.TempDir(), "workspace")
	start := filepath.Join(boundary, "services", "orders")

	t.Run("visits through the boundary", func(t *testing.T) {
		var visited []string
		err := WalkParentDirectories(start, boundary, func(dir string) (bool, error) {
			visited = append(visited, dir)
			return false, nil
		})

		require.NoError(t, err)
		assert.Equal(t, []string{
			start,
			filepath.Join(boundary, "services"),
			boundary,
		}, visited)
	})

	t.Run("stops at the requested directory", func(t *testing.T) {
		var visited []string
		err := WalkParentDirectories(start, boundary, func(dir string) (bool, error) {
			visited = append(visited, dir)
			return filepath.Base(dir) == "services", nil
		})

		require.NoError(t, err)
		assert.Equal(t, []string{start, filepath.Join(boundary, "services")}, visited)
	})

	t.Run("propagates callback errors", func(t *testing.T) {
		expected := errors.New("read manifest")
		err := WalkParentDirectories(start, boundary, func(string) (bool, error) {
			return false, expected
		})

		require.ErrorIs(t, err, expected)
	})

	t.Run("ignores invalid paths", func(t *testing.T) {
		for _, paths := range [][2]string{
			{"relative/start", boundary},
			{start, "relative/boundary"},
			{filepath.Join(filepath.Dir(boundary), "outside"), boundary},
		} {
			calls := 0
			err := WalkParentDirectories(paths[0], paths[1], func(string) (bool, error) {
				calls++
				return false, nil
			})

			require.NoError(t, err)
			assert.Zero(t, calls)
		}
	})
}
