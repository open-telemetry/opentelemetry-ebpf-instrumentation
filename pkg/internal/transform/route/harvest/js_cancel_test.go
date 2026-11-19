// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkJSFilesCancellation(t *testing.T) {
	for _, walk := range []struct {
		name string
		fn   func(context.Context, string, func(string) error) error
	}{
		{name: "source", fn: WalkJSFiles},
		{name: "compiled", fn: WalkCompiledJSFiles},
	} {
		t.Run(walk.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range []string{"a.js", "b.js", "c.js"} {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o644))
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			visited := 0
			err := walk.fn(ctx, dir, func(string) error {
				visited++
				cancel()
				return nil
			})
			require.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, 1, visited)
		})
	}
}

func TestJSScanCanceled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.js")
	require.NoError(t, os.WriteFile(path, []byte("app.get('/users', handler);\n"), 0o644))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	extractor := NewRouteExtractor()
	require.ErrorIs(t, extractor.scanFile(ctx, path), context.Canceled)
	assert.Empty(t, extractor.GetRoutes())
	require.ErrorIs(t, extractor.ScanDirectory(ctx, dir), context.Canceled)
	result, err := extractJSRoutes(ctx, dir)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, result)
}

func TestJSFileScanStopsAtDeadline(t *testing.T) {
	const lines = 100000
	path := filepath.Join(t.TempDir(), "server.js")
	var content strings.Builder
	for i := range lines {
		fmt.Fprintf(&content, "app.get('/users/%d', handler);\n", i)
	}
	require.NoError(t, os.WriteFile(path, []byte(content.String()), 0o644))

	for _, compiled := range []bool{false, true} {
		extractor := NewRouteExtractor()
		extractor.compiled = compiled
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		err := extractor.scanFile(ctx, path)
		cancel()
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Less(t, len(extractor.GetRoutes()), lines)
	}
}

func TestExtractJSRoutesCompiledScanStopsAtDeadline(t *testing.T) {
	dir := t.TempDir()
	dist := filepath.Join(dir, "dist")
	require.NoError(t, os.MkdirAll(dist, 0o755))
	content := strings.Repeat("app.get('/users', handler);\n", 100000)
	require.NoError(t, os.WriteFile(filepath.Join(dist, "server.js"), []byte(content), 0o644))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	result, err := extractJSRoutes(ctx, dir)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, result)
}

func TestGetHarvestedRoutesCanceled(t *testing.T) {
	extractor := NewRouteExtractor()
	extractor.routes = []RoutePattern{{Path: "/users"}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	routes, err := extractor.GetHarvestedRoutes(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, routes)
}

func TestWalkJSFilesSkipsNodeModules(t *testing.T) {
	for _, walk := range []struct {
		name string
		fn   func(context.Context, string, func(string) error) error
	}{
		{name: "source", fn: WalkJSFiles},
		{name: "compiled", fn: WalkCompiledJSFiles},
	} {
		t.Run(walk.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range []string{"app.js", "node_modules/package/index.js", "src/node_modules/package/index.js"} {
				path := filepath.Join(dir, name)
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.WriteFile(path, nil, 0o644))
			}
			var visited []string
			err := walk.fn(t.Context(), dir, func(path string) error {
				visited = append(visited, path)
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, []string{filepath.Join(dir, "app.js")}, visited)

			err = walk.fn(t.Context(), filepath.Join(dir, "node_modules"), func(path string) error {
				t.Errorf("unexpected dependency scan: %s", path)
				return nil
			})
			require.NoError(t, err)
		})
	}
}
