// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSScanWithoutSemicolons(t *testing.T) {
	for _, prefix := range []string{"", "const pending = unknown(\n"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "server.js")
		content := prefix + strings.Repeat("const value = 123456789\n", 5000) + "app.get('/users', handler)\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		extractor := NewRouteExtractor()
		err := extractor.scanFile(ctx, path)
		cancel()
		require.NoError(t, err)
		routes, err := extractor.GetHarvestedRoutes(t.Context())
		require.NoError(t, err)
		assert.Equal(t, []string{"/users"}, routes)
	}
}

func TestJSScanMultilineRoutesWithoutSemicolons(t *testing.T) {
	for _, content := range []string{
		"router.get(\n '/users/:id',\n handler\n)\n",
		"fastify.route({\n method: 'GET',\n url: '/users/:id',\n handler\n})\n",
	} {
		path := filepath.Join(t.TempDir(), "server.js")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		extractor := NewRouteExtractor()
		require.NoError(t, extractor.scanFile(t.Context(), path))
		routes, err := extractor.GetHarvestedRoutes(t.Context())
		require.NoError(t, err)
		assert.Equal(t, []string{"/users/:id"}, routes)
	}
}
