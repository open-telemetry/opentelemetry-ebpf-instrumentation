// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractPythonRoutes(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "api"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".venv"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`
@app.get("/items/{item_id}")
router = APIRouter(prefix="/api")
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "api", "users.py"), []byte(`
@bp.route('/users/<int:user_id>')
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".venv", "dep.py"), []byte(`
@app.get("/dependency")
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte(`
@app.get("/notes")
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, PartialRoutes, result.Kind)
	assert.Equal(t, []string{"/api", "/items/{item_id}", "/users/<int:user_id>"}, result.Routes)
}

func TestExtractPythonRoutesSkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	data := strings.Repeat("# filler\n", int(maxPythonFileBytes/9)+1) + `@app.get("/large")`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "large.py"), []byte(data), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Empty(t, result.Routes)
}

func TestExtractPythonRoutesMissingDir(t *testing.T) {
	result, err := extractPythonRoutes(filepath.Join(t.TempDir(), "missing"))

	require.Error(t, err)
	assert.Nil(t, result)
}

func routeKeys(routes map[string]struct{}) []string {
	keys := make([]string, 0, len(routes))
	for route := range routes {
		keys = append(keys, route)
	}
	return keys
}
