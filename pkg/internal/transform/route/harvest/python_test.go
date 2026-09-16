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
@app.get(
    "/items/{item_id}",
    response_model=Item,
    response_model_exclude_none=True,
    tags=["items"],
)
	router = APIRouter(prefix="/api")
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "api", "users.py"), []byte(`
@bp.route(
    '/users/<int:user_id>',
)
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

func TestExtractPythonDjangoRoutes(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "checkout"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "orders"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.urls import include, path

urlpatterns = [
    path("users/<int:user_id>/", user_detail),
    path("shop/", include("checkout.urls")),
]
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "checkout", "urls.py"), []byte(`
from django.urls import include, path

urlpatterns = [
    path("orders/", include("orders.urls")),
]
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "orders", "urls.py"), []byte(`
from django.urls import path

urlpatterns = [
    path("<int:order_id>/", order_detail),
]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{
		"/shop/orders/<int:order_id>/",
		"/users/<int:user_id>/",
	}, result.Routes)
}

func TestExtractPythonDjangoLiteralPrefixes(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "checkout"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.urls import include, path

urlpatterns = [
    path(".", dot_view),
    path("", include("checkout.urls")),
    path("v1.", include("checkout.urls")),
]
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "checkout", "urls.py"), []byte(`
from django.urls import path

urlpatterns = [path("orders/", orders)]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/.", "/orders/", "/v1.orders/"}, result.Routes)
}

func TestExtractPythonDjangoAdminRoutes(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.contrib import admin
from django.urls import path

urlpatterns = [
    path("backoffice/", admin.site.urls),
]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Contains(t, result.Routes, "/backoffice/login/")
	assert.NotContains(t, result.Routes, "/admin/login/")

	matcher := RouteMatcherFromResult(*result)
	for _, tc := range []struct {
		path  string
		route string
	}{
		{path: "/backoffice/login/", route: "/backoffice/login/"},
		{path: "/backoffice/r/7/42/", route: "/backoffice/r/<path:content_type_id>/<path:object_id>/"},
		{path: "/backoffice/auth/user/add/", route: "/backoffice/<app_label>/<model_name>/add/"},
		{path: "/backoffice/auth/user/42/change/", route: "/backoffice/<app_label>/<model_name>/<path:object_id>/change/"},
		{path: "/backoffice/catalog/item/a/b/change/", route: "/backoffice/<app_label>/<model_name>/<path:object_id>/change/"},
	} {
		assert.Equal(t, tc.route, matcher.Find(tc.path), tc.path)
	}
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

func TestExtractPythonRoutesFromSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.py"), []byte(`
@app.get("/items/{item_id}")
`), 0o644))
	root := filepath.Join(t.TempDir(), "root")
	require.NoError(t, os.Symlink(dir, root))

	result, err := extractPythonRoutes(root)

	require.NoError(t, err)
	assert.Equal(t, []string{"/items/{item_id}"}, result.Routes)
}

func TestWalkPythonFilesStopsAtLimit(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.py", "b.py", "c.py"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o644))
	}

	count := 0
	err := walkPythonFilesN(dir, 2, func(string) {
		count++
	})

	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func routeKeys(routes map[string]struct{}) []string {
	keys := make([]string, 0, len(routes))
	for route := range routes {
		keys = append(keys, route)
	}
	return keys
}
