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

func TestParenDelta(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want int
	}{
		{name: "empty", line: "", want: 0},
		{name: "opening call", line: `path(`, want: 1},
		{name: "opening list", line: `urlpatterns = [`, want: 1},
		{name: "nested openings", line: `path("credit/", include([`, want: 3},
		{name: "closing delimiters", line: `]))`, want: -3},
		{name: "balanced", line: `[path("reports/", reports)]`, want: 0},
		{name: "double quoted delimiters", line: `path("[(", view)`, want: 0},
		{name: "single quoted delimiters", line: `path(')]', view)`, want: 0},
		{name: "escaped double quote", line: `path("a\"[(", view)`, want: 0},
		{name: "escaped single quote", line: `path('a\')]', view)`, want: 0},
		{name: "escaped backslash", line: `path("a\\", view)`, want: 0},
		{name: "comment", line: `# path([`, want: 0},
		{name: "trailing comment", line: `urlpatterns = [ # ])`, want: 1},
		{name: "quoted hash", line: `path("#", view`, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parenDelta(tc.line))
		})
	}
}

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

	result, err := extractPythonRoutes(t.Context(), dir)

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

	result, err := extractPythonRoutes(t.Context(), dir)

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

	result, err := extractPythonRoutes(t.Context(), dir)

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

	result, err := extractPythonRoutes(t.Context(), dir)

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

func TestExtractPythonPyramidRoutes(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
from wsgiref.simple_server import make_server

from pyramid.config import Configurator
from pyramid.response import Response


def user(request):
    return Response("ok")


with Configurator() as config:
    config.add_route("user", "/users/{user_id}")
    config.add_route(
        "order",
        pattern=r"/orders/{order_id:\d+}",
    )
    config.add_view(user, route_name="user")
    config.include(".routes")
    app = config.make_wsgi_app()
make_server("127.0.0.1", 18105, app).serve_forever()
`), 0o644))
	// includeme modules usually don't import pyramid.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "routes.py"), []byte(`
def includeme(config):
    config.add_route("static", "/static/*subpath")
    config.add_route("item", "items/{item_id}")
`), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir)

	require.NoError(t, err)
	assert.Equal(t, CompleteRoutes, result.Kind)
	assert.Equal(t, []string{"/items/{item_id}", "/orders/{order_id}", "/static/*", "/users/{user_id}"}, result.Routes)

	matcher := RouteMatcherFromResult(*result)
	for _, tc := range []struct {
		path  string
		route string
	}{
		{path: "/users/7", route: "/users/{user_id}"},
		{path: "/orders/42", route: "/orders/{order_id}"},
		{path: "/items/5", route: "/items/{item_id}"},
		{path: "/static/css/app.css", route: "/static/*"},
	} {
		assert.Equal(t, tc.route, matcher.Find(tc.path), tc.path)
	}
}

func TestExtractPythonPyramidRoutesAreNotCombined(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
from pyramid.config import Configurator

with Configurator() as config:
    config.add_route("users", "/users")
    config.add_route("user", "/users/{user_id}")
    config.add_route("page", "/{slug}")
`), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir)

	require.NoError(t, err)
	matcher := RouteMatcherFromResult(*result)
	assert.Equal(t, "/users/{user_id}", matcher.Find("/users/7"))
	assert.Equal(t, "/{slug}", matcher.Find("/about"))
	assert.Empty(t, matcher.Find("/users/7/extra"))
}

func TestExtractPythonPyramidRoutesWithFlaskRoutesStayPartial(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
import pyramid

config.add_route("user", "/users/{user_id}")
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "legacy.py"), []byte(`
@bp.route("/legacy")
`), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir)

	require.NoError(t, err)
	assert.Equal(t, PartialRoutes, result.Kind)
	assert.Equal(t, []string{"/legacy", "/users/{user_id}"}, result.Routes)
}

func TestExtractPythonPyramidRoutesRequirePyramidImport(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
import aiohttp

app.router.add_route("GET", "users/{user_id}", handler)
config.add_route("user", "/users/{user_id}")
`), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir)

	require.NoError(t, err)
	assert.Empty(t, result.Routes)
}

func TestExtractPythonRoutesSkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	data := strings.Repeat("# filler\n", int(maxPythonFileBytes/9)+1) + `@app.get("/large")`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "large.py"), []byte(data), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir)

	require.NoError(t, err)
	assert.Empty(t, result.Routes)
}

func TestExtractPythonRoutesMissingDir(t *testing.T) {
	result, err := extractPythonRoutes(t.Context(), filepath.Join(t.TempDir(), "missing"))

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

	result, err := extractPythonRoutes(t.Context(), root)

	require.NoError(t, err)
	assert.Equal(t, []string{"/items/{item_id}"}, result.Routes)
}

func TestWalkPythonFilesStopsAtLimit(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.py", "b.py", "c.py"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o644))
	}

	count := 0
	err := walkPythonFilesN(t.Context(), dir, 2, func(string) error {
		count++
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestWalkPythonFilesCancellation(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.py", "b.py", "nested/c.py"} {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, nil, 0o644))
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	visited := 0
	err := walkPythonFiles(ctx, dir, func(string) error {
		visited++
		cancel()
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, visited)
}

func TestExtractPythonRoutesCanceled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.py")
	require.NoError(t, os.WriteFile(path, []byte("@app.get('/users')\n"), 0o644))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	extractor := pythonExtractor{routes: map[string]struct{}{}, djangoRoutes: map[string][]djangoRoute{}}
	require.ErrorIs(t, extractor.scanFile(ctx, path), context.Canceled)
	assert.Empty(t, extractor.routes)
	result, err := extractPythonRoutes(ctx, dir)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, result)
	result, err = ExtractPythonRoutes(ctx, nil)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, result)
}

func TestPythonFileScanStopsAtDeadline(t *testing.T) {
	const lines = 100000
	var content strings.Builder
	for i := range lines {
		fmt.Fprintf(&content, "@app.get('/users/%d')\n", i)
	}
	path := filepath.Join(t.TempDir(), "server.py")
	require.NoError(t, os.WriteFile(path, []byte(content.String()), 0o644))
	extractor := pythonExtractor{routes: map[string]struct{}{}, djangoRoutes: map[string][]djangoRoute{}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	require.ErrorIs(t, extractor.scanFile(ctx, path), context.DeadlineExceeded)
	assert.Less(t, len(extractor.routes), lines)
}

func routeKeys(routes map[string]struct{}) []string {
	keys := make([]string, 0, len(routes))
	for route := range routes {
		keys = append(keys, route)
	}
	return keys
}
