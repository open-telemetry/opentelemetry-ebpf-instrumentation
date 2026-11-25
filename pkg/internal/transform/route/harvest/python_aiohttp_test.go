// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanAiohttp(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		want  []string
	}{
		{
			name: "router calls",
			lines: []string{
				`from aiohttp import web`,
				`app.router.add_get("/users/{user_id}", user)`,
				`app.router.add_post(r'/orders', create_order)`,
				`router.add_view(u"/items", ItemView)`,
				`self.app.router.add_delete("/items/{item_id}", remove)`,
				`app.router.add_route("GET", "/health", health)`,
				`app.router.add_route(hdrs.METH_PUT, '/ready', ready)`,
			},
			want: []string{"/health", "/items", "/items/{item_id}", "/orders", "/ready", "/users/{user_id}"},
		},
		{
			name: "route definitions",
			lines: []string{
				`from aiohttp import hdrs, web`,
				`app.add_routes([web.get("/users/{user_id}", user), web.post('/orders', create_order)])`,
				`app.add_routes([aiohttp.web.view("/items", ItemView)])`,
				`app.add_routes([web.route("PATCH", "/items/{item_id}", update)])`,
			},
			want: []string{"/items", "/items/{item_id}", "/orders", "/users/{user_id}"},
		},
		{
			name: "route table decorators",
			lines: []string{
				`from aiohttp import web`,
				`routes = web.RouteTableDef()`,
				`@routes.get("/users/{user_id}")`,
				`@routes.post('/orders')`,
				`@routes.view("/items")`,
				`@routes.route("DELETE", "/items/{item_id}")`,
			},
			want: []string{"/items", "/items/{item_id}", "/orders", "/users/{user_id}"},
		},
		{
			name: "annotated route table",
			lines: []string{
				`from aiohttp import web`,
				`routes: web.RouteTableDef = web.RouteTableDef()`,
				`@routes.get(r"/users/{user_id:\d+}")`,
				`routes: Flask = Flask(__name__)`,
				`@routes.get(r"/flask/{item_id:\d+}")`,
			},
			want: []string{"/users/{user_id}"},
		},
		{
			name: "regex parameters keep only the name",
			lines: []string{
				`from aiohttp import web`,
				`app.router.add_get(r"/users/{user_id:\d+}", user)`,
				`app.router.add_get(r"/archive/{year:\d{4}}/{slug:[a-z-]+}", archive)`,
				`app.router.add_get("/files/{tail:.*}", files)`,
				`app.router.add_get("/files/{tail:.*}/download", download)`,
			},
			want: []string{"/archive/{year}/{slug}", "/files/{tail:path}", "/users/{user_id}"},
		},
		{
			name: "requires aiohttp import",
			lines: []string{
				`app.router.add_get("/users/{user_id}", user)`,
				`app.add_routes([web.get("/orders", orders)])`,
			},
		},
		{
			name: "keyword and nested paths",
			lines: []string{
				`from aiohttp import web`,
				`app.router.add_get("/download", functools.partial(download, path="/srv/data"))`,
				`app.router.add_delete(handler=remove, path="/items/{item_id}")`,
				`app.add_routes([web.get(path="/orders", handler=orders)])`,
			},
			want: []string{"/download"},
		},
		{
			name: "other libraries",
			lines: []string{
				`import aiohttp`,
				`resp = await web.get("/api/users/1")`,
				`app.add_route(handler, "/sanic/route")`,
				`admin.add_view("/reports", ReportView)`,
				`my_router.add_get("/other", other)`,
			},
		},
		{
			name: "web attribute",
			lines: []string{
				`from aiohttp import web`,
				`resp = await self.web.get("/api/users/1")`,
			},
		},
		{
			name: "unsupported forms",
			lines: []string{
				`from aiohttp import web`,
				`app.router.add_get(f"/{item_id}", item)`,
				`app.router.add_get(PATH, item)`,
				`app.router.add_static("/static", "./static")`,
				`app.add_subapp("/admin", admin)`,
				`resource.add_route("GET", handler)`,
				`app.router.add_get(`,
				`"/split", split)`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes := map[string]struct{}{}
			var aiohttp aiohttpFile
			for _, line := range tc.lines {
				aiohttp.scan(line, routes)
			}

			assert.ElementsMatch(t, tc.want, routeKeys(routes))
		})
	}
}

func TestScanAiohttpOwnsOnlyRouteTableDecorators(t *testing.T) {
	routes := map[string]struct{}{}
	var aiohttp aiohttpFile
	for _, line := range []string{
		`from aiohttp import web`,
		`routes = web.RouteTableDef()`,
	} {
		assert.False(t, aiohttp.scan(line, routes))
	}

	assert.True(t, aiohttp.scan(`@routes.get(r"/users/{user_id:\d+}")`, routes))
	assert.True(t, aiohttp.scan(`@routes.get("/files/{tail:.*}/download")`, routes))
	assert.Equal(t, []string{"/users/{user_id}"}, routeKeys(routes))
	assert.False(t, aiohttp.scan(`@routes.route("/flask")`, routes))
	assert.False(t, aiohttp.scan(`@app.route("/flask")`, routes))
	assert.False(t, aiohttp.scan(`app.router.add_get("/orders", orders)`, routes))

	assert.False(t, aiohttp.scan(`routes = Flask(__name__)`, routes))
	assert.False(t, aiohttp.scan(`@routes.get("/flask")`, routes))
}

func TestExtractPythonAiohttpRoutes(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
from aiohttp import web

routes = web.RouteTableDef()


@routes.get(r"/users/{user_id:\d+}")
async def user(request):
    return web.Response(text="ok")


app = web.Application()
app.router.add_get(
    "/orders/{order_id}",
    order,
)
app.add_routes([
    web.get("/items", items),
    web.post(r"/items/{item_id:\d+}", item),
])
app.add_routes(routes)
`), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir, dir)

	require.NoError(t, err)
	assert.Equal(t, PartialRoutes, result.Kind)
	assert.Equal(t, []string{"/items", "/items/{item_id}", "/orders/{order_id}", "/users/{user_id}"}, result.Routes)
}

func TestExtractPythonAiohttpWithFlask(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
from aiohttp import web
from flask import Flask

flask_app = Flask(__name__)
routes = web.RouteTableDef()


@flask_app.route("/flask/<int:user_id>")
def flask_user(user_id):
    return "ok"


@routes.get(r"/users/{user_id:\d+}")
async def user(request):
    return web.Response(text="ok")
`), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir, dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/flask/<int:user_id>", "/users/{user_id}"}, result.Routes)
}

func TestDependsOnAiohttp(t *testing.T) {
	for _, tc := range []struct {
		name     string
		file     string
		contents string
		want     bool
	}{
		{name: "requirements", file: "requirements.txt", contents: "gunicorn==22.0\naiohttp>=3.9\n", want: true},
		{name: "requirements extras", file: "requirements-prod.txt", contents: "aiohttp[speedups]==3.9.5\n", want: true},
		{name: "requirements unpinned", file: "requirements.txt", contents: "AIOHTTP\r\n", want: true},
		{name: "pyproject dependencies", file: "pyproject.toml", contents: "[project]\ndependencies = [\"aiohttp>=3.9\"]\n", want: true},
		{name: "poetry dependencies", file: "pyproject.toml", contents: "[tool.poetry.dependencies]\naiohttp = \"^3.9\"\n", want: true},
		{name: "pipfile", file: "Pipfile", contents: "[packages]\naiohttp = \"*\"\n", want: true},
		{name: "poetry lock ignored", file: "poetry.lock", contents: "[[package]]\nname = \"aiohttp\"\nversion = \"3.9.5\"\n"},
		{name: "aiohttp plugin only", file: "requirements.txt", contents: "aiohttp-jinja2==1.6\naiohttp_cors\n"},
		{name: "other framework", file: "requirements.txt", contents: "flask==3.0\n"},
		{name: "not a manifest", file: "notes.txt", contents: "aiohttp\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.contents), 0o644))

			got, err := dependsOnAiohttp(t.Context(), dir, dir)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// An application started from a subdirectory keeps its manifests in a parent.
func TestDependsOnAiohttpParentManifest(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "app", "src")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "requirements.txt"), []byte("aiohttp==3.9.5\n"), 0o644))

	got, err := dependsOnAiohttp(t.Context(), root, dir)
	require.NoError(t, err)
	assert.True(t, got)
}

// The nearest manifests describe the application; one further up belongs to
// something else.
func TestDependsOnAiohttpUsesNearestManifest(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "srv", "api")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "srv", "requirements.txt"), []byte("aiohttp\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask\n"), 0o644))

	got, err := dependsOnAiohttp(t.Context(), root, dir)
	require.NoError(t, err)
	assert.False(t, got)
}

// Manifests above the process root belong to the host, not the application.
func TestDependsOnAiohttpStopsAtRoot(t *testing.T) {
	host := t.TempDir()
	root := filepath.Join(host, "root")
	dir := filepath.Join(root, "app")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(host, "requirements.txt"), []byte("aiohttp\n"), 0o644))

	got, err := dependsOnAiohttp(t.Context(), root, dir)
	require.NoError(t, err)
	assert.False(t, got)
}

func TestExtractPythonAiohttpRoutesFromManifest(t *testing.T) {
	routesFile := []byte(`
from .views import index, poll


def setup_routes(app):
    app.router.add_get("/", index)
    app.router.add_get("/poll/{question_id}", poll, name="poll")
`)

	t.Run("listed in requirements", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("aiohttp==3.9.5\n"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "routes.py"), routesFile, 0o644))

		result, err := extractPythonRoutes(t.Context(), dir, dir)

		require.NoError(t, err)
		assert.Equal(t, []string{"/", "/poll/{question_id}"}, result.Routes)
	})

	t.Run("listed in a parent directory", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "app", "src")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "app", "pyproject.toml"), []byte("[project]\ndependencies = [\"aiohttp>=3.9\"]\n"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "routes.py"), routesFile, 0o644))

		result, err := extractPythonRoutes(t.Context(), root, dir)

		require.NoError(t, err)
		assert.Equal(t, []string{"/", "/poll/{question_id}"}, result.Routes)
	})

	t.Run("no manifest", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "routes.py"), routesFile, 0o644))

		result, err := extractPythonRoutes(t.Context(), dir, dir)

		require.NoError(t, err)
		assert.Empty(t, result.Routes)
	})
}

func TestExtractPythonAiohttpMultilineRouteTable(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
from aiohttp import web

routes = web.RouteTableDef(
)


@routes.get(r"/users/{user_id:\d+}")
async def user(request):
    return web.Response(text="ok")
`), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir, dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/users/{user_id}"}, result.Routes)
}

func TestExtractPythonAiohttpReboundRouteTable(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
from aiohttp import web
from flask import Flask

routes = web.RouteTableDef()


@routes.get(r"/users/{user_id:\d+}")
async def user(request):
    return web.Response(text="ok")


routes = Flask(__name__)


@routes.route("/flask/<int:user_id>")
def flask_user(user_id):
    return "ok"
`), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir, dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/flask/<int:user_id>", "/users/{user_id}"}, result.Routes)
}

func TestExtractPythonAiohttpTailRoute(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
from aiohttp import web

app = web.Application()
app.router.add_get("/files/{tail:.*}", files)
app.router.add_get(r"/static/{rest:.+}", static)
`), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir, dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/files/{tail:path}", "/static/{rest:path}"}, result.Routes)

	matcher := RouteMatcherFromResult(*result)
	assert.Equal(t, "/files/{tail:path}", matcher.Find("/files/a/report.txt"))
	assert.Equal(t, "/static/{rest:path}", matcher.Find("/static/css/site.css"))
}

// aiohttp is also a common HTTP client: depending on it does not make client
// calls or other libraries' methods routes.
func TestExtractPythonAiohttpClientOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("aiohttp==3.9.5\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "client.py"), []byte(`
import aiohttp


async def fetch(web):
    async with aiohttp.ClientSession() as session:
        await session.get("/api/users/1")
    await web.get("/api/orders/1")
    await web.post(path="/api/orders", json={})


admin.add_view("/reports", ReportView)
`), 0o644))

	result, err := extractPythonRoutes(t.Context(), dir, dir)

	require.NoError(t, err)
	assert.Empty(t, result.Routes)
}
