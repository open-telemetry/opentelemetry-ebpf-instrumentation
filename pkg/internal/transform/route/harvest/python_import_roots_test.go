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

func writePythonFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestExtractPythonRoutesScansImportRoots(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writePythonFile(t, filepath.Join(app, "run.py"), `
from webapp import app

app.run()
`)
	writePythonFile(t, filepath.Join(lib, "webapp.py"), `
from flask import Flask

app = Flask(__name__)

@app.route("/users/<int:user_id>")
def user(user_id):
    return "ok"
`)

	result, err := extractPythonRoutes(t.Context(), app, lib)

	require.NoError(t, err)
	assert.Equal(t, []string{"/users/<int:user_id>"}, result.Routes)
}

func TestExtractPythonRoutesIgnoresMissingImportRoot(t *testing.T) {
	app := t.TempDir()
	writePythonFile(t, filepath.Join(app, "main.py"), `
@app.get("/items/{item_id}")
`)

	result, err := extractPythonRoutes(t.Context(), app, filepath.Join(t.TempDir(), "missing"))

	require.NoError(t, err)
	assert.Equal(t, []string{"/items/{item_id}"}, result.Routes)
}

func TestExtractPythonRoutesStillFailsForMissingAppDir(t *testing.T) {
	result, err := extractPythonRoutes(t.Context(), filepath.Join(t.TempDir(), "missing"), t.TempDir())

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestPythonScanRoots(t *testing.T) {
	for _, tc := range []struct {
		name string
		dirs []string
		want []pythonScanRoot
	}{
		{
			name: "import roots nested in an earlier one",
			dirs: []string{"/srv/app", "/srv/app/vendor", "/opt/lib", "/srv/app", "/opt/lib/sub"},
			want: []pythonScanRoot{{dir: "/srv/app", app: true}, {dir: "/opt/lib"}},
		},
		{
			name: "application directory nested in an import root",
			dirs: []string{"/srv/app/entry", "/opt/lib", "/srv/app"},
			want: []pythonScanRoot{{dir: "/srv/app", app: true}, {dir: "/opt/lib"}},
		},
		{
			name: "import root nested in a later one",
			dirs: []string{"/srv/app", "/opt/lib/sub", "/opt/lib"},
			want: []pythonScanRoot{{dir: "/srv/app", app: true}, {dir: "/opt/lib"}},
		},
		{
			name: "sibling with a common prefix",
			dirs: []string{"/srv/app", "/srv/application"},
			want: []pythonScanRoot{{dir: "/srv/app", app: true}, {dir: "/srv/application"}},
		},
		{
			name: "environment directories",
			dirs: []string{"/srv/app", "/usr/lib/python3/dist-packages", "/opt/venv/lib/python3.12/site-packages"},
			want: []pythonScanRoot{{dir: "/srv/app", app: true}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pythonScanRoots(tc.dirs))
		})
	}
}

func TestExtractPythonRoutesFailsWhenTheRootCoveringTheAppDirFails(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "missing")

	result, err := extractPythonRoutes(t.Context(), filepath.Join(parent, "entry"), parent)

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestExtractPythonRoutesSkipsInstalledPackages(t *testing.T) {
	app := t.TempDir()
	deps := t.TempDir()
	writePythonFile(t, filepath.Join(app, "main.py"), `
@app.get("/items/{item_id}")
`)
	writePythonFile(t, filepath.Join(deps, "django", "contrib", "auth", "urls.py"), `
from django.urls import path

urlpatterns = [
    path("login/", views.LoginView.as_view()),
]
`)
	require.NoError(t, os.MkdirAll(filepath.Join(deps, "Django-5.2.dist-info"), 0o755))

	result, err := extractPythonRoutes(t.Context(), app, deps)

	require.NoError(t, err)
	assert.Equal(t, []string{"/items/{item_id}"}, result.Routes)
	assert.Equal(t, PartialRoutes, result.Kind)
}

func TestExtractPythonDjangoRoutesOnImportRootsArePartial(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writePythonFile(t, filepath.Join(app, "run.py"), `
import shop.wsgi
`)
	writePythonFile(t, filepath.Join(lib, "shop", "urls.py"), `
from django.urls import path

urlpatterns = [
    path("orders/<int:order_id>/", order_detail),
]
`)

	result, err := extractPythonRoutes(t.Context(), app, lib)

	require.NoError(t, err)
	assert.Equal(t, []string{"/orders/<int:order_id>/"}, result.Routes)
	assert.Equal(t, PartialRoutes, result.Kind)
}

func TestExtractPythonDjangoIncludeFromImportRootInsideAppDir(t *testing.T) {
	app := t.TempDir()
	src := filepath.Join(app, "src")
	writePythonFile(t, filepath.Join(src, "proj", "urls.py"), `
from django.urls import include, path

urlpatterns = [
    path("shop/", include("checkout.urls")),
]
`)
	writePythonFile(t, filepath.Join(src, "checkout", "urls.py"), `
from django.urls import path

urlpatterns = [
    path("orders/<int:order_id>/", order_detail),
]
`)

	result, err := extractPythonRoutes(t.Context(), app, src)

	require.NoError(t, err)
	assert.Equal(t, []string{"/shop/orders/<int:order_id>/"}, result.Routes)
	assert.Equal(t, CompleteRoutes, result.Kind)
}

func TestExtractPythonDjangoIncludeAcrossImportRoots(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writePythonFile(t, filepath.Join(app, "urls.py"), `
from django.urls import include, path

urlpatterns = [
    path("shop/", include("checkout.urls")),
]
`)
	writePythonFile(t, filepath.Join(lib, "checkout", "urls.py"), `
from django.urls import path

urlpatterns = [
    path("orders/<int:order_id>/", order_detail),
]
`)

	result, err := extractPythonRoutes(t.Context(), app, lib)

	require.NoError(t, err)
	assert.Equal(t, []string{"/shop/orders/<int:order_id>/"}, result.Routes)
}

func TestIndexDjangoModulesEarlierRootShadowsLater(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	appURLs := filepath.Join(app, "checkout", "urls.py")
	libURLs := filepath.Join(lib, "checkout", "urls.py")
	files := map[string][]djangoRoute{
		appURLs: {{path: "app/"}},
		libURLs: {{path: "lib/"}},
	}

	assert.Equal(t, appURLs, indexDjangoModules([]string{app, lib}, files)["checkout.urls"])
	assert.Equal(t, libURLs, indexDjangoModules([]string{lib, app}, files)["checkout.urls"])
}
