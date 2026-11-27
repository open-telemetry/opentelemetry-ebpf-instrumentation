// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/pythontools"
)

// extractImportRoots scans dirs as import roots, the first one being the
// application directory.
func extractImportRoots(t *testing.T, dirs ...string) (*RouteHarvesterResult, error) {
	t.Helper()
	return extractImportRootRoutes(t.Context(), "/", pythontools.AppDirs{App: dirs[0], ImportRoots: dirs}, maxPythonFiles)
}

func TestExtractPythonProcessRoutesIgnoresImportRootsWhenTheAppHasRoutes(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writePythonFile(t, filepath.Join(app, "main.py"), `
@app.get("/items/{item_id}")
`)
	writePythonFile(t, filepath.Join(lib, "other.py"), `
@app.get("/other/{id}")
`)

	result, err := extractPythonProcessRoutes(t.Context(), "/", pythontools.AppDirs{App: app, ImportRoots: []string{app, lib}})

	require.NoError(t, err)
	assert.Equal(t, []string{"/items/{item_id}"}, result.Routes)
}

func TestExtractPythonProcessRoutesScansImportRootsWhenTheAppHasNoRoutes(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writePythonFile(t, filepath.Join(app, "run.py"), `
from webapp import app

app.run()
`)
	writePythonFile(t, filepath.Join(lib, "webapp.py"), `
@app.route("/users/<int:user_id>")
`)

	result, err := extractPythonProcessRoutes(t.Context(), "/", pythontools.AppDirs{App: app, ImportRoots: []string{app, lib}})

	require.NoError(t, err)
	assert.Equal(t, []string{"/users/<int:user_id>"}, result.Routes)
	assert.Equal(t, PartialRoutes, result.Kind)
}

func TestExtractPythonDjangoShadowedAppURLconfDoesNotCompleteRoutes(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writePythonFile(t, filepath.Join(app, "checkout", "__init__.py"), "")
	writeDjangoURLs(t, filepath.Join(app, "checkout", "urls.py"), `path("app/", view),`)
	writePythonFile(t, filepath.Join(lib, "checkout", "__init__.py"), "")
	writePythonFile(t, filepath.Join(lib, "checkout", "urls.py"), "")
	writePythonFile(t, filepath.Join(lib, "webapp.py"), `
@app.get("/users/{user_id}")
`)

	result, err := extractImportRootRoutes(t.Context(), "/", pythontools.AppDirs{App: app, ImportRoots: []string{lib, app}}, maxPythonFiles)

	require.NoError(t, err)
	assert.Equal(t, []string{"/users/{user_id}"}, result.Routes)
	assert.Equal(t, PartialRoutes, result.Kind)
}

func writeRecord(t *testing.T, distInfo, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(distInfo, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "RECORD"), []byte(content), 0o644))
}

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

	result, err := extractImportRoots(t, app, lib)

	require.NoError(t, err)
	assert.Equal(t, []string{"/users/<int:user_id>"}, result.Routes)
}

func TestExtractPythonRoutesIgnoresMissingImportRoot(t *testing.T) {
	app := t.TempDir()
	writePythonFile(t, filepath.Join(app, "main.py"), `
@app.get("/items/{item_id}")
`)

	result, err := extractImportRoots(t, app, filepath.Join(t.TempDir(), "missing"))

	require.NoError(t, err)
	assert.Equal(t, []string{"/items/{item_id}"}, result.Routes)
}

func TestExtractPythonRoutesStillFailsForMissingAppDir(t *testing.T) {
	result, err := extractImportRoots(t, filepath.Join(t.TempDir(), "missing"), t.TempDir())

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestPythonScanRoots(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dirs       []string
		roots      []string
		boundaries []string
	}{
		{
			name:       "application directory first, duplicates dropped",
			dirs:       []string{"/srv/app", "/opt/lib", "/srv/app", "/opt/lib"},
			roots:      []string{"/srv/app", "/opt/lib"},
			boundaries: []string{"/srv/app", "/opt/lib"},
		},
		{
			name:       "nested roots are kept and bound each other",
			dirs:       []string{"/srv/zapp", "/srv", "/srv/lib"},
			roots:      []string{"/srv/zapp", "/srv", "/srv/lib"},
			boundaries: []string{"/srv/zapp", "/srv", "/srv/lib"},
		},
		{
			name:       "installation directories are boundaries, not roots",
			dirs:       []string{"/srv/app", "/usr/lib/python3/dist-packages", "/opt/venv/lib/python3.12/site-packages"},
			roots:      []string{"/srv/app"},
			boundaries: []string{"/srv/app", "/usr/lib/python3/dist-packages", "/opt/venv/lib/python3.12/site-packages"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, boundaries := pythonScanRoots(tc.dirs, "")
			assert.Equal(t, tc.roots, roots)
			assert.ElementsMatch(t, tc.boundaries, slices.Collect(maps.Keys(boundaries)))
		})
	}
}

func TestExtractPythonRoutesSkipsInstalledPackagesNestedInAnImportRoot(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	vendor := filepath.Join(lib, "vendor")
	writeRecord(t, filepath.Join(vendor, "dep-1.0.dist-info"),
		"dep/__init__.py,sha256=x,0\ndep/routes.py,sha256=x,10\ndep-1.0.dist-info/RECORD,,\n../../bin/dep,sha256=x,5\n")
	writePythonFile(t, filepath.Join(lib, "webapp.py"), `
@app.get("/users/{user_id}")
`)
	writePythonFile(t, filepath.Join(vendor, "dep", "routes.py"), `
@app.get("/dependency/{id}")
`)

	result, err := extractImportRoots(t, app, lib, vendor)

	require.NoError(t, err)
	assert.Equal(t, []string{"/users/{user_id}"}, result.Routes)
}

func TestExtractPythonRoutesScansExplicitRootsSkippedByName(t *testing.T) {
	srv := t.TempDir()
	app := filepath.Join(srv, "lib")
	writePythonFile(t, filepath.Join(app, "main.py"), `
@app.get("/items/{item_id}")
`)
	shared := filepath.Join(srv, "shared", "lib")
	writePythonFile(t, filepath.Join(shared, "users.py"), `
@app.get("/users/{user_id}")
`)

	result, err := extractImportRoots(t, app, srv, shared)

	require.NoError(t, err)
	assert.Equal(t, []string{"/items/{item_id}", "/users/{user_id}"}, result.Routes)
}

func TestExtractPythonRoutesFailsWhenTheRootCoveringTheAppDirFails(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "missing")

	result, err := extractImportRoots(t, filepath.Join(parent, "entry"), parent)

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
	writeRecord(t, filepath.Join(deps, "Django-5.2.dist-info"),
		"django/__init__.py,sha256=x,0\ndjango/contrib/auth/urls.py,sha256=x,10\n")

	result, err := extractImportRoots(t, app, deps)

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

	result, err := extractImportRoots(t, app, lib)

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

	result, err := extractImportRoots(t, app, src)

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

	result, err := extractImportRoots(t, app, lib)

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

	assert.Equal(t, appURLs, importRootDjangoModules("/", []string{app, lib}, files)["checkout.urls"])
	assert.Equal(t, libURLs, importRootDjangoModules("/", []string{lib, app}, files)["checkout.urls"])
}

func TestIndexDjangoModulesRegularPackageBeatsEarlierNamespacePortion(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	appURLs := filepath.Join(app, "checkout", "urls.py")
	libURLs := filepath.Join(lib, "checkout", "urls.py")
	files := map[string][]djangoRoute{
		appURLs: {{path: "app/"}},
		filepath.Join(lib, "checkout", "__init__.py"): nil,
		libURLs: {{path: "lib/"}},
	}

	assert.Equal(t, libURLs, importRootDjangoModules("/", []string{app, lib}, files)["checkout.urls"])
}

func TestExtractPythonDjangoShadowedModuleIsNotARoot(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writePythonFile(t, filepath.Join(app, "project", "urls.py"), `
from django.urls import include, path

urlpatterns = [
    path("shop/", include("checkout.urls")),
]
`)
	writePythonFile(t, filepath.Join(app, "checkout", "__init__.py"), "")
	writePythonFile(t, filepath.Join(app, "checkout", "urls.py"), `
from django.urls import path

urlpatterns = [
    path("app/", app_view),
]
`)
	writePythonFile(t, filepath.Join(lib, "checkout", "__init__.py"), "")
	writePythonFile(t, filepath.Join(lib, "checkout", "urls.py"), `
from django.urls import path

urlpatterns = [
    path("lib/", lib_view),
]
`)

	result, err := extractImportRoots(t, app, lib)

	require.NoError(t, err)
	assert.Equal(t, []string{"/shop/app/"}, result.Routes)
}

func TestExtractPythonRoutesScansCodeNextToInstalledPackages(t *testing.T) {
	srv := t.TempDir()
	app := filepath.Join(srv, "app")
	writePythonFile(t, filepath.Join(app, "webapp.py"), `
@app.get("/users/{user_id}")
`)
	writeRecord(t, filepath.Join(app, "flask-3.1.dist-info"),
		"flask/__init__.py,sha256=x,0\nflask/app.py,sha256=x,10\n")
	writePythonFile(t, filepath.Join(app, "flask", "app.py"), `
@app.get("/dependency/{id}")
`)

	result, err := extractImportRoots(t, srv, app)

	require.NoError(t, err)
	assert.Equal(t, []string{"/users/{user_id}"}, result.Routes)
}

func TestExtractPythonRoutesSharesTheFileLimitAcrossRoots(t *testing.T) {
	app := t.TempDir()
	first := t.TempDir()
	second := t.TempDir()
	writePythonFile(t, filepath.Join(app, "main.py"), `
@app.get("/app")
`)
	for _, name := range []string{"a", "b"} {
		writePythonFile(t, filepath.Join(first, name+".py"), "@app.get(\"/first/"+name+"\")\n")
	}
	writePythonFile(t, filepath.Join(second, "c.py"), `
@app.get("/second")
`)
	dirs := []string{app, first, second}

	result, err := extractImportRootRoutes(t.Context(), "/", pythontools.AppDirs{App: app, ImportRoots: dirs}, 2)

	require.NoError(t, err)
	assert.Equal(t, []string{"/app", "/first/a"}, result.Routes)
}

func TestExtractPythonDjangoIncludeWithoutTheAppDirOnTheImportPath(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writePythonFile(t, filepath.Join(app, "project", "urls.py"), `
from django.urls import include, path

urlpatterns = [
    path("shop/", include("checkout.urls")),
]
`)
	for dir, route := range map[string]string{app: "app/", lib: "lib/"} {
		writePythonFile(t, filepath.Join(dir, "checkout", "__init__.py"), "")
		writePythonFile(t, filepath.Join(dir, "checkout", "urls.py"), `
from django.urls import path

urlpatterns = [
    path("`+route+`", view),
]
`)
	}

	result, err := extractImportRootRoutes(t.Context(), "/", pythontools.AppDirs{App: app, ImportRoots: []string{lib}}, maxPythonFiles)

	require.NoError(t, err)
	assert.Equal(t, []string{"/shop/lib/"}, result.Routes)
}

func TestExtractPythonRoutesKeepsApplicationCodeInASharedNamespace(t *testing.T) {
	app := t.TempDir()
	writePythonFile(t, filepath.Join(app, "acme", "web", "routes.py"), `
@app.get("/users/{user_id}")
`)
	writePythonFile(t, filepath.Join(app, "acme", "util", "__init__.py"), "")
	writePythonFile(t, filepath.Join(app, "acme", "util", "routes.py"), `
@app.get("/dependency/{id}")
`)
	writeRecord(t, filepath.Join(app, "acme_util-1.0.dist-info"),
		"acme/util/__init__.py,sha256=x,0\nacme/util/routes.py,sha256=x,10\n")

	result, err := extractImportRoots(t, app)

	require.NoError(t, err)
	assert.Equal(t, []string{"/users/{user_id}"}, result.Routes)
}

func TestExtractPythonDjangoInstalledPackageShadowsAppNamespacePortion(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writePythonFile(t, filepath.Join(app, "project", "urls.py"), `
from django.urls import include, path

urlpatterns = [
    path("shop/", include("checkout.urls")),
]
`)
	writePythonFile(t, filepath.Join(app, "checkout", "urls.py"), `
from django.urls import path

urlpatterns = [
    path("app/", app_view),
]
`)
	writePythonFile(t, filepath.Join(lib, "checkout", "__init__.py"), "")
	writePythonFile(t, filepath.Join(lib, "checkout", "urls.py"), `
from django.urls import path

urlpatterns = [
    path("installed/", installed_view),
]
`)
	writeRecord(t, filepath.Join(lib, "checkout-1.0.dist-info"),
		"checkout/__init__.py,sha256=x,0\ncheckout/urls.py,sha256=x,10\n")

	result, err := extractImportRoots(t, app, lib)

	require.NoError(t, err)
	assert.Empty(t, result.Routes)
}

func writeDjangoURLs(t *testing.T, path, patterns string) {
	t.Helper()
	writePythonFile(t, path, `
from django.urls import include, path

urlpatterns = [
    `+patterns+`
]
`)
}

func TestExtractPythonDjangoIncludeFollowsLauncherSearchOrder(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writeDjangoURLs(t, filepath.Join(app, "project", "urls.py"), `path("shop/", include("checkout.urls")),`)
	for dir, route := range map[string]string{app: "app/", lib: "lib/"} {
		writePythonFile(t, filepath.Join(dir, "checkout", "__init__.py"), "")
		writeDjangoURLs(t, filepath.Join(dir, "checkout", "urls.py"), `path("`+route+`", view),`)
	}

	result, err := extractImportRootRoutes(t.Context(), "/", pythontools.AppDirs{App: app, ImportRoots: []string{lib, app}}, maxPythonFiles)

	require.NoError(t, err)
	assert.Equal(t, []string{"/shop/lib/"}, result.Routes)
}

func TestExtractPythonRoutesScansNestedRootsBeforeExternalOnes(t *testing.T) {
	app := t.TempDir()
	shared := t.TempDir()
	src := filepath.Join(app, "src")
	writePythonFile(t, filepath.Join(app, "main.py"), `
@app.get("/app")
`)
	writePythonFile(t, filepath.Join(src, "users.py"), `
@app.get("/src")
`)
	for _, name := range []string{"a", "b"} {
		writePythonFile(t, filepath.Join(shared, name+".py"), "@app.get(\"/shared/"+name+"\")\n")
	}
	dirs := []string{app, shared, src}

	result, err := extractImportRootRoutes(t.Context(), "/", pythontools.AppDirs{App: app, ImportRoots: dirs}, 2)

	require.NoError(t, err)
	assert.Equal(t, []string{"/app", "/src"}, result.Routes)
}

func TestExtractPythonRoutesScansThePackagedApplication(t *testing.T) {
	app := t.TempDir()
	target := filepath.Join(app, "myapp", "__main__.py")
	writePythonFile(t, filepath.Join(app, "myapp", "__init__.py"), "")
	writePythonFile(t, target, "")
	writePythonFile(t, filepath.Join(app, "myapp", "routes.py"), `
@app.get("/users/{user_id}")
`)
	writeRecord(t, filepath.Join(app, "myapp-1.0.dist-info"),
		"myapp/__init__.py,sha256=x,0\nmyapp/__main__.py,sha256=x,0\nmyapp/routes.py,sha256=x,10\n")

	result, err := extractImportRootRoutes(t.Context(), "/", pythontools.AppDirs{App: app, ImportRoots: []string{app}, Target: target}, maxPythonFiles)

	require.NoError(t, err)
	assert.Equal(t, []string{"/users/{user_id}"}, result.Routes)
}

func TestExtractPythonDjangoBlockedModuleIsNotARoot(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writePythonFile(t, filepath.Join(app, "checkout.py"), "")
	writePythonFile(t, filepath.Join(lib, "checkout", "__init__.py"), "")
	writeDjangoURLs(t, filepath.Join(lib, "checkout", "urls.py"), `path("lib/", view),`)

	result, err := extractImportRoots(t, app, lib)

	require.NoError(t, err)
	assert.Empty(t, result.Routes)
}

func TestExtractPythonDjangoShadowedIncludeDoesNotHideARoot(t *testing.T) {
	app := t.TempDir()
	lib := t.TempDir()
	writeDjangoURLs(t, filepath.Join(app, "project", "urls.py"), `path("shop/", include("checkout.urls")),`)
	writePythonFile(t, filepath.Join(app, "checkout", "__init__.py"), "")
	writeDjangoURLs(t, filepath.Join(app, "checkout", "urls.py"), `path("app/", view),`)
	writePythonFile(t, filepath.Join(lib, "checkout", "__init__.py"), "")
	writeDjangoURLs(t, filepath.Join(lib, "checkout", "urls.py"), `path("loop/", include("project.urls")),`)

	result, err := extractImportRoots(t, app, lib)

	require.NoError(t, err)
	assert.Equal(t, []string{"/shop/app/"}, result.Routes)
}
