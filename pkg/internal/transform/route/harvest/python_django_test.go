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

func TestScanPythonFileDjangoMultilineImport(t *testing.T) {
	file := filepath.Join(t.TempDir(), "urls.py")
	require.NoError(t, os.WriteFile(file, []byte(`
from django.urls import (
    include,
    path,
)

urlpatterns = [
    path(
        route="orders/<int:order_id>/",
        view=order_detail,
    ),
]
`), 0o644))

	e := pythonExtractor{
		routes:       map[string]struct{}{},
		djangoRoutes: map[string][]djangoRoute{},
	}
	err := e.scanFile(file)

	require.NoError(t, err)
	assert.Equal(t, []djangoRoute{{path: "orders/<int:order_id>/"}}, e.djangoRoutes[file])
}

func TestExtractPythonDjangoImportAliasInclude(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "checkout"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "checkout", "urls.py"), []byte(`
from django.urls import path

urlpatterns = [path("orders/<int:order_id>/", order_detail)]
`), 0o644))
	for _, importStmt := range []string{
		"from checkout import urls as checkout_urls",
		"import checkout.urls as checkout_urls",
	} {
		t.Run(importStmt, func(t *testing.T) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(importStmt+`
from django.urls import include, path

urlpatterns = [
    path("health/", health_view),
    path("shop/", include(checkout_urls)),
]
`), 0o644))

			result, err := extractPythonRoutes(dir)

			require.NoError(t, err)
			assert.Equal(t, []string{"/health/", "/shop/orders/<int:order_id>/"}, result.Routes)
		})
	}
}

func TestExtractPythonDjangoSkipsUnresolvedInclude(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.urls import include, path

urlpatterns = [
    path("health/", health_view),
    path("shop/", include(unknown_urls)),
]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/health/"}, result.Routes)
}

func TestDjangoCallEnd(t *testing.T) {
	for _, body := range []string{
		`path("orders/", orders)`,
		`path("shop/", include("checkout.urls"))`,
		`path("literal)/", view), path('literal(/', view)`,
		`path("escaped\")/", view)`,
	} {
		t.Run(body, func(t *testing.T) {
			call := "i18n_patterns(" + body + ")"
			stmt := call + ` + [path("health/", health)]`
			assert.Equal(t, len(call)-1, djangoCallEnd(stmt, len("i18n_patterns")))
		})
	}
	assert.Equal(t, -1, djangoCallEnd(`i18n_patterns(path("orders/", orders)`, len("i18n_patterns")))
}

func TestExtractPythonDjangoI18nPatterns(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.conf.urls.i18n import i18n_patterns
from django.urls import path

urlpatterns = i18n_patterns(
    path("orders/<int:order_id>/", order_detail),
) + [path("health/", health_view)]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/<language>/orders/<int:order_id>/", "/health/"}, result.Routes)
	matcher := RouteMatcherFromResult(*result)
	assert.Equal(t, "/<language>/orders/<int:order_id>/", matcher.Find("/en/orders/42/"))
	assert.Equal(t, "/health/", matcher.Find("/health/"))
	assert.Empty(t, matcher.Find("/orders/42/"))
	assert.Empty(t, matcher.Find("/en/health/"))
}

func TestExtractPythonDjangoI18nDefaultLanguageUnprefixed(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.conf.urls.i18n import i18n_patterns
from django.urls import path

urlpatterns = i18n_patterns(
    path("orders/<int:order_id>/", order_detail),
    prefix_default_language=False,
)
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{
		"/<language>/orders/<int:order_id>/",
		"/orders/<int:order_id>/",
	}, result.Routes)
	matcher := RouteMatcherFromResult(*result)
	assert.Equal(t, "/<language>/orders/<int:order_id>/", matcher.Find("/en/orders/42/"))
	assert.Equal(t, "/orders/<int:order_id>/", matcher.Find("/orders/42/"))
}

func TestExtractPythonDjangoI18nInclude(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "checkout"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "checkout", "urls.py"), []byte(`
from django.urls import path
urlpatterns = [path("orders/<int:order_id>/", order_detail)]
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.conf.urls.i18n import i18n_patterns
from django.urls import include, path

urlpatterns = i18n_patterns(
    path("shop/", include("checkout.urls")),
)
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/<language>/shop/orders/<int:order_id>/"}, result.Routes)
	matcher := RouteMatcherFromResult(*result)
	assert.Equal(t, result.Routes[0], matcher.Find("/de/shop/orders/42/"))
	assert.Empty(t, matcher.Find("/shop/orders/42/"))
}

func TestIndexDjangoModules(t *testing.T) {
	dir := t.TempDir()
	urlsFile := filepath.Join(dir, "checkout", "urls.py")
	packageFile := filepath.Join(dir, "checkout", "__init__.py")
	moduleFile := filepath.Join(dir, "checkout.py")
	files := map[string][]djangoRoute{
		urlsFile:    nil,
		packageFile: nil,
		moduleFile:  nil,
	}

	assert.Equal(t, map[string]string{
		"checkout.urls": urlsFile,
		"checkout":      packageFile,
	}, indexDjangoModules(dir, files))
}

func TestDjangoRootFiles(t *testing.T) {
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "project", "urls.py")
	checkoutFile := filepath.Join(dir, "checkout", "urls.py")
	ordersFile := filepath.Join(dir, "orders", "urls.py")
	files := map[string][]djangoRoute{
		rootFile:     {{path: "shop/", includeModule: "checkout.urls"}},
		checkoutFile: {{path: "orders/", includeModule: "orders.urls"}},
		ordersFile:   {{path: "<int:order_id>/"}},
	}
	modules := indexDjangoModules(dir, files)

	assert.Equal(t, []string{rootFile}, djangoRootFiles(files, modules))
}

func TestResolveDjangoRoutes(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]djangoRoute{
		filepath.Join(dir, "project", "urls.py"): {
			{path: "shop/", includeModule: "checkout.urls"},
			{path: "wholesale/", includeModule: "checkout.urls"},
		},
		filepath.Join(dir, "checkout", "urls.py"): {
			{path: "orders/", includeModule: "orders.urls"},
		},
		filepath.Join(dir, "orders", "urls.py"): {
			{path: "<int:order_id>/"},
			{path: "again/", includeModule: "checkout.urls"},
		},
	}
	routes := map[string]struct{}{}

	resolveDjangoRoutes(dir, files, routes)

	assert.Equal(t, map[string]struct{}{
		"/shop/orders/<int:order_id>/":      {},
		"/wholesale/orders/<int:order_id>/": {},
	}, routes)
}
