// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"os"
	"path/filepath"
	"regexp/syntax"
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
	assert.Equal(t, []djangoRoute{{path: "orders/<int:order_id>/", listName: "urlpatterns"}}, e.djangoRoutes[file])
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

func TestExtractPythonDjangoListInclude(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.urls import include, path

extra_patterns = [
    path("reports/", reports),
]
urlpatterns = [path("credit/", include(extra_patterns))]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/credit/reports/"}, result.Routes)
}

func TestExtractPythonDjangoNestedListMounts(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.urls import include, path

reports_patterns = [path("reports/", reports)]
extra_patterns = [path("billing/", include(reports_patterns))]
urlpatterns = [
    path("credit/", include(extra_patterns)),
    path("debit/", include(extra_patterns)),
]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/credit/billing/reports/", "/debit/billing/reports/"}, result.Routes)
}

func TestExtractPythonDjangoTupleInclude(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.urls import include, path

extra_patterns = [path("reports/", reports)]
urlpatterns = [path("credit/", include((extra_patterns, "credit"), namespace="billing"))]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/credit/reports/"}, result.Routes)
}

func TestExtractPythonDjangoModuleTupleInclude(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "credit"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "credit", "urls.py"), []byte(`
from django.urls import path
urlpatterns = [path("reports/", reports)]
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.urls import include, path
urlpatterns = [path("credit/", include(("credit.urls", "credit"), namespace="billing"))]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/credit/reports/"}, result.Routes)
}

func TestExtractPythonDjangoRegexRoute(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.urls import re_path

urlpatterns = [re_path(r"^reports/(?P<id>[0-9]+)/$", reports)]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/reports/<id>/"}, result.Routes)
	matcher := RouteMatcherFromResult(*result)
	assert.Equal(t, "/reports/<id>/", matcher.Find("/reports/42/"))
	assert.Equal(t, "/reports/<id>/", matcher.Find("/reports/abc/"))
	assert.Empty(t, matcher.Find("/reports/"))
}

func TestExtractPythonDjangoRegexFixedCount(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.urls import re_path
urlpatterns = [re_path(r"^articles/(?P<year>[0-9]{4})/$", year_archive)]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/articles/<year>/"}, result.Routes)
	matcher := RouteMatcherFromResult(*result)
	assert.Equal(t, "/articles/<year>/", matcher.Find("/articles/2026/"))
}

func TestExtractPythonDjangoRegexInclude(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "reports.py"), []byte(`
from django.urls import re_path
urlpatterns = [re_path(r"^reports/(?P<id>[0-9]+)/$", reports)]
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "urls.py"), []byte(`
from django.urls import include, path
urlpatterns = [path("shop/", include("reports"))]
`), 0o644))

	result, err := extractPythonRoutes(dir)

	require.NoError(t, err)
	assert.Equal(t, []string{"/shop/reports/<id>/"}, result.Routes)
	matcher := RouteMatcherFromResult(*result)
	assert.Equal(t, "/shop/reports/<id>/", matcher.Find("/shop/reports/42/"))
	assert.Empty(t, matcher.Find("/reports/42/"))
}

func TestDjangoRegexExprRoute(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		route   string
		ok      bool
	}{
		{pattern: `^articles/(?P<year>[0-9]{4})/$`, route: "articles/<year>/", ok: true},
		{pattern: `^reports/(?P<id>[0-9]+)/$`, route: "reports/<id>/", ok: true},
		{pattern: `^health/$`, route: "health/", ok: true},
		{pattern: `^articles/(archive/)?$`, ok: false},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			expr, err := syntax.Parse(tc.pattern, syntax.Perl)
			require.NoError(t, err)

			route, ok := djangoRegexExprRoute(expr)

			assert.Equal(t, tc.route, route)
			assert.Equal(t, tc.ok, ok)
		})
	}
}

func TestDjangoRegexRouteUnsupported(t *testing.T) {
	for _, pattern := range []string{
		`(?i)^reports/(?P<id>[0-9]+)/$`,
		`^reports/(?:archive/)?$`,
		`^reports/(?P<id>[0-9]+|[a-z]+)/$`,
		`^reports/(?P<id>([0-9]+))/$`,
		`^reports/(?P<id>[^x]+)/$`,
		`^page(?P<num>[0-9]+)/$`,
	} {
		t.Run(pattern, func(t *testing.T) {
			_, ok := djangoRegexRoute(pattern)
			assert.False(t, ok)
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
