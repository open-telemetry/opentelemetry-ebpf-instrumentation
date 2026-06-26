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

func TestResolveASTRoutes_StringConcatenationLiterals(t *testing.T) {
	routes := scanJSContent(t, "app.post('/api' + '/orders', handler);\n")
	assertHasRoute(t, routes, "POST", "/api/orders")
}

func TestResolveASTRoutes_StringConcatenationVariableAndLiteral(t *testing.T) {
	routes := scanJSContent(t, "const base = '/api';\napp.put(base + '/settings', handler);\n")
	assertHasRoute(t, routes, "PUT", "/api/settings")
}

func TestRouteExtractor_VariableRoutesApp(t *testing.T) {
	extractor := NewRouteExtractor()
	exampleFile := filepath.Join("nodejs", "test_files", "variable-routes-app.js")
	require.NoError(t, extractor.scanFile(exampleFile))

	routes := extractor.GetRoutes()
	require.NotEmpty(t, routes)

	expected := []struct{ method, path string }{
		{"GET", "/users"},
		{"GET", "/api/v1/products"},
		{"DELETE", "/users/:id"},
		{"POST", "/api/orders"},
		{"PUT", "/api/settings"},
		{"GET", "/health"},
	}
	for _, e := range expected {
		assertHasRoute(t, routes, e.method, e.path)
	}
}

func scanJSContent(t *testing.T, content string) []RoutePattern {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.js")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	extractor := NewRouteExtractor()
	require.NoError(t, extractor.scanFile(path))
	return extractor.GetRoutes()
}

// scanJSDir creates multiple files in a temp directory and scans the named entrypoint.
func scanJSDir(t *testing.T, files map[string]string, entrypoint string) []RoutePattern {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	extractor := NewRouteExtractor()
	require.NoError(t, extractor.scanFile(filepath.Join(dir, entrypoint)))
	return extractor.GetRoutes()
}

func assertHasRoute(t *testing.T, routes []RoutePattern, method, path string) {
	t.Helper()
	for _, r := range routes {
		if r.Method == method && r.Path == path {
			return
		}
	}
	t.Fatalf("expected route %s %s, got %v", method, path, routes)
}

func TestResolveASTRoutes_VariablePath(t *testing.T) {
	routes := scanJSContent(t, `
const usersPath = '/users';
app.get(usersPath, (req, res) => res.send('ok'));
`)
	assertHasRoute(t, routes, "GET", "/users")
}

func TestResolveASTRoutes_VariableDeclaredAfterUse(t *testing.T) {
	// Variable resolution must not depend on declaration order.
	routes := scanJSContent(t, `
router.post(createPath, handler);
const createPath = '/api/items';
`)
	assertHasRoute(t, routes, "POST", "/api/items")
}

func TestResolveASTRoutes_TemplateLiteralWithResolvedVar(t *testing.T) {
	routes := scanJSContent(t, "const ver = 'v1';\napp.get(`/api/${ver}/users`, handler);\n")
	assertHasRoute(t, routes, "GET", "/api/v1/users")
}

func TestResolveASTRoutes_TemplateLiteralWithUnresolvedParam(t *testing.T) {
	// An interpolated identifier that cannot be resolved becomes a :param
	// placeholder so the route shape is preserved.
	routes := scanJSContent(t, "app.delete(`/users/${id}`, handler);\n")
	assertHasRoute(t, routes, "DELETE", "/users/:id")
}

func TestResolveASTRoutes_NestedInsideFunction(t *testing.T) {
	// The walker must descend into function bodies.
	routes := scanJSContent(t, `
function registerRoutes(app) {
  const p = '/health';
  app.get(p, handler);
}
`)
	assertHasRoute(t, routes, "GET", "/health")
}

func TestResolveASTRoutes_LineNumberIsSet(t *testing.T) {
	routes := scanJSContent(t, "const p = '/x';\napp.get(p, handler);\n")
	require.NotEmpty(t, routes)
	for _, r := range routes {
		if r.Path == "/x" {
			assert.Positive(t, r.Line, "line number should be set")
			assert.NotEmpty(t, r.File, "file should be set")
		}
	}
}

func TestResolveASTRoutes_SkipsUnparseableSource(t *testing.T) {
	// TypeScript-style annotations are not valid JS; the AST pass must return
	// nil without error rather than emitting bogus routes.
	got := (&RouteExtractor{}).resolveASTRoutes("app.ts", `app.get(p: string, handler);`)
	assert.Nil(t, got)
}

func TestResolveASTRoutes_IgnoresStringLiteralArgs(t *testing.T) {
	// Plain string literals are handled by the regex pass; the AST pass should
	// not re-emit them.
	got := (&RouteExtractor{}).resolveASTRoutes("app.js", `app.get('/literal', handler);`)
	assert.Empty(t, got)
}

func TestResolveASTRoutes_IgnoresUnknownMethod(t *testing.T) {
	got := (&RouteExtractor{}).resolveASTRoutes("app.js", `const p = '/x'; app.listen(p);`)
	assert.Empty(t, got)
}

func TestResolveASTRoutes_IgnoresTemplateLiteralWithoutInterpolation(t *testing.T) {
	// Backtick strings with no ${} are already caught by the regex pass; the
	// AST pass must not re-emit them to avoid duplicates in GetRoutes().
	got := (&RouteExtractor{}).resolveASTRoutes("app.js", "app.get(`/static`, handler);")
	assert.Empty(t, got)
}

func TestResolveASTRoutes_ChainedVariableDependency(t *testing.T) {
	routes := scanJSContent(t, `
const base = '/api';
const full = base + '/users';
app.get(full, handler);
`)
	assertHasRoute(t, routes, "GET", "/api/users")
}

func TestResolveASTRoutes_AssignExpression(t *testing.T) {
	routes := scanJSContent(t, `
let path;
path = '/orders';
app.post(path, handler);
`)
	assertHasRoute(t, routes, "POST", "/orders")
}

func TestResolveASTRoutes_ComplexTemplateExpressionBecomesParam(t *testing.T) {
	routes := scanJSContent(t, "app.get(`/users/${req.params.id}`, handler);\n")
	assertHasRoute(t, routes, "GET", "/users/:param")
}

func TestResolveASTRoutes_ConditionalExpression(t *testing.T) {
	routes := scanJSContent(t, `
const path = isAdmin ? '/admin/users' : '/users';
app.get(path, handler);
`)
	assertHasRoute(t, routes, "GET", "/admin/users")
	assertHasRoute(t, routes, "GET", "/users")
}

func TestResolveASTRoutes_TemplateLiteralWithConditionalInterpolation(t *testing.T) {
	// Cartesian product: template literal whose interpolation resolves to
	// multiple values produces one route per combination.
	routes := scanJSContent(t, "const role = isAdmin ? 'admin' : 'user';\napp.get(`/${role}/profile`, handler);\n")
	assertHasRoute(t, routes, "GET", "/admin/profile")
	assertHasRoute(t, routes, "GET", "/user/profile")
}

func TestResolveASTRoutes_RouteInsideIfBlock(t *testing.T) {
	routes := scanJSContent(t, `
const devPath = '/debug';
if (env === 'development') {
  app.get(devPath, handler);
}
`)
	assertHasRoute(t, routes, "GET", "/debug")
}

func TestResolveASTRoutes_RouteInsideForOfLoop(t *testing.T) {
	routes := scanJSContent(t, `
const itemsPath = '/items';
for (const entry of enabledRoutes) {
  app.get(itemsPath, handler);
}
`)
	assertHasRoute(t, routes, "GET", "/items")
}

func TestResolveASTRoutes_RouteInsideTryCatch(t *testing.T) {
	routes := scanJSContent(t, `
const safePath = '/safe';
try {
  app.get(safePath, handler);
} catch (e) {
  console.error(e);
}
`)
	assertHasRoute(t, routes, "GET", "/safe")
}

func TestResolveASTRoutes_RouteInsideSwitch(t *testing.T) {
	routes := scanJSContent(t, `
const switchPath = '/switched';
switch (env) {
  case 'prod':
    app.get(switchPath, handler);
    break;
}
`)
	assertHasRoute(t, routes, "GET", "/switched")
}

func TestResolveASTRoutes_RouteWithAwait(t *testing.T) {
	routes := scanJSContent(t, `
const asyncPath = '/async';
async function setup() {
  await app.get(asyncPath, handler);
}
`)
	assertHasRoute(t, routes, "GET", "/async")
}

func TestResolveASTRoutes_ForOfLiteralArray(t *testing.T) {
	routes := scanJSContent(t, `
for (const p of ['/users', '/items']) {
  app.get(p, handler);
}
`)
	assertHasRoute(t, routes, "GET", "/users")
	assertHasRoute(t, routes, "GET", "/items")
}

func TestResolveASTRoutes_ForOfVariable(t *testing.T) {
	routes := scanJSContent(t, `
const paths = ['/orders', '/products'];
for (const p of paths) {
  app.post(p, handler);
}
`)
	assertHasRoute(t, routes, "POST", "/orders")
	assertHasRoute(t, routes, "POST", "/products")
}

func TestResolveASTRoutes_ObjectLiteralPropertyAccess(t *testing.T) {
	routes := scanJSContent(t, `
const cfg = { base: '/api/v2' };
app.get(cfg.base, handler);
`)
	assertHasRoute(t, routes, "GET", "/api/v2")
}

func TestResolveASTRoutes_ObjectDestructuring(t *testing.T) {
	routes := scanJSContent(t, `
const cfg = { path: '/admin' };
const { path } = cfg;
app.delete(path, handler);
`)
	assertHasRoute(t, routes, "DELETE", "/admin")
}

func TestResolveASTRoutes_ObjectDestructuringRenamed(t *testing.T) {
	routes := scanJSContent(t, `
const cfg = { path: '/reports' };
const { path: localPath } = cfg;
app.get(localPath, handler);
`)
	assertHasRoute(t, routes, "GET", "/reports")
}

func TestResolveASTRoutes_RequireExports(t *testing.T) {
	routes := scanJSDir(t, map[string]string{
		"config.js": "module.exports = { basePath: '/api/v1' };\n",
		"app.js":    "const cfg = require('./config');\napp.get(cfg.basePath, handler);\n",
	}, "app.js")
	assertHasRoute(t, routes, "GET", "/api/v1")
}

func TestResolveASTRoutes_RequireDestructure(t *testing.T) {
	routes := scanJSDir(t, map[string]string{
		"routes.js": "module.exports = { BASE: '/v2', HEALTH: '/healthz' };\n",
		"app.js":    "const { BASE, HEALTH } = require('./routes');\napp.get(BASE + '/users', handler);\napp.get(HEALTH, handler);\n",
	}, "app.js")
	assertHasRoute(t, routes, "GET", "/v2/users")
	assertHasRoute(t, routes, "GET", "/healthz")
}

func TestResolveASTRoutes_RequireNamedExports(t *testing.T) {
	routes := scanJSDir(t, map[string]string{
		"paths.js":  "exports.root = '/root';\nexports.sub = '/sub';\n",
		"server.js": "const p = require('./paths');\napp.get(p.root, handler);\napp.put(p.sub, handler);\n",
	}, "server.js")
	assertHasRoute(t, routes, "GET", "/root")
	assertHasRoute(t, routes, "PUT", "/sub")
}

func TestResolveASTRoutes_ForOfVarDeclaration(t *testing.T) {
	routes := scanJSContent(t, `
for (var p of ['/stock', '/catalog']) {
  app.get(p, handler);
}
`)
	assertHasRoute(t, routes, "GET", "/stock")
	assertHasRoute(t, routes, "GET", "/catalog")
}

func TestResolveASTRoutes_ForOfExistingVar(t *testing.T) {
	routes := scanJSContent(t, `
let p;
const routePaths = ['/profiles', '/settings'];
for (p of routePaths) {
  app.get(p, handler);
}
`)
	assertHasRoute(t, routes, "GET", "/profiles")
	assertHasRoute(t, routes, "GET", "/settings")
}

func TestResolveASTRoutes_StringLiteralObjectKey(t *testing.T) {
	routes := scanJSContent(t, `
const cfg = { 'base': '/catalog' };
app.get(cfg.base, handler);
`)
	assertHasRoute(t, routes, "GET", "/catalog")
}

func TestResolveASTRoutes_RouteInsideWhileLoop(t *testing.T) {
	routes := scanJSContent(t, `
const loopPath = '/loop';
while (condition) {
  app.get(loopPath, handler);
  break;
}
`)
	assertHasRoute(t, routes, "GET", "/loop")
}

func TestResolveASTRoutes_RouteInsideDoWhile(t *testing.T) {
	routes := scanJSContent(t, `
const oncePath = '/once';
do {
  app.get(oncePath, handler);
} while (false);
`)
	assertHasRoute(t, routes, "GET", "/once")
}

func TestResolveASTRoutes_RouteInsideForLoop(t *testing.T) {
	routes := scanJSContent(t, `
const forPath = '/items';
for (let i = 0; i < 1; i++) {
  app.get(forPath, handler);
}
`)
	assertHasRoute(t, routes, "GET", "/items")
}

func TestResolveASTRoutes_RequireNonExistent(t *testing.T) {
	routes := scanJSContent(t, `const cfg = require('./nonexistent'); app.get(cfg.path, handler);`)
	assert.Empty(t, routes)
}

func TestResolveASTRoutes_RequireNodeModule(t *testing.T) {
	routes := scanJSContent(t, `const express = require('express'); app.get(express.path, handler);`)
	assert.Empty(t, routes)
}

func TestResolveASTRoutes_RequireExportsMixedProps(t *testing.T) {
	routes := scanJSDir(t, map[string]string{
		"cfg.js": "const path = '/ignored';\nmodule.exports = { path, base: '/mixed' };\n",
		"app.js": "const c = require('./cfg');\napp.get(c.base, handler);\n",
	}, "app.js")
	assertHasRoute(t, routes, "GET", "/mixed")
}

func TestResolveASTRoutes_RequireDestructureStringKey(t *testing.T) {
	routes := scanJSDir(t, map[string]string{
		"cfg.js": "module.exports = { 'api-path': '/v2/api' };\n",
		"app.js": "const { 'api-path': apiPath } = require('./cfg');\napp.get(apiPath, handler);\n",
	}, "app.js")
	assertHasRoute(t, routes, "GET", "/v2/api")
}

func TestResolveASTRoutes_NestedDestructuringSkipped(t *testing.T) {
	got := (&RouteExtractor{}).resolveASTRoutes("app.js", `
const outer = { inner: { sub: '/deep' } };
const { inner: { sub } } = outer;
app.get(sub, handler);
`)
	assert.Empty(t, got)
}

func TestResolveASTRoutes_ComputedObjectKeySkipped(t *testing.T) {
	routes := scanJSContent(t, `
const name = 'dynamic';
const cfg = { [name]: '/skip', base: '/keep' };
app.get(cfg.base, handler);
`)
	assertHasRoute(t, routes, "GET", "/keep")
}
