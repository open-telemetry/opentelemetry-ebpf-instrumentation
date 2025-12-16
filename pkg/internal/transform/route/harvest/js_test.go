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

func TestRouteExtractor_ExpressApp(t *testing.T) {
	extractor := NewRouteExtractor()
	exampleFile := filepath.Join("nodejs", "test_files", "express-app.js")
	err := extractor.scanFile(exampleFile)
	require.NoError(t, err)

	routes := extractor.GetRoutes()
	require.NotEmpty(t, routes, "should extract routes from express-app.js")

	// Expected routes from express-app.js
	expectedRoutes := []RoutePattern{
		{Method: "GET", Path: "/"},
		{Method: "POST", Path: "/users"},
		{Method: "GET", Path: "/users/:id"},
		{Method: "PUT", Path: "/users/:userId/posts/:postId"},
		{Method: "DELETE", Path: "/api/v1/items/:id"},
		{Method: "ALL", Path: "/books"},
		{Method: "ALL", Path: "/books/:id"},
		{Method: "GET", Path: "/profile"},
		{Method: "POST", Path: "/settings"},
		{Method: "PATCH", Path: "/account/:accountId"},
		{Method: "ALL", Path: "/admin/*"},
	}

	// Verify we found the expected number of routes
	assert.GreaterOrEqual(t, len(routes), len(expectedRoutes), "should find at least the expected routes")

	// Check that each expected route exists
	for _, expected := range expectedRoutes {
		found := false
		for _, actual := range routes {
			if actual.Method == expected.Method && actual.Path == expected.Path {
				found = true
				assert.NotEmpty(t, actual.File, "file should be set")
				assert.Positive(t, actual.Line, "line number should be positive")
				break
			}
		}
		assert.True(t, found, "should find route %s %s", expected.Method, expected.Path)
	}
}

func TestRouteExtractor_FastifyApp(t *testing.T) {
	extractor := NewRouteExtractor()
	exampleFile := filepath.Join("nodejs", "test_files", "fastify-app.js")
	err := extractor.scanFile(exampleFile)
	require.NoError(t, err)

	routes := extractor.GetRoutes()
	require.NotEmpty(t, routes, "should extract routes from fastify-app.js")

	// Expected routes from fastify-app.js
	expectedRoutes := []RoutePattern{
		{Method: "GET", Path: "/"},
		{Method: "POST", Path: "/users"},
		{Method: "GET", Path: "/users/:id"},
		{Method: "PUT", Path: "/posts/:postId/comments/:commentId"},
		{Method: "GET", Path: "/search"},
		{Method: "POST", Path: "/api/v2/items"},
		{Method: "DELETE", Path: "/api/v2/items/:id"},
		{Method: "PATCH", Path: "/settings/:key"},
		{Method: "DELETE", Path: "/cache"},
	}

	// Verify we found the expected number of routes
	assert.GreaterOrEqual(t, len(routes), len(expectedRoutes), "should find at least the expected routes")

	// Check that each expected route exists
	for _, expected := range expectedRoutes {
		found := false
		for _, actual := range routes {
			if actual.Method == expected.Method && actual.Path == expected.Path {
				found = true
				assert.NotEmpty(t, actual.File, "file should be set")
				assert.Positive(t, actual.Line, "line number should be positive")
				break
			}
		}
		assert.True(t, found, "should find route %s %s", expected.Method, expected.Path)
	}
}

func TestRouteExtractor_HttpDispatcherApp(t *testing.T) {
	extractor := NewRouteExtractor()
	exampleFile := filepath.Join("nodejs", "test_files", "httpdispatcher-app.js")
	err := extractor.scanFile(exampleFile)
	require.NoError(t, err)

	routes := extractor.GetRoutes()
	require.NotEmpty(t, routes, "should extract routes from httpdispatcher-app.js")

	// Expected routes from httpdispatcher-app.js
	expectedRoutes := []RoutePattern{
		{Method: "GET", Path: "/health"},
		{Method: "GET", Path: "/users"},
		{Method: "POST", Path: "/^\\/ratings\\/[0-9]*//"},                    // Regex route
		{Method: "GET", Path: "/^\\/ratings\\/[0-9]*//"},                     // Regex route
		{Method: "PUT", Path: "/^\\/api\\/v1\\/products\\/[a-zA-Z0-9-]+$//"}, // Regex route
		{Method: "DELETE", Path: "/items/:id"},
		{Method: "GET", Path: "/^\\/files\\/.*\\.pdf$//"}, // Regex route
	}

	// Verify we found the expected number of routes
	assert.GreaterOrEqual(t, len(routes), len(expectedRoutes), "should find at least the expected routes")

	// Check that each expected route exists
	for _, expected := range expectedRoutes {
		found := false
		for _, actual := range routes {
			if actual.Method == expected.Method && actual.Path == expected.Path {
				found = true
				assert.NotEmpty(t, actual.File, "file should be set")
				assert.Positive(t, actual.Line, "line number should be positive")
				break
			}
		}
		assert.True(t, found, "should find route %s %s", expected.Method, expected.Path)
	}
}

func TestRouteExtractor_NextJSManifest(t *testing.T) {
	extractor := NewRouteExtractor()
	// The routes-manifest.json is in test_files/.next/
	examplesDir := filepath.Join("nodejs", "test_files")
	err := extractor.extractNextJSRoutesFromManifest(examplesDir)
	require.NoError(t, err)

	routes := extractor.GetRoutes()
	require.NotEmpty(t, routes, "should extract routes from routes-manifest.json")

	// Expected routes from routes-manifest.json
	// Note: root "/" is filtered out by GetHarvestedRoutes
	expectedRoutes := []RoutePattern{
		{Method: "ALL", Path: "/blog"},
		{Method: "ALL", Path: "/users"},
		{Method: "ALL", Path: "/favicon.ico"},
		{Method: "ALL", Path: "/blog/:slug"},
		{Method: "ALL", Path: "/users/:userId"},
		{Method: "ALL", Path: "/users/:userId/posts/:postId"},
	}

	// Verify we found the expected number of routes
	assert.GreaterOrEqual(t, len(routes), len(expectedRoutes), "should find at least the expected routes")

	// Check that each expected route exists
	for _, expected := range expectedRoutes {
		found := false
		for _, actual := range routes {
			if actual.Method == expected.Method && actual.Path == expected.Path {
				found = true
				assert.NotEmpty(t, actual.File, "file should be set")
				assert.Equal(t, 0, actual.Line, "line number should be 0 for manifest routes")
				break
			}
		}
		assert.True(t, found, "should find route %s %s", expected.Method, expected.Path)
	}
}

func TestRouteExtractor_AllExamples(t *testing.T) {
	extractor := NewRouteExtractor()
	examplesDir := filepath.Join("nodejs", "test_files")

	// Extract Next.js routes from manifest first
	err := extractor.extractNextJSRoutesFromManifest(examplesDir)
	require.NoError(t, err)

	err = extractor.ScanDirectory(examplesDir)
	require.NoError(t, err)

	routes := extractor.GetRoutes()
	require.NotEmpty(t, routes, "should extract routes from all example files")

	// Group routes by file
	routesByFile := make(map[string][]RoutePattern)
	for _, route := range routes {
		filename := filepath.Base(route.File)
		routesByFile[filename] = append(routesByFile[filename], route)
	}

	// Verify we found routes in each example file
	assert.NotEmpty(t, routesByFile["express-app.js"], "should have routes from express-app.js")
	assert.NotEmpty(t, routesByFile["fastify-app.js"], "should have routes from fastify-app.js")
	assert.NotEmpty(t, routesByFile["httpdispatcher-app.js"], "should have routes from httpdispatcher-app.js")
	assert.NotEmpty(t, routesByFile["routes-manifest.json"], "should have routes from routes-manifest.json")

	// Verify route details
	for filename, fileRoutes := range routesByFile {
		t.Run(filename, func(t *testing.T) {
			for _, route := range fileRoutes {
				assert.NotEmpty(t, route.Method, "method should not be empty")
				assert.NotEmpty(t, route.Path, "path should not be empty")
				assert.Contains(t, route.File, filename, "file should match")
				// Manifest routes have line 0, JS files have positive line numbers
				if filename == "routes-manifest.json" {
					assert.Equal(t, 0, route.Line, "manifest routes should have line 0")
				} else {
					assert.Positive(t, route.Line, "line should be positive")
				}
			}
		})
	}
}

func TestRouteExtractor_ParameterizedRoutes(t *testing.T) {
	extractor := NewRouteExtractor()
	examplesDir := filepath.Join("nodejs", "test_files")
	err := extractor.ScanDirectory(examplesDir)
	require.NoError(t, err)

	routes := extractor.GetRoutes()

	// Find routes with parameters
	paramRoutes := []RoutePattern{}
	for _, route := range routes {
		if strings.Contains(route.Path, ":") {
			paramRoutes = append(paramRoutes, route)
		}
	}

	// Verify parameter syntax
	assert.NotEmpty(t, paramRoutes, "should find routes with parameters")
	for _, route := range paramRoutes {
		assert.Contains(t, route.Path, ":", "parameterized route should contain :")
		t.Logf("Found parameterized route: %s %s", route.Method, route.Path)
	}
}

func TestRouteExtractor_RegexRoutes(t *testing.T) {
	extractor := NewRouteExtractor()
	exampleFile := filepath.Join("nodejs", "test_files", "httpdispatcher-app.js")
	err := extractor.scanFile(exampleFile)
	require.NoError(t, err)

	routes := extractor.GetRoutes()

	// Find routes with regex patterns (wrapped in /)
	regexRoutes := []RoutePattern{}
	for _, route := range routes {
		if strings.HasPrefix(route.Path, "/") && strings.HasSuffix(route.Path, "/") && len(route.Path) > 2 {
			regexRoutes = append(regexRoutes, route)
		}
	}

	// Verify regex patterns are preserved
	assert.NotEmpty(t, regexRoutes, "should find regex routes")
	for _, route := range regexRoutes {
		assert.True(t, strings.HasPrefix(route.Path, "/"), "regex route should start with /")
		assert.True(t, strings.HasSuffix(route.Path, "/"), "regex route should end with /")
		t.Logf("Found regex route: %s %s", route.Method, route.Path)
	}
}

// Unit tests for individual handler functions

func TestExpressPendingRoute(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *RoutePattern
		found    bool
	}{
		{
			name:  "valid route() with single quotes",
			line:  "  app.route('/books')",
			found: true,
			expected: &RoutePattern{
				Method: "ALL",
				Path:   "/books",
			},
		},
		{
			name:  "valid route() with double quotes",
			line:  `  router.route("/users/:id")`,
			found: true,
			expected: &RoutePattern{
				Method: "ALL",
				Path:   "/users/:id",
			},
		},
		{
			name:  "valid route() with backticks",
			line:  "  app.route(`/api/v1/items`)",
			found: true,
			expected: &RoutePattern{
				Method: "ALL",
				Path:   "/api/v1/items",
			},
		},
		{
			name:  "route with parameters",
			line:  "  app.route('/users/:userId/posts/:postId')",
			found: true,
			expected: &RoutePattern{
				Method: "ALL",
				Path:   "/users/:userId/posts/:postId",
			},
		},
		{
			name:  "not a route() pattern",
			line:  "  app.get('/users', handler)",
			found: false,
		},
		{
			name:  "route() with variable",
			line:  "  app.route(apiPath)",
			found: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			found := extractor.expressPendingRoute("test.js", tt.line, 10)

			assert.Equal(t, tt.found, found, "found status should match")

			if tt.found {
				require.Len(t, extractor.routes, 1, "should have one route")
				actual := extractor.routes[0]
				assert.Equal(t, tt.expected.Method, actual.Method)
				assert.Equal(t, tt.expected.Path, actual.Path)
				assert.Equal(t, "test.js", actual.File)
				assert.Equal(t, 10, actual.Line)
			} else {
				assert.Empty(t, extractor.routes, "should have no routes")
			}
		})
	}
}

func TestHandleTypicalRoute(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *RoutePattern
		found    bool
	}{
		{
			name:  "app.get with single quotes",
			line:  "  app.get('/users', handler)",
			found: true,
			expected: &RoutePattern{
				Method: "GET",
				Path:   "/users",
			},
		},
		{
			name:  "router.post with double quotes",
			line:  `  router.post("/items", createItem)`,
			found: true,
			expected: &RoutePattern{
				Method: "POST",
				Path:   "/items",
			},
		},
		{
			name:  "app.put with backticks",
			line:  "  app.put(`/users/:id`, updateUser)",
			found: true,
			expected: &RoutePattern{
				Method: "PUT",
				Path:   "/users/:id",
			},
		},
		{
			name:  "app.delete",
			line:  "  app.delete('/items/:id', deleteItem)",
			found: true,
			expected: &RoutePattern{
				Method: "DELETE",
				Path:   "/items/:id",
			},
		},
		{
			name:  "app.patch",
			line:  "  app.patch('/users/:id', patchUser)",
			found: true,
			expected: &RoutePattern{
				Method: "PATCH",
				Path:   "/users/:id",
			},
		},
		{
			name:  "app.all",
			line:  "  app.all('/admin/*', authMiddleware)",
			found: true,
			expected: &RoutePattern{
				Method: "ALL",
				Path:   "/admin/*",
			},
		},
		{
			name:  "nested path parameters",
			line:  "  router.put('/users/:userId/posts/:postId', handler)",
			found: true,
			expected: &RoutePattern{
				Method: "PUT",
				Path:   "/users/:userId/posts/:postId",
			},
		},
		{
			name:  "not a route pattern",
			line:  "  console.log('test')",
			found: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			found := extractor.handleTypicalRoute("test.js", tt.line, 15)

			assert.Equal(t, tt.found, found)

			if tt.found {
				require.Len(t, extractor.routes, 1)
				actual := extractor.routes[0]
				assert.Equal(t, tt.expected.Method, actual.Method)
				assert.Equal(t, tt.expected.Path, actual.Path)
				assert.Equal(t, "test.js", actual.File)
				assert.Equal(t, 15, actual.Line)
			} else {
				assert.Empty(t, extractor.routes)
			}
		})
	}
}

func TestHandleFastifyRoute(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *RoutePattern
		found    bool
	}{
		{
			name:  "fastify.route with method and url",
			line:  `  fastify.route({ method: 'GET', url: '/users' })`,
			found: true,
			expected: &RoutePattern{
				Method: "GET",
				Path:   "/users",
			},
		},
		{
			name:  "route with POST method",
			line:  `  fastify.route({ method: 'POST', url: '/items', handler: createItem })`,
			found: true,
			expected: &RoutePattern{
				Method: "POST",
				Path:   "/items",
			},
		},
		{
			name:  "route with double quotes",
			line:  `  fastify.route({ method: "DELETE", url: "/items/:id" })`,
			found: true,
			expected: &RoutePattern{
				Method: "DELETE",
				Path:   "/items/:id",
			},
		},
		{
			name:  "route with backticks",
			line:  "  fastify.route({ method: `PUT`, url: `/users/:id` })",
			found: true,
			expected: &RoutePattern{
				Method: "PUT",
				Path:   "/users/:id",
			},
		},
		{
			name:  "not a fastify.route pattern",
			line:  "  fastify.get('/users', handler)",
			found: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			found := extractor.handleFastifyRoute("test.js", tt.line, 20)

			assert.Equal(t, tt.found, found)

			if tt.found {
				require.Len(t, extractor.routes, 1)
				actual := extractor.routes[0]
				assert.Equal(t, tt.expected.Method, actual.Method)
				assert.Equal(t, tt.expected.Path, actual.Path)
				assert.Equal(t, "test.js", actual.File)
				assert.Equal(t, 20, actual.Line)
			} else {
				assert.Empty(t, extractor.routes)
			}
		})
	}
}

func TestHandleHapi(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *RoutePattern
		found    bool
	}{
		{
			name:  "hapi server.route with GET",
			line:  `  server.route({ method: 'GET', path: '/users' })`,
			found: true,
			expected: &RoutePattern{
				Method: "GET",
				Path:   "/users",
			},
		},
		{
			name:  "hapi with path parameters",
			line:  `  server.route({ method: 'POST', path: '/users/{id}', handler: createUser })`,
			found: true,
			expected: &RoutePattern{
				Method: "POST",
				Path:   "/users/{id}",
			},
		},
		{
			name:  "hapi with double quotes",
			line:  `  server.route({ method: "DELETE", path: "/items/{id}" })`,
			found: true,
			expected: &RoutePattern{
				Method: "DELETE",
				Path:   "/items/{id}",
			},
		},
		{
			name:  "not a hapi pattern",
			line:  "  server.get('/users')",
			found: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			found := extractor.handleHapi("test.js", tt.line, 25)

			assert.Equal(t, tt.found, found)

			if tt.found {
				require.Len(t, extractor.routes, 1)
				actual := extractor.routes[0]
				assert.Equal(t, tt.expected.Method, actual.Method)
				assert.Equal(t, tt.expected.Path, actual.Path)
				assert.Equal(t, "test.js", actual.File)
				assert.Equal(t, 25, actual.Line)
			} else {
				assert.Empty(t, extractor.routes)
			}
		})
	}
}

func TestHandleRestify(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *RoutePattern
		found    bool
	}{
		{
			name:  "restify server.get",
			line:  "  server.get('/users', handler)",
			found: true,
			expected: &RoutePattern{
				Method: "GET",
				Path:   "/users",
			},
		},
		{
			name:  "restify server.post",
			line:  "  server.post('/items', createItem)",
			found: true,
			expected: &RoutePattern{
				Method: "POST",
				Path:   "/items",
			},
		},
		{
			name:  "restify server.del (normalized to DELETE)",
			line:  "  server.del('/items/:id', deleteItem)",
			found: true,
			expected: &RoutePattern{
				Method: "DELETE",
				Path:   "/items/:id",
			},
		},
		{
			name:  "restify server.opts (normalized to OPTIONS)",
			line:  "  server.opts('/api', optionsHandler)",
			found: true,
			expected: &RoutePattern{
				Method: "OPTIONS",
				Path:   "/api",
			},
		},
		{
			name:  "restify server.put",
			line:  "  server.put('/users/:id', updateUser)",
			found: true,
			expected: &RoutePattern{
				Method: "PUT",
				Path:   "/users/:id",
			},
		},
		{
			name:  "not a restify pattern",
			line:  "  server.listen(3000)",
			found: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			found := extractor.handleRestify("test.js", tt.line, 30)

			assert.Equal(t, tt.found, found)

			if tt.found {
				require.Len(t, extractor.routes, 1)
				actual := extractor.routes[0]
				assert.Equal(t, tt.expected.Method, actual.Method)
				assert.Equal(t, tt.expected.Path, actual.Path)
				assert.Equal(t, "test.js", actual.File)
				assert.Equal(t, 30, actual.Line)
			} else {
				assert.Empty(t, extractor.routes)
			}
		})
	}
}

func TestHandleNestJS(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *RoutePattern
		found    bool
	}{
		{
			name:  "NestJS @Get decorator",
			line:  "  @Get('/users')",
			found: true,
			expected: &RoutePattern{
				Method: "GET",
				Path:   "/users",
			},
		},
		{
			name:  "NestJS @Post decorator",
			line:  "  @Post('/items')",
			found: true,
			expected: &RoutePattern{
				Method: "POST",
				Path:   "/items",
			},
		},
		{
			name:  "NestJS @Delete with parameter",
			line:  "  @Delete('/items/:id')",
			found: true,
			expected: &RoutePattern{
				Method: "DELETE",
				Path:   "/items/:id",
			},
		},
		{
			name:  "NestJS @Put decorator",
			line:  "  @Put('/users/:id')",
			found: true,
			expected: &RoutePattern{
				Method: "PUT",
				Path:   "/users/:id",
			},
		},
		{
			name:  "NestJS @Patch decorator",
			line:  "  @Patch('/settings')",
			found: true,
			expected: &RoutePattern{
				Method: "PATCH",
				Path:   "/settings",
			},
		},
		{
			name:  "NestJS decorator with empty path (defaults to /)",
			line:  "  @Get()",
			found: false,
		},
		{
			name:  "NestJS @Get with empty string (defaults to /)",
			line:  "  @Get('')",
			found: true,
			expected: &RoutePattern{
				Method: "GET",
				Path:   "/",
			},
		},
		{
			name:  "not a NestJS decorator",
			line:  "  function getUsers() {}",
			found: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			found := extractor.handleNestJS("test.ts", tt.line, 35)

			assert.Equal(t, tt.found, found)

			if tt.found {
				require.Len(t, extractor.routes, 1)
				actual := extractor.routes[0]
				assert.Equal(t, tt.expected.Method, actual.Method)
				assert.Equal(t, tt.expected.Path, actual.Path)
				assert.Equal(t, "test.ts", actual.File)
				assert.Equal(t, 35, actual.Line)
			} else {
				assert.Empty(t, extractor.routes)
			}
		})
	}
}

func TestHandleHTTPDispatcher(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *RoutePattern
		found    bool
	}{
		{
			name:  "dispatcher.onGet with string path",
			line:  "  dispatcher.onGet('/users', handler)",
			found: true,
			expected: &RoutePattern{
				Method: "GET",
				Path:   "/users",
			},
		},
		{
			name:  "dispatcher.onPost with string path",
			line:  "  dispatcher.onPost('/items', createItem)",
			found: true,
			expected: &RoutePattern{
				Method: "POST",
				Path:   "/items",
			},
		},
		{
			name:  "dispatcher.onGet with regex pattern",
			line:  "  dispatcher.onGet(/^\\/ratings\\/[0-9]*/, handler)",
			found: true,
			expected: &RoutePattern{
				Method: "GET",
				Path:   "/^\\/ratings\\/[0-9]*//",
			},
		},
		{
			name:  "dispatcher.onPost with regex pattern",
			line:  "  dispatcher.onPost(/^\\/api\\/v1\\/products\\/[a-zA-Z0-9-]+$/, createProduct)",
			found: true,
			expected: &RoutePattern{
				Method: "POST",
				Path:   "/^\\/api\\/v1\\/products\\/[a-zA-Z0-9-]+$//",
			},
		},
		{
			name:  "dispatcher.onDelete with string path and parameter",
			line:  "  dispatcher.onDelete('/items/:id', deleteItem)",
			found: true,
			expected: &RoutePattern{
				Method: "DELETE",
				Path:   "/items/:id",
			},
		},
		{
			name:  "dispatcher.onPut with regex",
			line:  "  dispatcher.onPut(/^\\/files\\/.*\\.pdf$/, uploadPdf)",
			found: true,
			expected: &RoutePattern{
				Method: "PUT",
				Path:   "/^\\/files\\/.*\\.pdf$//",
			},
		},
		{
			name:  "dispatcher.onPatch",
			line:  "  dispatcher.onPatch('/settings/:key', patchSetting)",
			found: true,
			expected: &RoutePattern{
				Method: "PATCH",
				Path:   "/settings/:key",
			},
		},
		{
			name:  "dispatcher.onAll",
			line:  "  dispatcher.onAll('/admin/*', authMiddleware)",
			found: true,
			expected: &RoutePattern{
				Method: "ALL",
				Path:   "/admin/*",
			},
		},
		{
			name:  "not a dispatcher pattern",
			line:  "  dispatcher.setErrorHandler(errorHandler)",
			found: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			found := extractor.handleHTTPDispatcher("test.js", tt.line, 40)

			assert.Equal(t, tt.found, found)

			if tt.found {
				require.Len(t, extractor.routes, 1)
				actual := extractor.routes[0]
				assert.Equal(t, tt.expected.Method, actual.Method)
				assert.Equal(t, tt.expected.Path, actual.Path)
				assert.Equal(t, "test.js", actual.File)
				assert.Equal(t, 40, actual.Line)
			} else {
				assert.Empty(t, extractor.routes)
			}
		})
	}
}

func TestCleanupRegexPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "pattern with special chars",
			input:    "/^\\/test\\/[a-z]+\\-[0-9]+$/",
			expected: "/test/:id",
		},
		{
			name:     "regex with wildcard",
			input:    "/^\\/files\\/.*\\.pdf$/",
			expected: "/files/:id",
		},
		{
			name:     "simple string path (not regex)",
			input:    "/users/:id",
			expected: "/users/:id",
		},
		{
			name:     "regex with character class",
			input:    "/^\\/api\\/v1\\/products\\/[a-zA-Z0-9-]+$/",
			expected: "/api/v1/products/:id",
		},
		{
			name:     "regex with numeric pattern",
			input:    "/^\\/ratings\\/[0-9]*/",
			expected: "/ratings/:id",
		},
		{
			name:     "regex with multiple patterns",
			input:    "/^\\/users\\/[0-9]+\\/posts\\/[a-z]+$/",
			expected: "/users/:id/posts/:id",
		},
		{
			name:     "regex with .+ wildcard",
			input:    "/^\\/documents\\/.+$/",
			expected: "/documents/:id",
		},
		{
			name:     "complex pattern with multiple character classes",
			input:    "/^\\/api\\/[a-z]+\\/items\\/[0-9]+$/",
			expected: "/api/:id/items/:id",
		},
		{
			name:     "pattern with optional quantifier",
			input:    "/^\\/path\\/[a-z]?$/",
			expected: "/path/:id",
		},
		{
			name:     "empty regex pattern",
			input:    "//",
			expected: "/",
		},
		{
			name:     "non-regex path",
			input:    "/api/users",
			expected: "/api/users",
		},
		{
			name:     "path with existing parameter",
			input:    "/users/:userId",
			expected: "/users/:userId",
		},
		{
			name:     "regex without anchors",
			input:    "/\\/users\\/[0-9]+/",
			expected: "/users/:id",
		},
		{
			name:     "multiple consecutive slashes",
			input:    "/api///users///:id",
			expected: "/api/users/:id",
		},
		{
			name:     "regex resulting in multiple slashes",
			input:    "/^\\/\\/api\\/\\/users/",
			expected: "/api/users",
		},
		{
			name:     "trailing slash removed",
			input:    "/^\\/api\\/users\\/$/",
			expected: "/api/users",
		},
		{
			name:     "root path keeps single slash",
			input:    "/^\\/$/",
			expected: "/",
		},
		{
			name:     "path with trailing slash in non-regex",
			input:    "/api/users/",
			expected: "/api/users",
		},
		{
			name:     "complex regex with multiple consecutive :id",
			input:    "/^\\/[a-z]+\\/[0-9]+\\/[a-z]+$/",
			expected: "/:id/:id/:id",
		},
		{
			name:     "regex with escaped special characters",
			input:    "/^\\/api\\/v1\\/[a-zA-Z0-9_\\-]+$/",
			expected: "/api/v1/:id",
		},
		{
			name:     "path with underscores preserved",
			input:    "/^\\/api_v1\\/users$/",
			expected: "/api_v1/users",
		},
		{
			name:     "path with hyphens preserved",
			input:    "/^\\/api-v1\\/items$/",
			expected: "/api-v1/items",
		},
		{
			name:     "mixed wildcards and character classes",
			input:    "/^\\/files\\/.+\\/[0-9]+\\/.*$/",
			expected: "/files/:id/:id/:id",
		},
		{
			name:     "very short regex",
			input:    "/^$/",
			expected: "/",
		},
		{
			name:     "path with query params pattern (should be cleaned)",
			input:    "/^\\/api\\/users\\?[a-z]+$/",
			expected: "/api/users",
		},
		{
			name:     "deeply nested path with multiple patterns",
			input:    "/^\\/api\\/v[0-9]+\\/users\\/[a-z0-9]+\\/posts\\/[0-9]+\\/comments$/",
			expected: "/api/:id/users/:id/posts/:id/comments",
		},
		{
			name:     "path starting without slash",
			input:    "api/users",
			expected: "",
		},
		{
			name:     "Hapi or fastify paths with curlies",
			input:    "/api/users/{userId}",
			expected: "/api/users/{userId}",
		},
		{
			name:     "single slash",
			input:    "/",
			expected: "",
		},
		{
			name:     "regex with only anchors",
			input:    "/^$/",
			expected: "/",
		},
		{
			name:     "path with file extension in pattern",
			input:    "/^\\/downloads\\/[a-z]+\\.zip$/",
			expected: "/downloads/:id",
		},
		{
			name:     "complex negative lookahead pattern",
			input:    "/((?!_next/static|_next/image|favicon.ico|sign-in|new-user|forgot-password|email-url-expired|sign-up|confirm-email-url|auth/callback|votes|monitoring|events).*)",
			expected: "/:id/:id/:id/:id",
		},
		{
			name:     "path with file extension and subdirectory",
			input:    "/app/supabase/prod-eu.crt",
			expected: "/app/supabase/prod-eu.crt",
		},
		{
			name:     "path with query string parameter",
			input:    "/sign-up?email=${encodeURIComponent(email)}",
			expected: "/sign-up",
		},
		{
			name:     "path with query string parameter",
			input:    "/forgot-password?message=Error sending password reset email",
			expected: "/forgot-password",
		},
		{
			name:     "path with wildcard parameter",
			input:    "/events/edit/:path*",
			expected: "/events/edit/:path",
		},
		{
			name:     "next.js dynamic route with brackets",
			input:    "/my-events/[eventId]",
			expected: "/my-events/[eventId]",
		},
		{
			name:     "template literal with single variable",
			input:    "/events/${eventId}",
			expected: "/events/{eventId}",
		},
		{
			name:     "template literal with multiple variables",
			input:    "/votes/${tenantId}/${eventId}",
			expected: "/votes/{tenantId}/{eventId}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			result := extractor.CleanupRegexPath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractNodejsRoutes(t *testing.T) {
	// Save original functions
	origRootDir := rootDirForPID
	origCmdline := cmdlineForPID
	origCwd := cwdForPID

	// Restore after test
	defer func() {
		rootDirForPID = origRootDir
		cmdlineForPID = origCmdline
		cwdForPID = origCwd
	}()

	// Create test directory structure
	tempDir := t.TempDir()
	testAppDir := filepath.Join(tempDir, "app")
	require.NoError(t, os.MkdirAll(testAppDir, 0o755))

	// Create a simple test JavaScript file with routes
	testFile := filepath.Join(testAppDir, "server.js")
	testContent := `
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
	res.json({ users: [] });
});

app.post('/api/users', (req, res) => {
	res.json({ created: true });
});

app.get('/api/users/:id', (req, res) => {
	res.json({ id: req.params.id });
});

app.listen(3000);
`
	require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0o644))

	// Create a separate Next.js app directory for the manifest test
	nextAppDir := filepath.Join(tempDir, "nextapp")
	require.NoError(t, os.MkdirAll(nextAppDir, 0o755))

	// Create .next directory with manifest
	nextDir := filepath.Join(nextAppDir, ".next")
	require.NoError(t, os.MkdirAll(nextDir, 0o755))

	manifestContent := `{
		"staticRoutes": [
			{"page": "/"},
			{"page": "/about"}
		],
		"dynamicRoutes": [
			{"page": "/products/[id]"},
			{"page": "/blog/[...slug]"}
		]
	}`
	manifestPath := filepath.Join(nextDir, "routes-manifest.json")
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifestContent), 0o644))

	// Create a JavaScript file in .next directory that would add unwanted routes if scanned
	nextServerFile := filepath.Join(nextDir, "server.js")
	nextServerContent := `
const express = require('express');
const app = express();

// This route should NOT appear in results because .next is skipped
app.get('/should-not-appear', (req, res) => {
	res.send('build artifact');
});
`
	require.NoError(t, os.WriteFile(nextServerFile, []byte(nextServerContent), 0o644))

	// Create a regular server file outside .next
	nextAppServerFile := filepath.Join(nextAppDir, "server.js")
	nextAppServerContent := `
const express = require('express');
const app = express();

// This route SHOULD appear because it's in the main app directory
app.get('/api/health', (req, res) => {
	res.json({ status: 'ok' });
});
`
	require.NoError(t, os.WriteFile(nextAppServerFile, []byte(nextAppServerContent), 0o644))

	tests := []struct {
		name              string
		pid               int32
		mockRootDir       string
		mockCmdline       []string
		mockCwd           string
		cmdlineErr        error
		cwdErr            error
		expectedErr       string
		expectedCount     int
		expectedRoutes    []string
		notExpectedRoutes []string // Routes that should NOT be present
	}{
		{
			name:        "successful extraction",
			pid:         12345,
			mockRootDir: tempDir,
			mockCmdline: []string{"node", "/app/server.js"},
			mockCwd:     "/app",
			expectedRoutes: []string{
				"/api/users",
				"/api/users/:id",
			},
			expectedCount: 2,
		},
		{
			name:        "cmdline error",
			pid:         12345,
			mockRootDir: tempDir,
			mockCmdline: nil,
			mockCwd:     "/app",
			cmdlineErr:  assert.AnError,
			expectedErr: "error finding cmd line",
		},
		{
			name:        "cwd error",
			pid:         12345,
			mockRootDir: tempDir,
			mockCmdline: []string{"node", "/app/server.js"},
			mockCwd:     "",
			cwdErr:      assert.AnError,
			expectedErr: "error finding cwd",
		},
		{
			name:        "script directory not found",
			pid:         12345,
			mockRootDir: tempDir,
			mockCmdline: []string{"node", "/nonexistent/script.js"},
			mockCwd:     "/nonexistent",
			expectedErr: "error scanning directory, error lstat",
		},
		{
			name:        "relative path in args",
			pid:         12345,
			mockRootDir: tempDir,
			mockCmdline: []string{"node", "server.js"},
			mockCwd:     "/app",
			expectedRoutes: []string{
				"/api/users",
				"/api/users/:id",
			},
			expectedCount: 2,
		},
		{
			name:        "args with flags",
			pid:         12345,
			mockRootDir: tempDir,
			mockCmdline: []string{"node", "--inspect", "/app/server.js"},
			mockCwd:     "/app",
			expectedRoutes: []string{
				"/api/users",
				"/api/users/:id",
			},
			expectedCount: 2,
		},
		{
			name:        "prefers Next.js manifest and skips .next directory",
			pid:         12346,
			mockRootDir: tempDir,
			mockCmdline: []string{"node", "/nextapp/server.js"},
			mockCwd:     "/nextapp",
			expectedRoutes: []string{
				"/about",        // from manifest (root "/" is filtered out by GetHarvestedRoutes)
				"/products/:id", // from manifest
				"/blog/:slug",   // from manifest
				"/api/health",   // from server.js in main app directory
			},
			notExpectedRoutes: []string{
				"/should-not-appear", // from .next/server.js - should be skipped
			},
			expectedCount: 4, // 3 from manifest (excluding /) + 1 from server.js
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the helper functions
			rootDirForPID = func(pid int32) string {
				assert.Equal(t, tt.pid, pid)
				return tt.mockRootDir
			}

			cmdlineForPID = func(pid int32) (string, []string, error) {
				assert.Equal(t, tt.pid, pid)
				if tt.cmdlineErr != nil {
					return "", nil, tt.cmdlineErr
				}
				var exe string
				if len(tt.mockCmdline) > 0 {
					exe = tt.mockCmdline[0]
				}
				return exe, tt.mockCmdline, nil
			}

			cwdForPID = func(pid int32) (string, error) {
				assert.Equal(t, tt.pid, pid)
				if tt.cwdErr != nil {
					return "", tt.cwdErr
				}
				return tt.mockCwd, nil
			}

			// Execute the function
			result, err := ExtractNodejsRoutes(tt.pid)

			// Verify results
			if tt.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, CompleteRoutes, result.Kind)
				assert.Len(t, result.Routes, tt.expectedCount)

				// Check that expected routes are present
				for _, expectedRoute := range tt.expectedRoutes {
					assert.Contains(t, result.Routes, expectedRoute, "should contain route %s", expectedRoute)
				}

				// Check that routes that should NOT be present are absent
				for _, notExpectedRoute := range tt.notExpectedRoutes {
					assert.NotContains(t, result.Routes, notExpectedRoute, "should not contain route %s", notExpectedRoute)
				}
			}
		})
	}
}

func TestExtractNodejsRoutes_EmptyDirectory(t *testing.T) {
	// Save original functions
	origRootDir := rootDirForPID
	origCmdline := cmdlineForPID
	origCwd := cwdForPID

	defer func() {
		rootDirForPID = origRootDir
		cmdlineForPID = origCmdline
		cwdForPID = origCwd
	}()

	// Create empty directory
	tempDir := t.TempDir()
	emptyDir := filepath.Join(tempDir, "empty")
	require.NoError(t, os.MkdirAll(emptyDir, 0o755))

	rootDirForPID = func(_ int32) string {
		return tempDir
	}

	cmdlineForPID = func(_ int32) (string, []string, error) {
		return "node", []string{"node", "server.js"}, nil
	}

	cwdForPID = func(_ int32) (string, error) {
		return "/empty", nil
	}

	result, err := ExtractNodejsRoutes(12345)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, CompleteRoutes, result.Kind)
	assert.Empty(t, result.Routes, "should return empty routes for empty directory")
}

func TestExtractNextJSRoutesFromManifest(t *testing.T) {
	tests := []struct {
		name            string
		manifestContent string
		expectedRoutes  []RoutePattern
		shouldError     bool
		removeReadPerm  bool   // if true, remove read permissions to simulate permission error
		skipManifest    bool   // if true, skip creating the manifest file to test not found scenario
		errorContains   string // expected error message substring
	}{
		{
			name: "static and dynamic routes",
			manifestContent: `{
				"staticRoutes": [
					{"page": "/"},
					{"page": "/about"},
					{"page": "/contact"}
				],
				"dynamicRoutes": [
					{"page": "/users/[id]"},
					{"page": "/posts/[slug]"}
				]
			}`,
			expectedRoutes: []RoutePattern{
				{Method: "ALL", Path: "/"},
				{Method: "ALL", Path: "/about"},
				{Method: "ALL", Path: "/contact"},
				{Method: "ALL", Path: "/users/:id"},
				{Method: "ALL", Path: "/posts/:slug"},
			},
		},
		{
			name: "catch-all routes",
			manifestContent: `{
				"staticRoutes": [
					{"page": "/api/health"}
				],
				"dynamicRoutes": [
					{"page": "/docs/[...slug]"},
					{"page": "/blog/[year]/[month]/[...rest]"}
				]
			}`,
			expectedRoutes: []RoutePattern{
				{Method: "ALL", Path: "/api/health"},
				{Method: "ALL", Path: "/docs/:slug"},
				{Method: "ALL", Path: "/blog/:year/:month/:rest"},
			},
		},
		{
			name: "only static routes",
			manifestContent: `{
				"staticRoutes": [
					{"page": "/"},
					{"page": "/login"},
					{"page": "/signup"}
				],
				"dynamicRoutes": []
			}`,
			expectedRoutes: []RoutePattern{
				{Method: "ALL", Path: "/"},
				{Method: "ALL", Path: "/login"},
				{Method: "ALL", Path: "/signup"},
			},
		},
		{
			name: "only dynamic routes",
			manifestContent: `{
				"staticRoutes": [],
				"dynamicRoutes": [
					{"page": "/products/[id]"},
					{"page": "/categories/[slug]/items/[itemId]"}
				]
			}`,
			expectedRoutes: []RoutePattern{
				{Method: "ALL", Path: "/products/:id"},
				{Method: "ALL", Path: "/categories/:slug/items/:itemId"},
			},
		},
		{
			name: "empty manifest",
			manifestContent: `{
				"staticRoutes": [],
				"dynamicRoutes": []
			}`,
			expectedRoutes: []RoutePattern{},
		},
		{
			name: "nested dynamic routes",
			manifestContent: `{
				"staticRoutes": [],
				"dynamicRoutes": [
					{"page": "/users/[userId]/posts/[postId]/comments/[commentId]"}
				]
			}`,
			expectedRoutes: []RoutePattern{
				{Method: "ALL", Path: "/users/:userId/posts/:postId/comments/:commentId"},
			},
		},
		{
			name: "mixed parameter types",
			manifestContent: `{
				"staticRoutes": [],
				"dynamicRoutes": [
					{"page": "/api/[version]/users/[userId]"},
					{"page": "/files/[...path]"}
				]
			}`,
			expectedRoutes: []RoutePattern{
				{Method: "ALL", Path: "/api/:version/users/:userId"},
				{Method: "ALL", Path: "/files/:path"},
			},
		},
		{
			name: "complex paths",
			manifestContent: `{
				"staticRoutes": [
					{"page": "/api/auth/signin"},
					{"page": "/api/auth/signout"}
				],
				"dynamicRoutes": [
					{"page": "/api/users/[userId]/profile"},
					{"page": "/api/posts/[postId]/comments/[commentId]"},
					{"page": "/blog/[year]/[month]/[day]/[slug]"},
					{"page": "/docs/[...slug]"}
				]
			}`,
			expectedRoutes: []RoutePattern{
				{Method: "ALL", Path: "/api/auth/signin"},
				{Method: "ALL", Path: "/api/auth/signout"},
				{Method: "ALL", Path: "/api/users/:userId/profile"},
				{Method: "ALL", Path: "/api/posts/:postId/comments/:commentId"},
				{Method: "ALL", Path: "/blog/:year/:month/:day/:slug"},
				{Method: "ALL", Path: "/docs/:slug"},
			},
		},
		{
			name:            "manifest not found",
			manifestContent: `{"staticRoutes": [], "dynamicRoutes": []}`,
			skipManifest:    true,
			expectedRoutes:  []RoutePattern{},
		},
		{
			name:            "invalid JSON",
			manifestContent: `{ "staticRoutes": [ invalid json `,
			shouldError:     true,
			errorContains:   "decode next.js routes-manifest",
		},
		{
			name:            "file permission error",
			manifestContent: `{"staticRoutes": [], "dynamicRoutes": []}`,
			shouldError:     true,
			removeReadPerm:  true,
			errorContains:   "open next.js routes-manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory structure
			tempDir := t.TempDir()
			nextDir := filepath.Join(tempDir, ".next")
			require.NoError(t, os.MkdirAll(nextDir, 0o755))

			// Write manifest file
			manifestPath := filepath.Join(nextDir, "routes-manifest.json")
			if !tt.skipManifest {
				require.NoError(t, os.WriteFile(manifestPath, []byte(tt.manifestContent), 0o644))
			}

			// Remove read permissions if testing permission error
			if tt.removeReadPerm {
				require.NoError(t, os.Chmod(manifestPath, 0o000))
				// Restore permissions after test
				defer func() {
					_ = os.Chmod(manifestPath, 0o644)
				}()
			}

			// Create extractor and run the method
			extractor := NewRouteExtractor()
			err := extractor.extractNextJSRoutesFromManifest(tempDir)

			if tt.shouldError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			routes := extractor.GetRoutes()

			// Verify the number of routes
			assert.Len(t, routes, len(tt.expectedRoutes), "should have expected number of routes")

			// Check each expected route
			for _, expected := range tt.expectedRoutes {
				found := false
				for _, actual := range routes {
					if actual.Method == expected.Method && actual.Path == expected.Path {
						found = true
						assert.Equal(t, manifestPath, actual.File, "file should be manifest path")
						assert.Equal(t, 0, actual.Line, "line should be 0 for manifest routes")
						break
					}
				}
				assert.True(t, found, "should find route %s %s", expected.Method, expected.Path)
			}
		})
	}
}
