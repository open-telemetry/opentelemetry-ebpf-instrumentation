// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSymfonyRoutes(t *testing.T) {
	tokens := lexPHP([]byte(`
        #[Route('/api')]
        final class Controller {
            #[Route(path: '/users/{id}')]
            public function show() {}
        }

        return function (RoutingConfigurator $routes): void {
            $routes->add('health', '/health');
        };
    `))
	routes := newRouteSet()

	attributes := extractSymfonyRoutes(tokens, routes)

	assert.Equal(t, []string{"/api/users/{id}"}, attributes)
	assert.Equal(t, routeSet{"/health": {}}, routes)
}

func TestExtractSymfonyAttributes(t *testing.T) {
	tokens := lexPHP([]byte(`
        #[Route('/v1'), Route('/v2')]
        class Controller {
            #[Route('/users')]
            #[Route(path: '/members')]
            public function index() {
                #[Route('/nested')]
                function nested() {}
            }

            #[Other('/ignored')]
            public function ignored() {}
        }

        #[Route('/health')]
        function health() {}
    `))
	routes := newRouteSet()

	extractSymfonyAttributes(tokens, routes)

	assert.Equal(t, routeSet{
		"/v1/users":   {},
		"/v1/members": {},
		"/v2/users":   {},
		"/v2/members": {},
		"/health":     {},
	}, routes)
}

func TestIsPHPDeclaration(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		position int
		want     bool
	}{
		{name: "first token", code: "class Example {}", want: true},
		{name: "case insensitive", code: "final CLASS Example {}", position: 1, want: true},
		{name: "class constant", code: "Example::class", position: 2},
		{name: "different name", code: "function example() {}"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isPHPDeclaration(lexPHP([]byte(test.code)), test.position, "class"))
		})
	}
}

func TestExtractSymfonyMethods(t *testing.T) {
	tokens := lexPHP([]byte(`{
        #[Route('/users')]
        public function users() {
            #[Route('/nested')]
            function nested() {}
        }
        #[Route('/status')]
        public function status();
    }`))
	end := matchingClosingToken(tokens, 0, "{", "}")
	require.Positive(t, end)
	routes := newRouteSet()

	extractSymfonyMethods(tokens, 1, end, []string{"/api"}, routes)

	assert.Equal(t, routeSet{
		"/api/users":  {},
		"/api/status": {},
	}, routes)
}

func TestExtractSymfonyMethodsIgnoresStringLiteralsThatLookLikeBraces(t *testing.T) {
	tokens := lexPHP([]byte(`{
        public function broken() {
            return '{';
        }
        #[Route('/after')]
        public function after() {}
    }`))
	end := matchingClosingToken(tokens, 0, "{", "}")
	require.Positive(t, end)
	routes := newRouteSet()

	extractSymfonyMethods(tokens, 1, end, nil, routes)

	assert.Equal(t, routeSet{"/after": {}}, routes)
}

func TestSymfonyAttributePaths(t *testing.T) {
	t.Run("collects route attributes", func(t *testing.T) {
		tokens := lexPHP([]byte(`#[Other('ignored'), Route('/users'), \Symfony\Component\Routing\Attribute\Route(path: '/members', methods: ['GET'])] function index() {}`))

		paths, end := symfonyAttributePaths(tokens, 0)

		assert.Equal(t, []string{"/users", "/members"}, paths)
		assert.Equal(t, 23, end)
	})

	t.Run("rejects unterminated attribute", func(t *testing.T) {
		tokens := lexPHP([]byte(`#[Route('/users')`))

		paths, end := symfonyAttributePaths(tokens, 0)

		assert.Nil(t, paths)
		assert.Zero(t, end)
	})
}

func TestMatchingAttributeEnd(t *testing.T) {
	tokens := lexPHP([]byte(`#[Route('/users', methods: ['GET'])]`))

	assert.Equal(t, len(tokens)-1, matchingAttributeEnd(tokens, 0))
	assert.Equal(t, -1, matchingAttributeEnd(tokens, 1))
	assert.Equal(t, -1, matchingAttributeEnd(tokens, -1))
	assert.Equal(t, -1, matchingAttributeEnd(tokens, len(tokens)))
	assert.Equal(t, -1, matchingAttributeEnd(lexPHP([]byte(`#[Route('/users')`)), 0))
}

func TestMatchingAttributeEndIgnoresStringLiteralsThatLookLikeBrackets(t *testing.T) {
	tokens := lexPHP([]byte(`#[Route('[', requirements: ['id' => '\d+'])] function show() {}`))

	assert.Equal(t, 13, matchingAttributeEnd(tokens, 0))
}

func TestSymfonyRouteAttributePath(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
		ok   bool
	}{
		{name: "positional", code: `Route('/users')`, want: "/users", ok: true},
		{name: "named", code: `Route(name: 'users', path: '/users')`, want: "/users", ok: true},
		{name: "qualified and case insensitive", code: `\Symfony\Component\Routing\Attribute\ROUTE('/users')`, want: "/users", ok: true},
		{name: "unrelated attribute", code: `Other('/users')`},
		{name: "missing call", code: `Route`},
		{name: "wrong delimiter", code: `Route['/users']`},
		{name: "dynamic positional", code: `Route($path)`},
		{name: "dynamic named", code: `Route(path: $path)`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, ok := symfonyRouteAttributePath(lexPHP([]byte(test.code)))

			assert.Equal(t, test.want, path)
			assert.Equal(t, test.ok, ok)
		})
	}
}

func TestAddSymfonyPaths(t *testing.T) {
	t.Run("adds paths without prefixes", func(t *testing.T) {
		routes := newRouteSet()

		addSymfonyPaths(routes, nil, []string{"/users", "/status"})

		assert.Equal(t, routeSet{"/users": {}, "/status": {}}, routes)
	})

	t.Run("joins every prefix and path", func(t *testing.T) {
		routes := newRouteSet()

		addSymfonyPaths(routes, []string{"/v1", "/v2"}, []string{"/users", "/status"})

		assert.Equal(t, routeSet{
			"/v1/users":  {},
			"/v1/status": {},
			"/v2/users":  {},
			"/v2/status": {},
		}, routes)
	})
}

func TestShortPHPName(t *testing.T) {
	tests := map[string]string{
		"Route": "Route",
		`Symfony\Component\Routing\Attribute\Route`: "Route",
		`\App\Route\`: "Route",
		`\\`:          "",
	}

	for name, want := range tests {
		assert.Equal(t, want, shortPHPName(name))
	}
}

func TestNextTokenValueIndex(t *testing.T) {
	tokens := lexPHP([]byte(`class Example { function run() {} }`))

	assert.Equal(t, 2, nextTokenValueIndex(tokens, 0, "{"))
	assert.Equal(t, 7, nextTokenValueIndex(tokens, 3, "{"))
	assert.Equal(t, -1, nextTokenValueIndex(tokens, 0, "missing"))
	assert.Equal(t, -1, nextTokenValueIndex(tokens, len(tokens), "{"))
	assert.Equal(t, -1, nextTokenValueIndex(tokens, -1, "{"))
}
