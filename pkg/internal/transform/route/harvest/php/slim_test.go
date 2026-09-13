// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSlimRoutes(t *testing.T) {
	tokens := lexPHP([]byte(`
		use Slim\Factory\AppFactory;
		use Slim\Routing\RouteCollectorProxy;
		$app = AppFactory::create();
		$app->setBasePath('/service');
		$app->get('/users', callable: UserHandler::class);
		$app->redirect('/old-users', '/users');
		$app->group('/api',
			fn (RouteCollectorProxy $group) => $group->get('/status', StatusHandler::class)
		);
	`))
	routes := newRouteSet()

	extractSlimRoutes(tokens, routes)

	assert.Equal(t, routeSet{
		"/service/api/status": {},
		"/service/users":      {},
		"/service/old-users":  {},
	}, routes)
}

func TestExtractSlimRoutesFindsRouteDocumentedWithADocComment(t *testing.T) {
	tokens := lexPHP([]byte(`
		use Slim\Factory\AppFactory;
		$app = AppFactory::create();
		$app
			/** List all users */
			->get('/users', UserHandler::class);
	`))
	routes := newRouteSet()

	extractSlimRoutes(tokens, routes)

	assert.Equal(t, routeSet{"/users": {}}, routes)
}

func TestSlimExtractorExtract(t *testing.T) {
	tokens := lexPHP([]byte(`
		$app->any('/any', AnyHandler::class);
		$app->delete('/delete', DeleteHandler::class);
		$app->get(pattern: '/get', callable: GetHandler::class);
		$app->map(methods: ['POST'], pattern: '/mapped', callable: MapHandler::class);
		$app->options('/options', OptionsHandler::class);
		$app->patch('/patch', PatchHandler::class);
		$app->post('/post', PostHandler::class);
		$app->put('/put', PutHandler::class);
		$app->redirect(from: '/old', to: '/get');
		$app->post($dynamic, DynamicHandler::class);
		$app->run();
	`))
	routes := newRouteSet()
	extractor := slimExtractor{tokens: tokens, routes: routes}

	extractor.extract(0, len(tokens), map[string]struct{}{"$app": {}}, "", false)

	assert.Equal(t, routeSet{
		"/any":     {},
		"/delete":  {},
		"/get":     {},
		"/mapped":  {},
		"/options": {},
		"/patch":   {},
		"/post":    {},
		"/put":     {},
		"/old":     {},
	}, routes)
}

func TestSlimRoutePath(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
		ok   bool
	}{
		{name: "route", code: `$app->get('/users', UserHandler::class)`, want: "/users", ok: true},
		{name: "named map pattern", code: `$app->map(methods: ['GET'], pattern: '/mapped', callable: Handler::class)`, want: "/mapped", ok: true},
		{name: "named redirect source", code: `$app->redirect(from: '/old', to: '/new')`, want: "/old", ok: true},
		{name: "dynamic pattern", code: `$app->get($pattern, Handler::class)`},
		{name: "not a route", code: `$app->run()`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, call := parseSlimCall(t, test.code, map[string]struct{}{"$app": {}})

			path, ok := slimRoutePath(call)

			assert.Equal(t, test.want, path)
			assert.Equal(t, test.ok, ok)
		})
	}
}

func TestSlimExtractorExtractGroup(t *testing.T) {
	tokens, call := parseSlimCall(t, `
		$app->group(
			pattern: '/api',
			callable: function (RouteCollectorProxy $group) {
				$group->get('/users', UserHandler::class);
			},
		)
	`, map[string]struct{}{"$app": {}})
	routes := newRouteSet()
	extractor := slimExtractor{tokens: tokens, routes: routes}

	extractor.extractGroup(call, map[string]struct{}{"$app": {}}, "/service")

	assert.Equal(t, routeSet{"/service/api/users": {}}, routes)

	v3Tokens, v3Call := parseSlimCall(t, `$app->group('/v3', function () {
		$this->get('/things', ThingHandler::class);
	})`, map[string]struct{}{"$app": {}})
	v3Routes := newRouteSet()
	(slimExtractor{tokens: v3Tokens, routes: v3Routes}).extractGroup(v3Call, map[string]struct{}{"$app": {}}, "")
	assert.Equal(t, routeSet{"/v3/things": {}}, v3Routes)

	optionalTokens, optionalCall := parseSlimCall(t, `$app->group('/api', function ($group, $optional = null) {
		$group->get('/users', UserHandler::class);
		$optional->get('/not-a-route', UserHandler::class);
	})`, map[string]struct{}{"$app": {}})
	optionalRoutes := newRouteSet()
	(slimExtractor{tokens: optionalTokens, routes: optionalRoutes}).extractGroup(optionalCall, map[string]struct{}{"$app": {}}, "")
	assert.Equal(t, routeSet{"/api/users": {}}, optionalRoutes)

	arrowTokens, arrowCall := parseSlimCall(t, `$app->group('/api',
		fn (RouteCollectorProxy $group) => $group->get('/status', StatusHandler::class)
	)`, map[string]struct{}{"$app": {}})
	arrowRoutes := newRouteSet()
	(slimExtractor{tokens: arrowTokens, routes: arrowRoutes}).extractGroup(arrowCall, map[string]struct{}{"$app": {}}, "")
	assert.Equal(t, routeSet{"/api/status": {}}, arrowRoutes)

	for _, code := range []string{
		`$app->group($prefix, function ($group) { $group->get('/users', UserHandler::class); })`,
		`$app->group('/api', Routes::class)`,
	} {
		invalidTokens, invalidCall := parseSlimCall(t, code, map[string]struct{}{"$app": {}})
		invalidRoutes := newRouteSet()
		(slimExtractor{tokens: invalidTokens, routes: invalidRoutes}).extractGroup(invalidCall, map[string]struct{}{"$app": {}}, "")
		assert.Empty(t, invalidRoutes, code)
	}
}

func TestSlimRouteCall(t *testing.T) {
	variables := map[string]struct{}{"$app": {}}
	tokens := lexPHP([]byte(`$app->GET('/users', UserHandler::class)`))

	call, ok := slimRouteCall(tokens, 0, len(tokens), variables, false)

	require.True(t, ok)
	assert.Equal(t, "GET", call.name)
	assert.Equal(t, "/users", call.arguments[0][0].value)
	assert.Equal(t, "(", tokens[call.open].value)
	assert.Equal(t, ")", tokens[call.close].value)

	thisTokens := lexPHP([]byte(`$this->post('/users', UserHandler::class)`))
	_, ok = slimRouteCall(thisTokens, 0, len(thisTokens), variables, true)
	assert.True(t, ok)
	_, ok = slimRouteCall(thisTokens, 0, len(thisTokens), variables, false)
	assert.False(t, ok)

	for _, code := range []string{
		`$other->get('/users', UserHandler::class)`,
		`$app::get('/users', UserHandler::class)`,
		`$app->('/users', UserHandler::class)`,
		`$app->get`,
		`$app->get('/users'`,
	} {
		invalidTokens := lexPHP([]byte(code))
		_, ok = slimRouteCall(invalidTokens, 0, len(invalidTokens), variables, false)
		assert.False(t, ok, code)
	}

	assert.NotPanics(t, func() {
		_, ok = slimRouteCall(nil, 0, 0, variables, false)
	})
	assert.False(t, ok)
}

func TestSlimRouteCallSkipsDocCommentsBeforeArrow(t *testing.T) {
	tokens := lexPHP([]byte(`$app
		/** Get all users */
		->get('/users', UserHandler::class)`))
	variables := map[string]struct{}{"$app": {}}

	call, ok := slimRouteCall(tokens, 0, len(tokens), variables, false)

	require.True(t, ok)
	assert.Equal(t, "get", call.name)
	assert.Equal(t, "/users", call.arguments[0][0].value)
}

func TestSlimCallbackBody(t *testing.T) {
	tokens, call := parseSlimCall(t, `$app->group('/api', function ($group) {
		if ($enabled) { $group->get('/users', UserHandler::class); }
	})`, map[string]struct{}{"$app": {}})

	start, end := slimCallbackBody(tokens, call)

	require.GreaterOrEqual(t, start, 0)
	require.Greater(t, end, start)
	assert.Equal(t, "{", tokens[start].value)
	assert.Equal(t, "}", tokens[end].value)
	assert.Equal(t, call.close-1, end)

	arrowTokens, arrowCall := parseSlimCall(t, `$app->group('/api', fn ($group) => register($group))`, map[string]struct{}{"$app": {}})
	start, end = slimCallbackBody(arrowTokens, arrowCall)
	assert.Equal(t, "=>", arrowTokens[start].value)
	assert.Equal(t, arrowCall.close, end)

	typedTokens, typedCall := parseSlimCall(t, `$app->group('/api', function (): void {})`, map[string]struct{}{"$app": {}})
	start, end = slimCallbackBody(typedTokens, typedCall)
	assert.Equal(t, "{", typedTokens[start].value)
	assert.Equal(t, "}", typedTokens[end].value)

	for _, test := range []struct {
		name   string
		code   string
		closer func([]token) int
	}{
		{name: "parameters reach call end", code: `function ()`, closer: func(tokens []token) int { return len(tokens) - 1 }},
		{name: "arrow without expression marker", code: `fn ($group) null`, closer: func(tokens []token) int { return len(tokens) }},
		{name: "closure without body", code: `function () null`, closer: func(tokens []token) int { return len(tokens) }},
		{name: "unclosed body", code: `function () {`, closer: func(tokens []token) int { return len(tokens) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			tokens := lexPHP([]byte(test.code))
			start, end := slimCallbackBody(tokens, slimCall{open: -1, close: test.closer(tokens)})
			assert.Equal(t, -1, start)
			assert.Equal(t, -1, end)
		})
	}
}

func TestSlimCallbackVariable(t *testing.T) {
	tokens, call := parseSlimCall(t, `$app->group('/api', static function (
		RouteCollectorProxy $group,
		?Service $optional = null,
	) {})`, map[string]struct{}{"$app": {}})
	start, _ := slimCallbackBody(tokens, call)

	variable, ok := slimCallbackVariable(tokens, call.open, start)
	assert.True(t, ok)
	assert.Equal(t, "$group", variable)

	arrow := lexPHP([]byte(`fn ($group) => null`))
	variable, ok = slimCallbackVariable(arrow, 0, len(arrow))
	assert.True(t, ok)
	assert.Equal(t, "$group", variable)

	for _, code := range []string{`function named($group) {}`, `function (`} {
		tokens := lexPHP([]byte(code))
		variable, ok = slimCallbackVariable(tokens, 0, len(tokens))
		assert.False(t, ok, code)
		assert.Empty(t, variable, code)
	}
}

func TestSlimCallbackDeclaration(t *testing.T) {
	closure := lexPHP([]byte(`function ($group) {}`))
	assert.Equal(t, 0, slimCallbackDeclaration(closure, 0, len(closure)))

	arrow := lexPHP([]byte(`fn ($group) => null`))
	assert.Equal(t, 0, slimCallbackDeclaration(arrow, 0, len(arrow)))

	nested := lexPHP([]byte(`function ($group) { fn () => null; }`))
	assert.Equal(t, 0, slimCallbackDeclaration(nested, 0, len(nested)))
	assert.Equal(t, -1, slimCallbackDeclaration(nested, len(nested), len(nested)))
}

func TestSlimBasePath(t *testing.T) {
	variables := map[string]struct{}{"$app": {}}
	tests := []struct {
		name string
		code string
		want string
	}{
		{
			name: "last static base path",
			code: `$app->setBasePath('/old');
				$other->setBasePath('/ignored');
				$app->setBasePath(basePath: '/service');`,
			want: "/service",
		},
		{
			name: "dynamic override removes stale prefix",
			code: `$app->setBasePath('/old');
				$app->setBasePath($configuredBasePath);`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tokens := lexPHP([]byte(test.code))

			assert.Equal(t, test.want, slimBasePath(tokens, variables))
		})
	}
}

func TestSlimVariablesUsesPHPCaseInsensitiveClassNames(t *testing.T) {
	tokens := lexPHP([]byte(`
		use Slim\App as WebApp;
		use slim\Factory\AppFactory as Factory;
		use Slim\Routing\RouteCollectorProxy as GroupRouter;

		function register(WEBAPP $typedApp, GROUPROUTER $group) {}
		$constructed = new webapp();
		$factoryApp = FACTORY::CREATE();
		$other = new OtherApp();
	`))
	aliases := slimClassAliases(tokens)

	variables := slimVariables(tokens, aliases)

	assert.Equal(t, map[string]struct{}{
		"$typedApp":    {},
		"$group":       {},
		"$constructed": {},
		"$factoryApp":  {},
	}, variables)
}

func TestSlimClassAliases(t *testing.T) {
	tokens := lexPHP([]byte(`
		use Slim\App;
		use \Slim\Factory\AppFactory as Factory;
		use App\Routing\Router as ApplicationRouter;
	`))

	aliases := slimClassAliases(tokens)

	assert.Equal(t, map[string]string{
		"App":     `Slim\App`,
		"Factory": `Slim\Factory\AppFactory`,
	}, aliases)
}

func TestIsSlimRouterType(t *testing.T) {
	aliases := map[string]string{
		"Application": "Slim\\App",
		"Group":       "Slim\\Routing\\RouteCollectorProxy",
	}

	for _, name := range []string{"Application", "application", "\\Slim\\App", "Group", "group"} {
		assert.True(t, isSlimRouterType(name, aliases), name)
	}
	assert.False(t, isSlimRouterType("Router", aliases))
}

func TestIsSlimApp(t *testing.T) {
	aliases := map[string]string{"Application": "Slim\\App"}

	for _, name := range []string{"Application", "application", "Slim\\App", "\\SLIM\\APP"} {
		assert.True(t, isSlimApp(name, aliases), name)
	}
	assert.False(t, isSlimApp("App", nil))
}

func TestIsSlimAppFactory(t *testing.T) {
	aliases := map[string]string{"Factory": "Slim\\Factory\\AppFactory"}

	for _, name := range []string{"Factory", "factory", "Slim\\Factory\\AppFactory", "\\SLIM\\FACTORY\\APPFACTORY"} {
		assert.True(t, isSlimAppFactory(name, aliases), name)
	}
	assert.False(t, isSlimAppFactory("AppFactory", nil))
}

func TestSlimClass(t *testing.T) {
	aliases := map[string]string{"Application": "Slim\\App"}

	assert.Equal(t, "Slim\\App", slimClass("application", aliases))
	assert.Equal(t, "Slim\\App", slimClass("\\Slim\\App", aliases))
	assert.Equal(t, "App\\Domain\\Application", slimClass("\\App\\Domain\\Application", aliases))
}

func TestNextNamedToken(t *testing.T) {
	tokens := lexPHP([]byte(`before FUNCTION () {} after`))

	assert.Equal(t, 1, nextNamedToken(tokens, 0, len(tokens), "function"))
	assert.Equal(t, -1, nextNamedToken(tokens, 2, len(tokens), "function"))
	assert.Equal(t, -1, nextNamedToken(tokens, 0, 1, "function"))
}

func parseSlimCall(t *testing.T, code string, variables map[string]struct{}) ([]token, slimCall) {
	t.Helper()

	tokens := lexPHP([]byte(code))
	for pos := range tokens {
		call, ok := slimRouteCall(tokens, pos, len(tokens), variables, false)
		if ok {
			return tokens, call
		}
	}

	require.FailNow(t, "Slim call not found", code)
	return nil, slimCall{}
}
