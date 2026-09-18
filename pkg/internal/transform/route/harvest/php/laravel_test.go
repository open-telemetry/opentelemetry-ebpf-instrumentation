// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractLaravelRoutes(t *testing.T) {
	root := t.TempDir()
	file := phpFile{
		path: filepath.Join(root, "routes", "api.php"),
		tokens: lexPHP([]byte(`
            use Illuminate\Support\Facades\Route;
            Route::get('/users', fn () => null);
        `)),
	}
	routes := newRouteSet()

	extractLaravelRoutes(file, root, laravelAPIPrefix{value: "api"}, routes)

	assert.Equal(t, routeSet{"/api/users": {}}, routes)
}

func TestExtractLaravelRoutesDecodesDoubleQuotedEscapes(t *testing.T) {
	root := t.TempDir()
	file := phpFile{
		path: filepath.Join(root, "routes", "web.php"),
		tokens: lexPHP([]byte(`
            use Illuminate\Support\Facades\Route;
            Route::get("\x2Fusers", fn () => null);
        `)),
	}
	routes := newRouteSet()

	extractLaravelRoutes(file, root, laravelAPIPrefix{}, routes)

	assert.Equal(t, routeSet{"/users": {}}, routes)
}

func TestLaravelExtractorExtractsNestedGroups(t *testing.T) {
	tokens := lexPHP([]byte(`
        use Illuminate\Support\Facades\Route;
        Route::prefix('/v1')->group(function () {
            Route::group(['prefix' => '/admin'], function () {
                Route::get('/users', fn () => null);
            });
        });
    `))
	routes := newRouteSet()
	extractor := laravelExtractor{
		tokens:    tokens,
		receivers: laravelRouteReceivers(tokens),
		routes:    routes,
	}

	extractor.extract(0, len(tokens), "/api")

	assert.Equal(t, routeSet{"/api/v1/admin/users": {}}, routes)
}

func TestLaravelExtractorSkipsUnterminatedCalls(t *testing.T) {
	tokens := lexPHP([]byte(`Route::get('/broken'`))
	routes := newRouteSet()
	extractor := laravelExtractor{
		tokens:    tokens,
		receivers: map[string]struct{}{"Route": {}},
		routes:    routes,
	}

	extractor.extract(0, len(tokens), "")

	assert.Empty(t, routes)
}

func TestLaravelExtractorExtractCall(t *testing.T) {
	tests := []struct {
		name string
		code string
		want routeSet
	}{
		{
			name: "named URI",
			code: `Route::get(uri: '/users', action: fn () => null)`,
			want: routeSet{"/api/users": {}},
		},
		{
			name: "match URI follows methods",
			code: `Route::match(['get', 'post'], '/events', fn () => null)`,
			want: routeSet{"/api/events": {}},
		},
		{
			name: "single resource",
			code: `Route::resource('users', UserController::class)->only('show')`,
			want: routeSet{"/api/users/{users}": {}},
		},
		{
			name: "batch resource",
			code: `Route::apiResources(['users' => UserController::class], ['only' => ['index']])`,
			want: routeSet{"/api/users": {}},
		},
		{name: "dynamic URI", code: `Route::get($uri, fn () => null)`, want: routeSet{}},
		{name: "unsupported call", code: `Route::fallback(fn () => null)`, want: routeSet{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tokens, calls := parseLaravelCallChain(t, test.code)
			routes := newRouteSet()
			extractor := laravelExtractor{tokens: tokens, routes: routes}

			extractor.extractCall("/api", calls)

			assert.Equal(t, test.want, routes)
		})
	}
}

func TestLaravelExtractorRouteChain(t *testing.T) {
	tokens := lexPHP([]byte(`Route::resource('users', UserController::class)->only('show')->shallow()`))
	receivers := map[string]struct{}{"Route": {}}
	name, openingParenthesis, ok := laravelRouteCall(tokens, 0, receivers)
	require.True(t, ok)

	calls := (laravelExtractor{tokens: tokens}).routeChain(name, openingParenthesis, len(tokens))

	require.Len(t, calls, 3)
	assert.Equal(t, []string{"resource", "only", "shallow"}, []string{calls[0].name, calls[1].name, calls[2].name})
	assert.Equal(t, "users", calls[0].arguments[0][0].value)
	assert.Equal(t, "show", calls[1].arguments[0][0].value)
	assert.Equal(t, len(tokens)-1, calls[2].close)

	unterminated := lexPHP([]byte(`Route::get('/users'`))
	assert.Nil(t, (laravelExtractor{tokens: unterminated}).routeChain("get", 3, len(unterminated)))
	assert.Nil(t, (laravelExtractor{tokens: tokens}).routeChain(name, openingParenthesis, openingParenthesis+1))

	brokenChain := lexPHP([]byte(`Route::get('/users')->middleware(`))
	brokenCalls := (laravelExtractor{tokens: brokenChain}).routeChain("get", 3, len(brokenChain))
	require.Len(t, brokenCalls, 1)
	assert.Equal(t, "get", brokenCalls[0].name)
}

func TestLaravelExtractorRouteChainSkipsDocCommentsBetweenCalls(t *testing.T) {
	tokens, calls := parseLaravelCallChain(t, `Route::prefix('api')
        /** admin routes */
        ->group(function () {})`)

	require.Len(t, calls, 2)
	assert.Equal(t, []string{"prefix", "group"}, []string{calls[0].name, calls[1].name})
	assert.Equal(t, len(tokens)-1, calls[1].close)
}

func TestLaravelGroup(t *testing.T) {
	_, calls := parseLaravelCallChain(t, `Route::prefix('/v1')->prefix('admin')->group(function () {})`)

	group, prefix, ok := laravelGroup(calls)

	assert.True(t, ok)
	assert.Equal(t, "group", group.name)
	assert.Equal(t, "/v1/admin", prefix)

	_, arrayCalls := parseLaravelCallChain(t, `Route::group(['middleware' => 'auth', 'prefix' => '/api'], function () {})`)
	_, prefix, ok = laravelGroup(arrayCalls)
	assert.True(t, ok)
	assert.Equal(t, "/api", prefix)

	_, namedCalls := parseLaravelCallChain(t, `Route::prefix(prefix: '/v2')->group(function () {})`)
	_, prefix, ok = laravelGroup(namedCalls)
	assert.True(t, ok)
	assert.Equal(t, "/v2", prefix)

	_, routeCalls := parseLaravelCallChain(t, `Route::get('/users', fn () => null)`)
	_, prefix, ok = laravelGroup(routeCalls)
	assert.False(t, ok)
	assert.Empty(t, prefix)
}

func TestLaravelGroupAbortsOnUnresolvedPrefix(t *testing.T) {
	// A dynamic fluent prefix() must abort the group, not silently proceed
	// as if there were no prefix: recursing with an empty prefix would
	// record the group's nested routes under the wrong (unprefixed) path.
	_, dynamicFluent := parseLaravelCallChain(t, `Route::prefix($dynamic)->group(function () {})`)
	_, prefix, ok := laravelGroup(dynamicFluent)
	assert.False(t, ok)
	assert.Empty(t, prefix)

	// Same for a dynamic prefix inside the group's own attributes array.
	_, dynamicArray := parseLaravelCallChain(t, `Route::group(['prefix' => $dynamic], function () {})`)
	_, prefix, ok = laravelGroup(dynamicArray)
	assert.False(t, ok)
	assert.Empty(t, prefix)

	// A group with no prefix at all (e.g. middleware-only) must still work.
	_, noPrefix := parseLaravelCallChain(t, `Route::group(['middleware' => 'auth'], function () {})`)
	group, prefix, ok := laravelGroup(noPrefix)
	assert.True(t, ok)
	assert.Equal(t, "group", group.name)
	assert.Empty(t, prefix)
}

func TestLaravelGroupArrayPrefix(t *testing.T) {
	tests := []struct {
		name     string
		argument string
		want     string
		resolved bool
		present  bool
	}{
		{name: "positional attributes", argument: `['middleware' => 'auth', 'prefix' => '/api']`, want: "/api", resolved: true, present: true},
		{name: "named attributes", argument: `attributes: ['prefix' => '/admin']`, want: "/admin", resolved: true, present: true},
		{name: "not an array", argument: `$attributes`},
		{name: "missing prefix", argument: `['middleware' => 'auth']`},
		{name: "dynamic prefix", argument: `['prefix' => $prefix]`, present: true},
		{name: "concatenated prefix", argument: `['prefix' => '/api' . $version]`, present: true},
		{name: "array keys are case-sensitive", argument: `['PREFIX' => '/api']`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			arguments := callArguments(lexPHP([]byte("group("+test.argument+")")), 1)

			value, resolved, present := laravelGroupArrayPrefix(arguments)

			assert.Equal(t, test.want, value)
			assert.Equal(t, test.resolved, resolved)
			assert.Equal(t, test.present, present)
		})
	}

	value, resolved, present := laravelGroupArrayPrefix(nil)
	assert.Empty(t, value)
	assert.False(t, resolved)
	assert.False(t, present)
}

func TestCallbackBody(t *testing.T) {
	tokens, calls := parseLaravelCallChain(t, `Route::group(function () { if ($ready) { run(); } })`)
	require.Len(t, calls, 1)

	start, end := callbackBody(tokens, calls[0])

	require.GreaterOrEqual(t, start, 0)
	require.Greater(t, end, start)
	assert.Equal(t, "{", tokens[start].value)
	assert.Equal(t, "}", tokens[end].value)
	assert.Equal(t, calls[0].close-1, end)

	arrowTokens, arrowCalls := parseLaravelCallChain(t, `Route::group(fn () => loadRoutes())`)
	start, end = callbackBody(arrowTokens, arrowCalls[0])
	assert.Equal(t, -1, start)
	assert.Equal(t, -1, end)
}

func TestCallbackBodyIgnoresBracesInEarlierArguments(t *testing.T) {
	// The attributes array carries its own brace-delimited closure (as a
	// middleware value); the real routing callback is the last argument.
	tokens, calls := parseLaravelCallChain(t, `Route::group(['middleware' => function ($r, $next) { return $next($r); }], function () { doWork(); })`)
	require.Len(t, calls, 1)

	start, end := callbackBody(tokens, calls[0])

	require.GreaterOrEqual(t, start, 0)
	assert.Equal(t, "{", tokens[start].value)
	assert.Equal(t, "}", tokens[end].value)
	assert.Equal(t, calls[0].close-1, end)
	assert.True(t, containsToken(tokens[start:end+1], "doWork"))
	assert.False(t, containsToken(tokens[start:end+1], "$next"))
}

func containsToken(tokens []token, value string) bool {
	for _, tok := range tokens {
		if tok.value == value {
			return true
		}
	}
	return false
}

func TestLaravelFilePrefix(t *testing.T) {
	root := t.TempDir()

	prefix, harvest := laravelFilePrefix(filepath.Join(root, "routes", "api.php"), root, laravelAPIPrefix{value: "/api"})
	assert.True(t, harvest)
	assert.Equal(t, "/api", prefix)

	prefix, harvest = laravelFilePrefix(filepath.Join(root, "routes", "api.php"), root, laravelAPIPrefix{})
	assert.True(t, harvest)
	assert.Empty(t, prefix)

	prefix, harvest = laravelFilePrefix(filepath.Join(root, "routes", "web.php"), root, laravelAPIPrefix{unresolved: true})
	assert.True(t, harvest)
	assert.Empty(t, prefix)

	prefix, harvest = laravelFilePrefix(filepath.Join(root, "routes", "api.php"), root, laravelAPIPrefix{unresolved: true})
	assert.False(t, harvest)
	assert.Empty(t, prefix)

	prefix, harvest = laravelFilePrefix(filepath.Join(filepath.Dir(root), "routes", "api.php"), root, laravelAPIPrefix{value: "/api"})
	assert.True(t, harvest)
	assert.Empty(t, prefix)
}

func TestLaravelRouteReceivers(t *testing.T) {
	tokens := lexPHP([]byte(`
        use Illuminate\Support\Facades\Route;
        use \Illuminate\Support\Facades\Route as Router;
        use App\Route as DomainRoute;
    `))

	receivers := laravelRouteReceivers(tokens)

	assert.Contains(t, receivers, "Route")
	assert.Contains(t, receivers, "Router")
	assert.Contains(t, receivers, `Illuminate\Support\Facades\Route`)
	assert.Contains(t, receivers, `\Illuminate\Support\Facades\Route`)
	assert.NotContains(t, receivers, "DomainRoute")
}

func TestLaravelRouteCallUsesPHPCaseInsensitiveNames(t *testing.T) {
	tokens := lexPHP([]byte(`
        use Illuminate\Support\Facades\Route as Router;
        router::GET('/users');
    `))
	receivers := laravelRouteReceivers(tokens)

	var method string
	var openingParenthesis int
	var found bool
	for pos := 0; pos+3 < len(tokens); pos++ {
		method, openingParenthesis, found = laravelRouteCall(tokens, pos, receivers)
		if found {
			break
		}
	}

	require.True(t, found)
	assert.Equal(t, "GET", method)
	assert.Equal(t, "(", tokens[openingParenthesis].value)

	for _, code := range []string{
		`Other::get('/users')`,
		`Route->get('/users')`,
		`Route::get`,
	} {
		invalidTokens := lexPHP([]byte(code))
		_, _, ok := laravelRouteCall(invalidTokens, 0, map[string]struct{}{"Route": {}})
		assert.False(t, ok, code)
	}
}

func TestIsLaravelRouteFacade(t *testing.T) {
	for _, name := range []string{
		`Illuminate\Support\Facades\Route`,
		`\Illuminate\Support\Facades\Route`,
		`\illuminate\support\facades\ROUTE`,
	} {
		assert.True(t, isLaravelRouteFacade(name), name)
	}

	assert.False(t, isLaravelRouteFacade(`App\Routing\Route`))
	assert.False(t, isLaravelRouteFacade("Route"))
}

func TestEqualName(t *testing.T) {
	assert.True(t, equalName(token{kind: tokenName, value: "RoUtE"}, "route"))
	assert.False(t, equalName(token{kind: tokenString, value: "route"}, "route"))
	assert.False(t, equalName(token{kind: tokenName, value: "Router"}, "route"))
}

func parseLaravelCallChain(t *testing.T, code string) ([]token, []laravelCall) {
	t.Helper()

	tokens := lexPHP([]byte(code))
	extractor := laravelExtractor{tokens: tokens}
	receivers := map[string]struct{}{"Route": {}}
	for pos := range tokens {
		name, openingParenthesis, ok := laravelRouteCall(tokens, pos, receivers)
		if ok {
			return tokens, extractor.routeChain(name, openingParenthesis, len(tokens))
		}
	}

	require.FailNow(t, "Laravel route call not found", code)
	return nil, nil
}
