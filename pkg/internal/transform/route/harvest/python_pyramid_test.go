// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanPyramid(t *testing.T) {
	for _, tc := range []struct {
		stmt  string
		route string
	}{
		{stmt: `config.add_route("user", "/users/{user_id}")`, route: "/users/{user_id}"},
		{stmt: `config.add_route('user', '/users/{user_id}', request_method='GET')`, route: "/users/{user_id}"},
		{stmt: `config.add_route("order", pattern="/orders/{order_id}")`, route: "/orders/{order_id}"},
		{stmt: `config.add_route(pattern="/orders/{order_id}", name="order")`, route: "/orders/{order_id}"},
		{stmt: `config.add_route("code", r"/codes/{code:\d+}")`, route: "/codes/{code}"},
		{stmt: `config.add_route("item", "items/{item_id}")`, route: "/items/{item_id}"},
		{stmt: `config.add_route("static", "/static/*subpath")`, route: "/static/*"},
		{stmt: `config.add_route("home", "/")`, route: "/"},
		{stmt: `self.config.add_route( "user", "/users/{user_id}", )`, route: "/users/{user_id}"},
		{stmt: `config.add_route(name="user", pattern="/users/{user_id}")`, route: "/users/{user_id}"},
		{stmt: `config.add_route("user", factory=UserFactory(), pattern="/users/{user_id}")`, route: "/users/{user_id}"},
		{stmt: `config.add_route("u", "/users/{id}", request_method=("GET", "POST"))`, route: "/users/{id}"},
		{stmt: `config.add_route("a,b", "/ab/{id}")`, route: "/ab/{id}"},
		{stmt: `config.add_route("tag#1", "/tags/{tag}")`, route: "/tags/{tag}"},
		{stmt: `config.add_route("user", u"/users/{user_id}")`, route: "/users/{user_id}"},
		{stmt: `config.add_route("user", R'/users/{user_id:\d+}')`, route: "/users/{user_id}"},
		{stmt: `config.add_route("page", "/page/{action}", static=False)`, route: "/page/{action}"},
		{stmt: `config.add_route(name="user", pattern="/prefix/pattern='/fake',")`, route: "/prefix/pattern='/fake',"},
	} {
		routes := map[string]struct{}{}
		scanPyramid(tc.stmt, routes)
		assert.Equal(t, map[string]struct{}{tc.route: {}}, routes, tc.stmt)
	}
}

func TestScanPyramidSkipsUnsupportedForms(t *testing.T) {
	for _, stmt := range []string{
		`config.add_route("user", USER_PATTERN)`,
		`config.add_route("user", f"/users/{user_id}")`,
		`config.add_route("user", "/users/" + suffix)`,
		`config.add_route("user", "/users/" "{user_id}")`,
		`config.add_route(`,
		`config.add_view(user, route_name="user")`,
		`@view_config(route_name="user", renderer="json")`,
		`app.add_route("/users/{user_id}", UserResource())`,
		`config.add_route("user", make_pattern(pattern="/users/"))`,
		`config.add_route("health", "/health:ready")`,
		`config.add_route("user", "/<user_id>")`,
		`config.add_route("user", "/users/{user_id}", pattern="/other")`,
		`config.add_route("user", **ROUTE_KWARGS)`,
		`config.add_route(*ROUTE_ARGS)`,
		`config.add_route("user", b"/users/{user_id}")`,
		`config.add_route("user", pattern == "/users")`,
		`config.add_route("user")`,
		`config.add_route("page", "/page/{action}", static=True)`,
		`config.add_route("youtube", "https://youtube.com/watch/{video_id}")`,
		`config.add_route( "user",  # old pattern="/old", pattern=USER_PATTERN, )`,
	} {
		routes := map[string]struct{}{}
		scanPyramid(stmt, routes)
		assert.Empty(t, routes, stmt)
	}
}

func TestPyramidRoute(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		route   string
		ok      bool
	}{
		{pattern: "/users/{user_id}", route: "/users/{user_id}", ok: true},
		{pattern: "users/{user_id}", route: "/users/{user_id}", ok: true},
		{pattern: "", route: "/", ok: true},
		{pattern: `/users/{user_id:\d+}`, route: "/users/{user_id}", ok: true},
		{pattern: `/codes/{code:\d{3}}`, route: "/codes/{code}", ok: true},
		{pattern: "/static/*subpath", route: "/static/*", ok: true},
		{pattern: "/traverse/{id}/*traverse", route: "/traverse/{id}/*", ok: true},
		{pattern: "/static/*", route: "/static/*", ok: true},
		{pattern: "/files/{name}.{ext}", ok: false},
		{pattern: "/users/{1user}", ok: false},
		{pattern: "/users/{user_id", ok: false},
		{pattern: "/static/*subpath/more", ok: false},
		{pattern: "/static*subpath", ok: false},
		{pattern: `/codes/{code:\d{{3}}}`, ok: false},
		{pattern: `/users/{user_id:[a-z]+}`, route: "/users/{user_id}", ok: true},
		{pattern: `/users/{user_id:\w+}`, route: "/users/{user_id}", ok: true},
		{pattern: "/files/{path:.*}", ok: false},
		{pattern: "/files/{path:.+}", ok: false},
		{pattern: `/files/{path:\S+}`, ok: false},
		{pattern: `/files/{path:[^?]+}`, ok: false},
		{pattern: `/versions/{ver:\d+\.\d+}`, ok: false},
		{pattern: `/files/{path:[ -~]+}`, ok: false},
		{pattern: `/files/{path:[\w\x2f]+}`, ok: false},
		{pattern: `/files/{path:[\w/]+}`, ok: false},
		{pattern: `/users/{user_id:\d*}`, ok: false},
		{pattern: `/users/{user_id:(}`, ok: false},
		{pattern: "/users/{user_id}/profile.json", route: "/users/{user_id}/profile.json", ok: true},
		{pattern: "/users/@me", route: "/users/@me", ok: true},
		{pattern: "/v1/items;list/{id}", route: "/v1/items;list/{id}", ok: true},
		{pattern: "/café", ok: false},
		{pattern: "/a b", ok: false},
		{pattern: "/search?q", ok: false},

		// Examples from the Pyramid route pattern syntax docs:
		// https://docs.pylonsproject.org/projects/pyramid/en/latest/narr/urldispatch.html#route-pattern-syntax
		{pattern: "{foo}/bar/baz", route: "/{foo}/bar/baz", ok: true},
		{pattern: "foo/{baz}/{bar}", route: "/foo/{baz}/{bar}", ok: true},
		{pattern: "/{foo}/", route: "/{foo}/", ok: true},
		{pattern: "/{a}/{a_b}/{_b}/{b9}", route: "/{a}/{a_b}/{_b}/{b9}", ok: true},
		{pattern: "/{foo:[^/]+}", route: "/{foo}", ok: true},
		{pattern: "foo/*fizzle", route: "/foo/*", ok: true},
		{pattern: "a/b/c/*foo", route: "/a/b/c/*", ok: true},
		{pattern: `/{year:\d+}/{month:\d+}/{day:\d+}`, route: "/{year}/{month}/{day}", ok: true},
		{pattern: "/{0a}", ok: false},
		{pattern: "foo/{name}.html", ok: false},
		{pattern: "foo/{name}.{ext}", ok: false},
		{pattern: "/{foo}{bar}", ok: false},
		{pattern: "foo/{baz}/{bar}*fizzle", ok: false},
		{pattern: "foo/{baz}/{bar}{fizzle:.*}", ok: false},
		{pattern: "/Foo Bar/{baz}", ok: false},
		{pattern: "/La Peña/{x}", ok: false},
		{pattern: `/La Pe\xc3\xb1a/{x}`, ok: false},
		{pattern: "https://youtube.com/watch/{video_id}", ok: false},
		{pattern: "/{foo:a/b}", ok: false},
	} {
		route, ok := pyramidRoute(tc.pattern)
		assert.Equal(t, tc.ok, ok, tc.pattern)
		assert.Equal(t, tc.route, route, tc.pattern)
	}
}

func TestPyTopLevelArgs(t *testing.T) {
	args, ok := pyTopLevelArgs(`"a,b", f(x, y), k=[1, 2], d={"p": 1}, 'it\'s, #ok',`)
	assert.True(t, ok)
	assert.Equal(t, []string{`"a,b"`, `f(x, y)`, `k=[1, 2]`, `d={"p": 1}`, `'it\'s, #ok'`, ""}, args)

	_, ok = pyTopLevelArgs(`"user",  # old pattern="/old", pattern=USER_PATTERN,`)
	assert.False(t, ok)
}

func TestPyKeywordArg(t *testing.T) {
	key, value, ok := pyKeywordArg(`pattern = "/users"`)
	assert.True(t, ok)
	assert.Equal(t, "pattern", key)
	assert.Equal(t, `"/users"`, value)

	for _, arg := range []string{`"/users"`, `pattern == "/users"`, `f(pattern="/users")`} {
		_, _, ok := pyKeywordArg(arg)
		assert.False(t, ok, arg)
	}
}
