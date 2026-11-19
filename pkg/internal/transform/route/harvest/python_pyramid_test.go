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
	} {
		assert.Equal(t, []string{tc.route}, scanPyramid(tc.stmt), tc.stmt)
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
	} {
		assert.Empty(t, scanPyramid(stmt), stmt)
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
	} {
		route, ok := pyramidRoute(tc.pattern)
		assert.Equal(t, tc.ok, ok, tc.pattern)
		assert.Equal(t, tc.route, route, tc.pattern)
	}
}

func TestUsesPyramid(t *testing.T) {
	for _, stmt := range []string{
		`import pyramid`,
		`import pyramid.config`,
		`import pyramid as pyr`,
		`import os, pyramid`,
		`import os as o, pyramid.config`,
		`from pyramid.config import Configurator`,
		`from pyramid import config`,
		`from pyramid.view import (`,
	} {
		assert.True(t, usesPyramid(stmt), stmt)
	}

	for _, stmt := range []string{
		`import pyramid_tm`,
		`from pyramid_jinja2 import renderer_factory`,
		`from mypyramid import config`,
		`import os`,
		`# from pyramid.config import Configurator`,
		`x = "from pyramid.config import Configurator"`,
	} {
		assert.False(t, usesPyramid(stmt), stmt)
	}
}
