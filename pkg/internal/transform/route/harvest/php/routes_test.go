// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRouteSet(t *testing.T) {
	routes := newRouteSet()

	require.NotNil(t, routes)
	assert.Empty(t, routes)
}

func TestRouteSetAdd(t *testing.T) {
	t.Run("normalizes and deduplicates", func(t *testing.T) {
		routes := newRouteSet()

		routes.add(" users/ ")
		routes.add("/users")
		routes.add("   ")

		assert.Equal(t, routeSet{"/users": {}}, routes)
	})

	t.Run("enforces route limit", func(t *testing.T) {
		routes := newRouteSet()
		for index := range maxRoutes {
			routes[fmt.Sprintf("/route/%d", index)] = struct{}{}
		}

		routes.add("/overflow")

		assert.Len(t, routes, maxRoutes)
		assert.NotContains(t, routes, "/overflow")
	})
}

func TestRouteSetSorted(t *testing.T) {
	routes := routeSet{
		"/users/admin": {},
		"/users/{id}":  {},
		"/alphabet":    {},
		"/status":      {},
		"/health":      {},
		"/{id}":        {},
	}

	assert.Equal(t, []string{
		"/users/admin",
		"/users/{id}",
		"/alphabet",
		"/health",
		"/status",
		"/{id}",
	}, routes.sorted())
}

func TestNormalizeRoute(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty"},
		{name: "whitespace", value: " \t\n"},
		{name: "root", value: "/", want: "/"},
		{name: "slash only", value: "///", want: "/"},
		{name: "adds leading slash", value: "users", want: "/users"},
		{name: "trims surrounding whitespace and trailing slashes", value: "  /api/users///  ", want: "/api/users"},
		{name: "preserves internal repeated slash", value: "api//users", want: "/api//users"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, normalizeRoute(test.value))
		})
	}
}

func TestJoinRoutes(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
		want  string
	}{
		{name: "no parts", want: "/"},
		{name: "empty parts", parts: []string{"", "/"}, want: "/"},
		{name: "joins", parts: []string{"api", "users", "{id}"}, want: "/api/users/{id}"},
		{name: "trims boundary slashes", parts: []string{"/api/", "/users/"}, want: "/api/users"},
		{name: "ignores slash only parts", parts: []string{"api", "///", "users"}, want: "/api/users"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, joinRoutes(test.parts...))
		})
	}
}

func TestRouteSortPriority(t *testing.T) {
	tests := []struct {
		route string
		want  int
	}{
		{route: "", want: 0},
		{route: "/", want: 0},
		{route: "/api/users", want: 2},
		{route: "api/users/", want: 2},
		{route: "/api/{id}", want: 1},
		{route: "/api/:id", want: 1},
		{route: "/api/*", want: 1},
		{route: "/api/items/{id:[0-9]+}", want: 2},
	}

	for _, test := range tests {
		t.Run(test.route, func(t *testing.T) {
			assert.Equal(t, test.want, routeSortPriority(test.route))
		})
	}
}
