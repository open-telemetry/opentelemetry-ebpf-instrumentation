// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJoinRoutePaths(t *testing.T) {
	tests := []struct {
		name       string
		classPath  string
		methodPath string
		expected   string
	}{
		{
			name:     "empty paths produce root",
			expected: "/",
		},
		{
			name:       "class path only",
			classPath:  "api",
			methodPath: "",
			expected:   "/api",
		},
		{
			name:       "method path only",
			classPath:  "",
			methodPath: "users",
			expected:   "/users",
		},
		{
			name:       "trims surrounding slashes before joining",
			classPath:  "/api/",
			methodPath: "/users/",
			expected:   "/api/users",
		},
		{
			name:       "trims surrounding spaces",
			classPath:  " /api ",
			methodPath: " users ",
			expected:   "/api/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, joinRoutePaths(tt.classPath, tt.methodPath))
		})
	}
}

func TestNormalizeRoute(t *testing.T) {
	tests := []struct {
		name     string
		route    string
		expected string
		ok       bool
	}{
		{
			name:     "copilot review one",
			route:    "/foo:bar",
			expected: "",
			ok:       false,
		},
		{
			name:     "copilot review two",
			route:    "/:123",
			expected: "",
			ok:       false,
		},
		{
			name:     "adds leading slash",
			route:    "api/users",
			expected: "/api/users",
			ok:       true,
		},
		{
			name:     "trims surrounding spaces",
			route:    " /api/users ",
			expected: "/api/users",
			ok:       true,
		},
		{
			name:     "trims trailing slash",
			route:    "/api/users/",
			expected: "/api/users",
			ok:       true,
		},
		{
			name:     "keeps root",
			route:    "/",
			expected: "/",
			ok:       true,
		},
		{
			name:     "sanitizes regex path parameter",
			route:    "/users/{id:[0-9]+}/",
			expected: "/users/{id}",
			ok:       true,
		},
		{
			name:     "sanitizes underscored path parameter",
			route:    "/users/{_id:\\d+}",
			expected: "/users/{_id}",
			ok:       true,
		},
		{
			name:     "keeps Quarkus colon parameter",
			route:    "/items/:itemId/",
			expected: "/items/:itemId",
			ok:       true,
		},
		{
			name:     "rejects invalid colon parameter",
			route:    "/items/:123",
			expected: "",
			ok:       false,
		},
		{
			name:     "rejects colon in static segment",
			route:    "/api/foo:bar/details",
			expected: "",
			ok:       false,
		},
		{
			name:     "keeps trailing wildcard",
			route:    "/assets/*",
			expected: "/assets/*",
			ok:       true,
		},
		{
			name:     "normalizes trailing double wildcard",
			route:    "/assets/**",
			expected: "/assets/*",
			ok:       true,
		},
		{
			name:     "keeps wildcard in middle",
			route:    "/assets/*/images",
			expected: "/assets/*/images",
			ok:       true,
		},
		{
			name:     "rejects embedded wildcard",
			route:    "/assets/file*.js",
			expected: "",
			ok:       false,
		},
		{
			name:     "trims query strings",
			route:    "/users?id=1",
			expected: "/users",
			ok:       true,
		},
		{
			name:     "trims fragments",
			route:    "/users#id",
			expected: "/users",
			ok:       true,
		},
		{
			name:     "rejects absolute URLs",
			route:    "https://example.com/users",
			expected: "",
			ok:       false,
		},
		{
			name:     "rejects placeholders",
			route:    "/${api.base}/users",
			expected: "",
			ok:       false,
		},
		{
			name:     "rejects empty route",
			route:    "",
			expected: "",
			ok:       false,
		},
		{
			name:     "rejects whitespace route",
			route:    "   ",
			expected: "",
			ok:       false,
		},
		{
			name:     "rejects punctuation only route",
			route:    "---",
			expected: "",
			ok:       false,
		},
		{
			name:     "sanitizes angle path parameter",
			route:    "/users/<id>",
			expected: "/users/{id}",
			ok:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, ok := normalizeRoute(tt.route)

			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
