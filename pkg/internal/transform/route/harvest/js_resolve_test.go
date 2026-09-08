// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordStringDeclaration(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected map[string]string
	}{
		{
			name:     "const with single quotes",
			line:     "const base = '/api';",
			expected: map[string]string{"base": "/api"},
		},
		{
			name:     "const with double quotes and no semicolon",
			line:     `const users = "/users"`,
			expected: map[string]string{"users": "/users"},
		},
		{
			name:     "const with template literal",
			line:     "const items = `/items`;",
			expected: map[string]string{"items": "/items"},
		},
		{
			name:     "let is not tracked",
			line:     "let users = '/users';",
			expected: map[string]string{},
		},
		{
			name:     "var is not tracked",
			line:     "var items = '/items';",
			expected: map[string]string{},
		},
		{
			name:     "exported const",
			line:     "export const version = 'v1';",
			expected: map[string]string{"version": "v1"},
		},
		{
			name:     "escaped quote in the literal",
			line:     `const p = '/it\'s';`,
			expected: map[string]string{"p": `/it\'s`},
		},
		{
			name:     "interpolated template is unresolvable",
			line:     "const p = `/api/${version}`;",
			expected: map[string]string{"p": ""},
		},
		{
			name:     "concatenation is unresolvable",
			line:     "const p = '/api' + '/users';",
			expected: map[string]string{"p": ""},
		},
		{
			name:     "several declarators are unresolvable",
			line:     "const p = '/api', other = 1;",
			expected: map[string]string{"p": ""},
		},
		{
			name:     "empty string is unresolvable",
			line:     "const p = '';",
			expected: map[string]string{"p": ""},
		},
		{
			name:     "non-literal initializer is unresolvable",
			line:     "const p = require('./paths');",
			expected: map[string]string{"p": ""},
		},
		{
			name:     "not a declaration",
			line:     "app.get('/users', handler);",
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			extractor.recordStringDeclaration(tt.line)
			assert.Equal(t, tt.expected, extractor.jsConsts)
		})
	}
}

func TestRecordStringDeclarationRedeclaredNameIsAmbiguous(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
	}{
		{
			name:  "two literals",
			lines: []string{"const p = '/first';", "const p = '/second';"},
		},
		{
			name:  "literal then expression",
			lines: []string{"const p = '/first';", "const p = prefix + '/second';"},
		},
		{
			name:  "expression then literal",
			lines: []string{"const p = getPath();", "const p = '/inner';"},
		},
		{
			name:  "three declarations",
			lines: []string{"const p = '/first';", "const p = '/second';", "const p = '/third';"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			for _, line := range tt.lines {
				extractor.recordStringDeclaration(line)
			}
			assert.Equal(t, map[string]string{"p": ""}, extractor.jsConsts)
			assert.Empty(t, extractor.resolveJSExpression("p"))
			assert.Equal(t, "/x/${p}", extractor.resolveJSExpression("`/x/${p}`"))
		})
	}
}

func TestRecordStringDeclarationIsBounded(t *testing.T) {
	extractor := NewRouteExtractor()
	for i := range maxJSStringConsts {
		extractor.recordStringDeclaration("const p" + strconv.Itoa(i) + " = '/path';")
	}
	require.Len(t, extractor.jsConsts, maxJSStringConsts)

	// new names are dropped once the cap is reached
	extractor.recordStringDeclaration("const overflow = '/overflow';")
	assert.Len(t, extractor.jsConsts, maxJSStringConsts)
	assert.NotContains(t, extractor.jsConsts, "overflow")

	// a known name declared again is still marked ambiguous
	extractor.recordStringDeclaration("const p0 = '/redeclared';")
	assert.Empty(t, extractor.jsConsts["p0"])
}

func TestFirstJSArgument(t *testing.T) {
	tests := []struct {
		name     string
		rest     string
		expected string
		complete bool
	}{
		{
			name:     "ends at the comma",
			rest:     "'/users', handler)",
			expected: "'/users'",
			complete: true,
		},
		{
			name:     "ends at the closing parenthesis",
			rest:     "'/users')",
			expected: "'/users'",
			complete: true,
		},
		{
			name:     "comma inside the string",
			rest:     "'/a,b', handler)",
			expected: "'/a,b'",
			complete: true,
		},
		{
			name:     "nested call",
			rest:     "join(base, '/users'), handler)",
			expected: "join(base, '/users')",
			complete: true,
		},
		{
			name:     "object argument",
			rest:     "{ method: 'GET', url: '/x' })",
			expected: "{ method: 'GET', url: '/x' }",
			complete: true,
		},
		{
			name:     "argument spread over lines",
			rest:     "\n  base + '/multi',\n  handler)",
			expected: "base + '/multi'",
			complete: true,
		},
		{
			name:     "cut after an operator",
			rest:     "base +",
			expected: "base +",
		},
		{
			name:     "cut after an operand",
			rest:     "base",
			expected: "base",
		},
		{
			name:     "empty",
			rest:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arg, complete := firstJSArgument(tt.rest)
			assert.Equal(t, tt.expected, arg)
			assert.Equal(t, tt.complete, complete)
		})
	}
}

func TestResolveJSExpression(t *testing.T) {
	consts := map[string]string{
		"base":    "/api",
		"version": "v1",
	}
	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{
			name:     "string literal",
			expr:     "'/users'",
			expected: "/users",
		},
		{
			name:     "template literal without interpolation",
			expr:     "`/users`",
			expected: "/users",
		},
		{
			name:     "known constant",
			expr:     "base",
			expected: "/api",
		},
		{
			name:     "unknown constant",
			expr:     "prefix",
			expected: "",
		},
		{
			name:     "concatenation of constants and literals",
			expr:     "base + '/' + version + \"/users\"",
			expected: "/api/v1/users",
		},
		{
			name:     "concatenation with an unknown constant",
			expr:     "prefix + '/users'",
			expected: "",
		},
		{
			name:     "plus inside a literal",
			expr:     "base + '/a+b'",
			expected: "/api/a+b",
		},
		{
			name:     "template with known interpolations",
			expr:     "`${base}/${version}/users`",
			expected: "/api/v1/users",
		},
		{
			name:     "template with unknown interpolation kept",
			expr:     "`${base}/users/${req.params.id}`",
			expected: "/api/users/${req.params.id}",
		},
		{
			name:     "concatenation with a template",
			expr:     "base + `/items/${id}`",
			expected: "/api/items/${id}",
		},
		{
			name:     "member access",
			expr:     "routes.users",
			expected: "",
		},
		{
			name:     "call",
			expr:     "join(base, '/users')",
			expected: "",
		},
		{
			name:     "arrow function",
			expr:     "(req, res) => res.send('ok')",
			expected: "",
		},
		{
			name:     "object",
			expr:     "{ method: 'GET', url: '/x' }",
			expected: "",
		},
		{
			name:     "dangling plus",
			expr:     "base +",
			expected: "",
		},
		{
			name:     "unterminated literal",
			expr:     "'/users",
			expected: "",
		},
		{
			name:     "empty",
			expr:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			extractor.jsConsts = consts
			assert.Equal(t, tt.expected, extractor.resolveJSExpression(tt.expr))
		})
	}
}

func TestSubstituteTemplate(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		expected string
	}{
		{
			name:     "known name",
			contents: "${base}/users",
			expected: "/api/users",
		},
		{
			name:     "known name with spaces",
			contents: "${ base }/users",
			expected: "/api/users",
		},
		{
			name:     "unknown name is kept",
			contents: "/users/${id}",
			expected: "/users/${id}",
		},
		{
			name:     "expression is kept",
			contents: "/users/${ids[0]}/${fn({a: 1})}",
			expected: "/users/${ids[0]}/${fn({a: 1})}",
		},
		{
			name:     "escaped interpolation is kept",
			contents: `/users/\${base}`,
			expected: `/users/\${base}`,
		},
		{
			name:     "dollar without brace",
			contents: "/price/$5",
			expected: "/price/$5",
		},
		{
			name:     "unterminated interpolation",
			contents: "/users/${base",
			expected: "/users/${base",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			extractor.jsConsts["base"] = "/api"
			assert.Equal(t, tt.expected, extractor.substituteTemplate(tt.contents))
		})
	}
}
