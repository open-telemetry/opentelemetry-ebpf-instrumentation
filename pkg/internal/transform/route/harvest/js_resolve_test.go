// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// js lexes a line of source for the tests
func js(s string) jsSource {
	src, _ := lexJS(s)
	return src
}

func texts(sources []jsSource) []string {
	out := make([]string, len(sources))
	for i, s := range sources {
		out[i] = s.text
	}
	return out
}

func TestRecordConstDeclaration(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected map[string]string
	}{
		{"single quotes", "const base = '/api';", map[string]string{"base": "/api"}},
		{"double quotes, no semicolon", `const users = "/users"`, map[string]string{"users": "/users"}},
		{"template literal", "const items = `/items`;", map[string]string{"items": "/items"}},
		{"exported", "export const version = 'v1';", map[string]string{"version": "v1"}},
		{"let is not tracked", "let users = '/users';", map[string]string{}},
		{"var is not tracked", "var items = '/items';", map[string]string{}},
		{"trailing line comment", "const base = '/api'; // prefix", map[string]string{"base": "/api"}},
		{"trailing block comment", "const base = '/api' /* prefix */", map[string]string{"base": "/api"}},
		{"comment before the literal", "const p = /* prefix */ '/api';", map[string]string{"p": "/api"}},
		{"comment holding a comma", "const p = '/api' /* , q = 1 */;", map[string]string{"p": "/api"}},
		{"type annotation", "const base: string = '/api';", map[string]string{"base": "/api"}},
		{"generic type annotation", "const base: Array<string> = '/api';", map[string]string{"base": "/api"}},
		{"no spaces", "const base:string='/api'", map[string]string{"base": "/api"}},
		{"as const", "const p = '/api' as const;", map[string]string{"p": "/api"}},
		{"satisfies", "const p = '/api' satisfies string;", map[string]string{"p": "/api"}},
		{"cast", "const p = <string>'/api';", map[string]string{"p": "/api"}},
		{"number", "const version = 2;", map[string]string{"version": "2"}},
		{"parenthesized literal", "const p = ('/api');", map[string]string{"p": "/api"}},
		{"dollar and underscore in the name", "const $_base = '/api';", map[string]string{"$_base": "/api"}},
		{"carriage return", "const base = '/api';\r", map[string]string{"base": "/api"}},
		{"escaped quote", `const p = '/it\'s';`, map[string]string{"p": `/it\'s`}},
		{"concatenation of literals", "const p = '/api' + '/users';", map[string]string{"p": "/api/users"}},
		{"template keeps an unknown interpolation", "const p = `/api/${version}`;", map[string]string{"p": "/api/${version}"}},
		{"several declarators", "const p = '/api', other = 1;", map[string]string{"p": "/api", "other": "1"}},
		{"declarator holding a call with a comma", "const a = f(x, y), b = '/b';", map[string]string{"a": "", "b": "/b"}},
		{"destructuring declarator is skipped", "const { a } = paths, b = '/b';", map[string]string{"b": "/b"}},
		{"several statements", "const p = '/api'; const q = '/b';", map[string]string{"p": "/api", "q": "/b"}},
		{"minified statements", "const a='/a';const b='/b';app.get(a+b,h);", map[string]string{"a": "/a", "b": "/b"}},
		{"semicolon inside the literal", "const p = '/a;b'; const q = '/q';", map[string]string{"p": "/a;b", "q": "/q"}},
		{"empty string is unresolvable", "const p = '';", map[string]string{"p": ""}},
		{"call is unresolvable", "const p = require('./paths');", map[string]string{"p": ""}},
		{"method call on the literal is unresolvable", "const p = '/api'.toLowerCase();", map[string]string{"p": ""}},
		{"unterminated literal is unresolvable", "const p = '/api", map[string]string{"p": ""}},
		{"regex initializer is unresolvable", "const re = /a,b/;", map[string]string{"re": ""}},
		{"not a declaration", "app.get('/users', handler);", map[string]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			extractor.recordConstDeclaration(js(tt.line))
			assert.Equal(t, tt.expected, extractor.jsConsts)
		})
	}
}

func TestRecordConstDeclarationFromConstants(t *testing.T) {
	extractor := NewRouteExtractor()
	for _, line := range []string{
		"const base = '/api';",
		"const version = 2;",
		"const users = base + '/users';",
		"const versioned = `${base}/v${version}`;",
		"const partial = `${base}/${unknown}`;",
		"const later = base + missing;",
	} {
		extractor.recordConstDeclaration(js(line))
	}

	assert.Equal(t, map[string]string{
		"base":      "/api",
		"version":   "2",
		"users":     "/api/users",
		"versioned": "/api/v2",
		"partial":   "/api/${unknown}",
		"later":     "",
	}, extractor.jsConsts)
	assert.Equal(t, "/api/users/all", extractor.resolveJSExpression(js("users + '/all'")))
	assert.Equal(t, "/api/${unknown}/x", extractor.resolveJSExpression(js("`${partial}/x`")))
}

func TestRecordConstDeclarationRedeclaredNameIsAmbiguous(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
	}{
		{"two literals", []string{"const p = '/first';", "const p = '/second';"}},
		{"literal then expression", []string{"const p = '/first';", "const p = prefix + '/second';"}},
		{"expression then literal", []string{"const p = getPath();", "const p = '/inner';"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			for _, line := range tt.lines {
				extractor.recordConstDeclaration(js(line))
			}
			assert.Equal(t, map[string]string{"p": ""}, extractor.jsConsts)
			assert.Empty(t, extractor.resolveJSExpression(js("p")))
			assert.Equal(t, "/x/${p}", extractor.resolveJSExpression(js("`/x/${p}`")))
		})
	}
}

func TestRecordConstDeclarationIsBounded(t *testing.T) {
	extractor := NewRouteExtractor()

	// unresolvable names, typical of bundled code, do not count
	for i := range maxJSConsts {
		extractor.recordConstDeclaration(js("const m" + strconv.Itoa(i) + " = require('./m');"))
	}
	for i := range maxJSConsts {
		extractor.recordConstDeclaration(js("const p" + strconv.Itoa(i) + " = '/path';"))
	}
	require.Len(t, extractor.jsConsts, 2*maxJSConsts)
	assert.Equal(t, "/path", extractor.resolveJSExpression(js("p0")))

	// once the cap is reached a new name is remembered without its value
	extractor.recordConstDeclaration(js("const overflow = '/overflow';"))
	assert.Contains(t, extractor.jsConsts, "overflow")
	assert.Empty(t, extractor.resolveJSExpression(js("overflow")))

	// a known name declared again is still marked ambiguous, which frees a
	// slot for a later value
	extractor.recordConstDeclaration(js("const p0 = '/redeclared';"))
	assert.Empty(t, extractor.resolveJSExpression(js("p0")))
	extractor.recordConstDeclaration(js("const freed = '/freed';"))
	assert.Equal(t, "/freed", extractor.resolveJSExpression(js("freed")))
}

func TestLexJS(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		code        string
		openComment int
	}{
		{"string contents blanked", "app.get('/users', h)", "app.get('      ', h)", -1},
		{"line comment blanked", "x(); // app.get(p", "x();             ", -1},
		{"block comment blanked", "a /* b */ c", "a         c", -1},
		{"regex contents blanked", "s.match(/a,b/)", "s.match(/   /)", -1},
		{"unterminated string blanked to the end", "app.get('/users", "app.get('      ", -1},
		{"escaped slash is not a comment", "x = \\/* y", "x = \\/* y", -1},
		{"opened at the start", "/* start", "        ", 0},
		{"opened after code", "app.get('/x', h); /* start", "app.get('  ', h);         ", 18},
		{"marker inside a string", "app.get('/*', h)", "app.get('  ', h)", -1},
		{"marker after a line comment", "a() // see /* note", "a()               ", -1},
		{"regex literal holding a marker", "p.replace(/\\/*$/, '')", "p.replace(/    /, '')", -1},
		{"character class after return", "return /[/*]/;", "return /    /;", -1},
		{"division before an open comment", "a / 2; /* open", "a / 2;        ", 7},
		{"unclosed regex ends with its line", "x(/a\nb('/c')", "x(/ \nb('  ')", -1},
		{"unclosed string ends with its line", "x('/a\nb('/c')", "x('  \nb('  ')", -1},
		{"template spans lines", "x(`/a\nb`)", "x(`    `)", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, open := lexJS(tt.line)
			assert.Equal(t, tt.line, src.text)
			assert.Equal(t, tt.code, src.code)
			assert.Equal(t, tt.openComment, open)
		})
	}
}

func TestStartsJSRegex(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected bool
	}{
		{"argument", "app.get(/x/, h)", true},
		{"assignment", "const r = /x/", true},
		{"start of source", "/x/.test(s)", true},
		{"after return", "return /x/", true},
		{"after an identifier", "count / 2", false},
		{"after a keyword-like identifier", "returned / 2", false},
		{"after a non-ascii identifier", "größe / 2", false},
		{"after a paren", "(a + b) / 2", false},
		{"line comment", "a // c", false},
		{"block comment", "a /* c */", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, startsJSRegex(tt.source, strings.IndexByte(tt.source, '/')))
		})
	}
}

func TestJSCommentStateStrip(t *testing.T) {
	var state jsCommentState
	lines := []struct {
		line     string
		expected string
		ok       bool
	}{
		{"  app.get('/a', h); /* open", "app.get('/a', h); ", true},
		{"const dead = '/dead';", "", false},
		{"still dead */ app.get('/b', h);", "app.get('/b', h);", true},
		{"/* note */ app.get('/c', h);", "app.get('/c', h);", true},
		{"  // only a comment", "", false},
		{"/* start", "", false},
		{"const dead = '/dead';", "", false},
		{"*/", "", false},
		{"app.get('/d', h);", "app.get('/d', h);", true},
	}

	for i, tt := range lines {
		src, ok := state.strip(tt.line)
		assert.Equal(t, tt.ok, ok, "line %d", i)
		assert.Equal(t, tt.expected, src.text, "line %d", i)
	}
}

func TestJSLineBuffer(t *testing.T) {
	var buffer jsLineBuffer

	merged, lines := buffer.merge("a")
	assert.Equal(t, "a", merged)
	assert.Equal(t, 1, lines)

	buffer.keep(merged, lines)
	merged, lines = buffer.merge("b")
	assert.Equal(t, "a\nb", merged)
	assert.Equal(t, 2, lines)

	// merging empties the buffer
	merged, lines = buffer.merge("c")
	assert.Equal(t, "c", merged)
	assert.Equal(t, 1, lines)

	// a text spanning too many lines is not kept
	buffer.keep("x", maxJSBufferedLines)
	merged, lines = buffer.merge("d")
	assert.Equal(t, "d", merged)
	assert.Equal(t, 1, lines)
}

func TestJSSourceTrim(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		trimmed   string
		startOnly string
	}{
		{"whitespace", "  a + b  ", "a + b", "a + b  "},
		{"comments", "/* a */ code // b", "code", "code // b"},
		{"unterminated literal", "app.get(`/x", "app.get(`", "app.get(`/x"},
		{"only a comment", "  // note", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.trimmed, js(tt.line).trim().text)
			assert.Equal(t, tt.startOnly, js(tt.line).trimStart().text)
		})
	}
}

func TestJSSourceSplit(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		sep      byte
		expected []string
	}{
		{"declarators", "a = '/a', b = '/b'", ',', []string{"a = '/a'", "b = '/b'"}},
		{"comma inside a call", "a = f(x, y), b = 2", ',', []string{"a = f(x, y)", "b = 2"}},
		{"comma inside a string", "a = ',', b = 2", ',', []string{"a = ','", "b = 2"}},
		{"comma inside a comment", "a = 1 /* , */, b = 2", ',', []string{"a = 1", "b = 2"}},
		{"plus inside a regex", "/a+b/ + '/x'", '+', []string{"/a+b/", "'/x'"}},
		{"plus inside a string", "'/a+b' + c", '+', []string{"'/a+b'", "c"}},
		{"no separator", "x", ',', []string{"x"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, texts(js(tt.expr).split(tt.sep)))
		})
	}
}

func TestFirstJSArgument(t *testing.T) {
	tests := []struct {
		name     string
		rest     string
		expected string
		complete bool
	}{
		{"ends at the comma", "'/users', handler)", "'/users'", true},
		{"ends at the closing parenthesis", "'/users')", "'/users'", true},
		{"comma inside the string", "'/a,b', handler)", "'/a,b'", true},
		{"nested call", "join(base, '/x'), handler)", "join(base, '/x')", true},
		{"object argument", "{ method: 'GET', url: '/x' }, handler)", "{ method: 'GET', url: '/x' }", true},
		{"argument spread over lines", "base +\n  '/users', handler)", "base +\n  '/users'", true},
		{"comma inside a template interpolation", "`/x/${a, b}`, handler)", "`/x/${a, b}`", true},
		{"comment before the comma", "'/x' /* c */, handler)", "'/x'", true},
		{"comma inside a comment", "'/x' /* , */ , handler)", "'/x'", true},
		{"regex literal holding a comma", "/a,b/, handler)", "/a,b/", true},
		{"division", "'/x' + n / 2, handler)", "'/x' + n / 2", true},
		{"no argument", ")", "", true},
		{"line comment cuts the source", "'/x' // , handler)", "'/x'", false},
		{"unclosed block comment cuts the source", "'/x' /* c", "'/x'", false},
		{"unterminated regex cuts the source", "/a(b, handler", "/", false},
		{"cut after an operator", "base +", "base +", false},
		{"cut after an operand", "base", "base", false},
		{"empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arg, complete := firstJSArgument(js(tt.rest))
			assert.Equal(t, tt.expected, arg.text)
			assert.Equal(t, tt.complete, complete)
		})
	}
}

func TestResolveRouteCalls(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		calls []routeCall
		cut   bool
	}{
		{"literal", "app.get('/users', handler)", []routeCall{{"get", "/users"}}, false},
		{"comment before the comma", "app.get(base + '/x' /* c */, handler)", []routeCall{{"get", "/api/x"}}, false},
		{"comment inside the expression", "app.get(base /* c */ + '/x', handler)", []routeCall{{"get", "/api/x"}}, false},
		{"line comment cuts the argument", "app.get(base + '/x' // path", nil, true},
		{"argument continues after a line comment", "app.get(base + '/x' // path\n, handler)", []routeCall{{"get", "/api/x"}}, false},
		{"unresolvable call before a resolvable one", "cache.get(unknown, load); app.post(base + '/x', handler)", []routeCall{{"post", "/api/x"}}, false},
		{"every resolvable call", "app.get(base + '/a', h); app.post(base + '/b', h)", []routeCall{{"get", "/api/a"}, {"post", "/api/b"}}, false},
		{"cut call after a resolvable one", "app.get('/a', h); app.post(base", nil, true},
		{"type assertion on the argument", "app.get((base + '/x') as string, handler)", []routeCall{{"get", "/api/x"}}, false},
		{"call inside a trailing comment", "doWork(); // app.get(prefix", nil, false},
		{"call inside a string", "log('app.get(' + prefix)", nil, false},
		{"comment before a real call", "/* app.get(a */ app.post(base + '/x', handler)", []routeCall{{"post", "/api/x"}}, false},
		{"nothing resolvable", "app.get(unknown, handler)", nil, false},
		{"no call", "const x = 1", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			extractor.jsConsts["base"] = "/api"
			calls, cut := extractor.resolveRouteCalls(js(tt.line), extractor.patterns.Typical)
			assert.Equal(t, tt.calls, calls)
			assert.Equal(t, tt.cut, cut)
		})
	}
}

func TestResolveJSExpression(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{"string literal", "'/users'", "/users"},
		{"template literal without interpolation", "`/users`", "/users"},
		{"known constant", "base", "/api"},
		{"unknown constant", "unknown", ""},
		{"concatenation of constants and literals", "base + '/' + version + '/users'", "/api/v1/users"},
		{"concatenation with an unknown constant", "base + unknown + '/users'", ""},
		{"no spaces around the operator", "base+'/users'", "/api/users"},
		{"plus inside a literal", "'/a+b'", "/a+b"},
		{"template with known interpolations", "`${base}/${version}/users`", "/api/v1/users"},
		{"template with unknown interpolation kept", "`${base}/users/${req.params.id}`", "/api/users/${req.params.id}"},
		{"adjacent interpolations", "`${base}${version}`", "/apiv1"},
		{"concatenation with a template", "base + `/items/${id}`", "/api/items/${id}"},
		{"number operand", "'/v' + 1", "/v1"},
		{"parenthesized expression", "('/a' + '/b')", "/a/b"},
		{"nested parentheses", "((base) + '/x')", "/api/x"},
		{"group followed by a call is unresolvable", "(base)('/x')", ""},
		{"non-null assertion", "base! + '/x'", "/api/x"},
		{"type assertion on an inner operand", "(base as string) + '/x'", "/api/x"},
		{"cast on an inner operand", "<string>base + '/x'", "/api/x"},
		{"member access", "routes.users", ""},
		{"call", "join(base, '/users')", ""},
		{"method call on a literal", "'/a' + '/b'.toUpperCase()", ""},
		{"other operators", "base ?? '/x'", ""},
		{"arrow function", "(req, res) => res.send('ok')", ""},
		{"object", "{ method: 'GET', url: '/x' }", ""},
		{"plus inside a regex literal", "/a+b/ + '/x'", ""},
		{"dangling plus", "base +", ""},
		{"unterminated literal", "'/users", ""},
		{"template spanning lines", "`/multi\n/line`", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			extractor.jsConsts["base"] = "/api"
			extractor.jsConsts["version"] = "v1"
			assert.Equal(t, tt.expected, extractor.resolveJSExpression(js(tt.expr)))
		})
	}
}

func TestStripJSTypeSyntax(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{"as const", "'/api' as const", "'/api'"},
		{"as string on a concatenation", "base + '/x' as string", "base + '/x'"},
		{"satisfies a generic", "'/api' satisfies Array<string>", "'/api'"},
		{"cast", "<string>'/api'", "'/api'"},
		{"cast and assertion", "<string>'/api' as const", "'/api'"},
		{"non-null", "base!", "base"},
		{"as inside a string kept", "'/a as b'", "'/a as b'"},
		{"identifier ending in as kept", "alias", "alias"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			assert.Equal(t, tt.expected, extractor.stripJSTypeSyntax(js(tt.expr)).text)
		})
	}
}

func TestClosesJSGroup(t *testing.T) {
	tests := []struct {
		operand  string
		expected bool
	}{
		{"(a + b)", true},
		{"((a) + (b))", true},
		{"('(' + b)", true},
		{"(a) + (b)", false},
		{"(a)(b)", false},
		{"(a + b", false},
		{"a + b", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.operand, func(t *testing.T) {
			assert.Equal(t, tt.expected, closesJSGroup(js(tt.operand)))
		})
	}
}

func TestIsJSNumberAndIdentifier(t *testing.T) {
	tests := []struct {
		s          string
		number     bool
		identifier bool
	}{
		{"", false, false},
		{"12", true, false},
		{"1a", false, false},
		{"a1", false, true},
		{"$_x", false, true},
		{"a.b", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			assert.Equal(t, tt.number, isJSNumber(tt.s))
			assert.Equal(t, tt.identifier, isJSIdentifier(tt.s))
		})
	}
}

func TestSubstituteTemplate(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		expected string
	}{
		{"known name", "${base}/users", "/api/users"},
		{"known name with spaces", "${ base }/users", "/api/users"},
		{"unknown name is kept", "/users/${id}", "/users/${id}"},
		{"expression is kept", "/users/${ids[0]}/${fn({a: 1})}", "/users/${ids[0]}/${fn({a: 1})}"},
		{"member access is kept", "${base.path}/users", "${base.path}/users"},
		{"concatenation resolved", "${base + '/v'}/users", "/api/v/users"},
		{"group resolved", "${(base)}/users", "/api/users"},
		{"literal resolved", "/x/${'}'}", "/x/}"},
		{"template resolved", "/x/${`${base}`}", "/x//api"},
		{"escaped interpolation is kept", `/users/\${base}`, `/users/\${base}`},
		{"dollar without brace", "/price/$5", "/price/$5"},
		{"unterminated interpolation", "/users/${base", "/users/${base"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewRouteExtractor()
			extractor.jsConsts["base"] = "/api"
			assert.Equal(t, tt.expected, extractor.substituteTemplate(tt.contents))
		})
	}
}
