// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLexPHPTokenizesRelevantSource(t *testing.T) {
	tokens := lexPHP([]byte(" \t// ignored\n# ignored\n/** route */ Route::get('/users', $handler); \"ignored $name\" #"))

	assert.Equal(t, []token{
		{kind: tokenDocComment, value: "/** route */"},
		{kind: tokenName, value: "Route"},
		{kind: tokenSymbol, value: "::"},
		{kind: tokenName, value: "get"},
		{kind: tokenSymbol, value: "("},
		{kind: tokenString, value: "/users"},
		{kind: tokenSymbol, value: ","},
		{kind: tokenVariable, value: "$handler"},
		{kind: tokenSymbol, value: ")"},
		{kind: tokenSymbol, value: ";"},
	}, tokens)
}

func TestLexPHPNullsafeOperator(t *testing.T) {
	tokens := lexPHP([]byte(`$app?->get`))

	assert.Equal(t, []token{
		{kind: tokenVariable, value: "$app"},
		{kind: tokenSymbol, value: "?->"},
		{kind: tokenName, value: "get"},
	}, tokens)
}

func TestReadPHPString(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		start      int
		want       string
		wantNext   int
		wantStatic bool
	}{
		{name: "single quoted", data: `'plain'`, want: "plain", wantNext: 7, wantStatic: true},
		{name: "single quote escape", data: `'it\'s'`, want: "it's", wantNext: 7, wantStatic: true},
		{name: "single quote preserves unknown escape", data: `'\d+'`, want: `\d+`, wantNext: 5, wantStatic: true},
		{name: "double quote escape", data: `"quoted\""`, want: `quoted"`, wantNext: 10, wantStatic: true},
		{
			name:       "double quote control escapes",
			data:       `"\n\r\t\v\e\f"`,
			want:       "\n\r\t\v\x1b\f",
			wantNext:   len(`"\n\r\t\v\e\f"`),
			wantStatic: true,
		},
		{name: "double quote octal escape", data: `"\057users"`, want: "/users", wantNext: 11, wantStatic: true},
		{name: "double quote octal overflow", data: `"\400"`, want: "\x00", wantNext: 6, wantStatic: true},
		{name: "double quote hexadecimal escape", data: `"\x2Fusers"`, want: "/users", wantNext: len(`"\x2Fusers"`), wantStatic: true},
		{name: "double quote Unicode escape", data: `"\u{1F600}"`, want: "😀", wantNext: 11, wantStatic: true},
		{name: "double quote interpolation", data: `"hello $name"`, want: "hello $name", wantNext: 13},
		{name: "double quote curly interpolation", data: `"hello {$name}"`, want: "hello {$name}", wantNext: 15},
		{name: "double quote legacy curly interpolation", data: `"hello ${name}"`, want: "hello ${name}", wantNext: 15},
		{name: "escaped dollar is literal", data: `"hello \$name"`, want: "hello $name", wantNext: 14, wantStatic: true},
		{name: "dollar not followed by name is literal", data: `"price $5"`, want: "price $5", wantNext: 10, wantStatic: true},
		{name: "trailing dollar is literal", data: `"total $"`, want: "total $", wantNext: 9, wantStatic: true},
		{name: "double quote preserves unknown escape", data: `"\d+"`, want: `\d+`, wantNext: 5, wantStatic: true},
		{name: "double quote preserves PCRE hexadecimal escape", data: `"\x{2F}"`, want: `\x{2F}`, wantNext: 8, wantStatic: true},
		{name: "offset", data: `xx'route'`, start: 2, want: "route", wantNext: 9, wantStatic: true},
		{name: "unterminated", data: `'broken`, wantNext: 7},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, next, static := readPHPString([]byte(test.data), test.start)

			assert.Equal(t, test.want, value)
			assert.Equal(t, test.wantNext, next)
			assert.Equal(t, test.wantStatic, static)
		})
	}
}

func TestDecodePHPStringEscape(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		start    int
		quote    byte
		want     string
		wantNext int
	}{
		{name: "double quoted newline", data: `\n`, quote: '"', want: "\n", wantNext: 2},
		{name: "double quoted quote", data: `\"`, quote: '"', want: `"`, wantNext: 2},
		{name: "double quoted backslash", data: `\\`, quote: '"', want: `\`, wantNext: 2},
		{name: "double quoted dollar", data: `\$`, quote: '"', want: `$`, wantNext: 2},
		{name: "double quoted unknown escape", data: `\d`, quote: '"', want: `\d`, wantNext: 2},
		{name: "single quoted quote", data: `\'`, quote: '\'', want: `'`, wantNext: 2},
		{name: "single quoted backslash", data: `\\`, quote: '\'', want: `\`, wantNext: 2},
		{name: "single quoted newline stays escaped", data: `\n`, quote: '\'', want: `\n`, wantNext: 2},
		{name: "offset", data: `xx\t`, start: 2, quote: '"', want: "\t", wantNext: 4},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, next := decodePHPStringEscape([]byte(test.data), test.start, test.quote)

			assert.Equal(t, test.want, value)
			assert.Equal(t, test.wantNext, next)
		})
	}
}

func TestDecodePHPOctalEscape(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		start    int
		want     string
		wantNext int
	}{
		{name: "one digit", data: `\7rest`, want: "\a", wantNext: 2},
		{name: "two digits", data: `\57rest`, want: "/", wantNext: 3},
		{name: "three digits", data: `\101rest`, want: "A", wantNext: 4},
		{name: "stops after three digits", data: `\0577`, want: "/", wantNext: 4},
		{name: "overflows to one byte", data: `\400`, want: "\x00", wantNext: 4},
		{name: "offset", data: `xx\101`, start: 2, want: "A", wantNext: 6},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, next := decodePHPOctalEscape([]byte(test.data), test.start)

			assert.Equal(t, test.want, value)
			assert.Equal(t, test.wantNext, next)
		})
	}
}

func TestDecodePHPHexEscape(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		start    int
		want     string
		wantNext int
		wantOK   bool
	}{
		{name: "one digit", data: `\x2rest`, want: "\x02", wantNext: 3, wantOK: true},
		{name: "two digits", data: `\x2Frest`, want: "/", wantNext: 4, wantOK: true},
		{name: "lowercase digit", data: `\xarest`, want: "\n", wantNext: 3, wantOK: true},
		{name: "stops after two digits", data: `\x2F7`, want: "/", wantNext: 4, wantOK: true},
		{name: "missing digit", data: `\x`},
		{name: "invalid digit", data: `\xZ`},
		{name: "offset", data: `xx\x41`, start: 2, want: "A", wantNext: 6, wantOK: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, next, ok := decodePHPHexEscape([]byte(test.data), test.start)

			assert.Equal(t, test.want, value)
			assert.Equal(t, test.wantNext, next)
			assert.Equal(t, test.wantOK, ok)
		})
	}
}

func TestDecodePHPUnicodeEscape(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		start    int
		want     string
		wantNext int
		wantOK   bool
	}{
		{name: "ASCII", data: `\u{41}rest`, want: "A", wantNext: 6, wantOK: true},
		{name: "multibyte", data: `\u{1F600}`, want: "😀", wantNext: 9, wantOK: true},
		{name: "missing braces", data: `\u41`},
		{name: "empty", data: `\u{}`},
		{name: "non hexadecimal", data: `\u{route}`},
		{name: "missing closing brace", data: `\u{41`},
		{name: "invalid codepoint", data: `\u{110000}`},
		{name: "surrogate", data: `\u{D800}`},
		{name: "offset", data: `xx\u{2F}`, start: 2, want: "/", wantNext: 8, wantOK: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, next, ok := decodePHPUnicodeEscape([]byte(test.data), test.start)

			assert.Equal(t, test.want, value)
			assert.Equal(t, test.wantNext, next)
			assert.Equal(t, test.wantOK, ok)
		})
	}
}

func TestIsOctalDigit(t *testing.T) {
	for _, char := range []byte("01234567") {
		assert.True(t, isOctalDigit(char), "character %q", char)
	}
	for _, char := range []byte("89aAfF") {
		assert.False(t, isOctalDigit(char), "character %q", char)
	}
}

func TestIsHexDigit(t *testing.T) {
	for _, char := range []byte("0123456789aAbBcCdDeEfF") {
		assert.True(t, isHexDigit(char), "character %q", char)
	}
	for _, char := range []byte("gGxX{}") {
		assert.False(t, isHexDigit(char), "character %q", char)
	}
}

func TestStartsPHPInterpolation(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		position int
		want     bool
	}{
		{name: "variable", source: "$name", want: true},
		{name: "braced variable", source: "${name}", want: true},
		{name: "offset", source: "value $name", position: 6, want: true},
		{name: "numeric dollar", source: "$5"},
		{name: "trailing dollar", source: "$"},
		{name: "ordinary character", source: "route"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, startsPHPInterpolation([]byte(test.source), test.position))
		})
	}
}

func TestReadBlockComment(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		start    int
		want     string
		wantNext int
		wantDoc  bool
	}{
		{name: "ordinary", data: "/* comment */tail", want: "/* comment */", wantNext: len("/* comment */")},
		{name: "documentation", data: "/** @Route */tail", want: "/** @Route */", wantNext: len("/** @Route */"), wantDoc: true},
		{name: "empty documentation", data: "/**/", want: "/**/", wantNext: 4, wantDoc: true},
		{name: "offset", data: "xx/* c */", start: 2, want: "/* c */", wantNext: len("xx/* c */")},
		{name: "unterminated ordinary", data: "/* comment", want: "/* comment", wantNext: len("/* comment")},
		{name: "unterminated documentation", data: "/** route", want: "/** route", wantNext: len("/** route"), wantDoc: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, next, doc := readBlockComment([]byte(test.data), test.start)

			assert.Equal(t, test.want, value)
			assert.Equal(t, test.wantNext, next)
			assert.Equal(t, test.wantDoc, doc)
		})
	}
}

func TestReadVariable(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		start    int
		want     string
		wantNext int
	}{
		{name: "name", data: "$handler;", want: "$handler", wantNext: 8},
		{name: "underscore and digits", data: "$_route2 ", want: "$_route2", wantNext: 8},
		{name: "non ASCII", data: "$é2 ", want: "$é2", wantNext: len("$é2")},
		{name: "offset", data: "xx$name;", start: 2, want: "$name", wantNext: 7},
		{name: "lone dollar", data: "$", wantNext: 1},
		{name: "digit cannot start", data: "$1", wantNext: 1},
		{name: "second dollar cannot start", data: "$$name", wantNext: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, next := readVariable([]byte(test.data), test.start)

			assert.Equal(t, test.want, value)
			assert.Equal(t, test.wantNext, next)
		})
	}
}

func TestReadName(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		start    int
		want     string
		wantNext int
	}{
		{name: "simple", data: "Route::get", want: "Route", wantNext: 5},
		{name: "qualified", data: `\App\Controller2::class`, want: `\App\Controller2`, wantNext: len(`\App\Controller2`)},
		{name: "underscore", data: "route_name ", want: "route_name", wantNext: 10},
		{name: "non ASCII", data: "Écoute ", want: "Écoute", wantNext: len("Écoute")},
		{name: "offset", data: "xxRoute;", start: 2, want: "Route", wantNext: 7},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, next := readName([]byte(test.data), test.start)

			assert.Equal(t, test.want, value)
			assert.Equal(t, test.wantNext, next)
		})
	}
}

func TestReadSymbol(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		start    int
		want     string
		wantNext int
	}{
		{name: "scope", data: "::get", want: "::", wantNext: 2},
		{name: "object", data: "->get", want: "->", wantNext: 2},
		{name: "array pair", data: "=>value", want: "=>", wantNext: 2},
		{name: "attribute", data: "#[Route", want: "#[", wantNext: 2},
		{name: "coalesce", data: "??value", want: "??", wantNext: 2},
		{name: "nullsafe", data: "?->get", want: "?->", wantNext: 3},
		{name: "single", data: "(value", want: "(", wantNext: 1},
		{name: "unrecognized pair", data: "?-value", want: "?", wantNext: 1},
		{name: "final byte", data: ";", want: ";", wantNext: 1},
		{name: "offset", data: "xx::get", start: 2, want: "::", wantNext: 4},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, next := readSymbol([]byte(test.data), test.start)

			assert.Equal(t, test.want, value)
			assert.Equal(t, test.wantNext, next)
		})
	}
}

func TestHasPrefixAt(t *testing.T) {
	source := []byte("Route::get")

	assert.True(t, hasPrefixAt(source, 0, "Route"))
	assert.True(t, hasPrefixAt(source, 5, "::"))
	assert.True(t, hasPrefixAt(source, len(source), ""))
	assert.False(t, hasPrefixAt(source, 0, "route"))
	assert.False(t, hasPrefixAt(source, -1, "Route"))
	assert.False(t, hasPrefixAt(source, len(source), "get"))
}

func TestSkipLine(t *testing.T) {
	tests := []struct {
		name  string
		data  string
		start int
		want  int
	}{
		{name: "stops before newline", data: "comment\nnext", want: len("comment")},
		{name: "stops at end", data: "comment", want: len("comment")},
		{name: "offset", data: "xxcomment\n", start: 2, want: len("xxcomment")},
		{name: "already at newline", data: "\nnext"},
		{name: "empty", data: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, skipLine([]byte(test.data), test.start))
		})
	}
}

func TestIsSpace(t *testing.T) {
	for _, character := range []byte{' ', '\t', '\r', '\n'} {
		assert.True(t, isSpace(character), "character %q", character)
	}
	for _, character := range []byte{'a', '\v', '\f', 0} {
		assert.False(t, isSpace(character), "character %q", character)
	}
}

func TestIsNameStart(t *testing.T) {
	for _, character := range []byte{'a', 'Z', '_', 0x80, 0xff} {
		assert.True(t, isNameStart(character), "character %#x", character)
	}
	for _, character := range []byte{'0', '-', '\\', '$', 0x7f} {
		assert.False(t, isNameStart(character), "character %#x", character)
	}
}

func TestIsNameContinue(t *testing.T) {
	for _, character := range []byte{'a', 'Z', '_', '0', '9', 0x80, 0xff} {
		assert.True(t, isNameContinue(character), "character %#x", character)
	}
	for _, character := range []byte{'-', '\\', '$', 0x7f} {
		assert.False(t, isNameContinue(character), "character %#x", character)
	}
}
