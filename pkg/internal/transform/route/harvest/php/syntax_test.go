// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchingClosingToken(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		start  int
		want   int
	}{
		{name: "simple", values: []string{"(", "value", ")"}, want: 2},
		{name: "nested", values: []string{"(", "(", ")", ")"}, want: 3},
		{name: "offset", values: []string{"call", "(", "value", ")"}, start: 1, want: 3},
		{name: "ignores other delimiter types", values: []string{"(", "[", ")", "]"}, want: 2},
		{name: "wrong opening", values: []string{"value", ")"}, want: -1},
		{name: "negative start", values: []string{"(", ")"}, start: -1, want: -1},
		{name: "start past end", values: []string{"(", ")"}, start: 2, want: -1},
		{name: "unmatched", values: []string{"(", "("}, want: -1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, matchingClosingToken(symbolTokens(test.values...), test.start, "(", ")"))
		})
	}
}

func TestMatchingClosingTokenIgnoresStringLiteralsThatLookLikeDelimiters(t *testing.T) {
	tokens := []token{
		{kind: tokenSymbol, value: "("},
		{kind: tokenString, value: "("},
		{kind: tokenSymbol, value: ","},
		{kind: tokenString, value: "value"},
		{kind: tokenSymbol, value: ")"},
	}

	assert.Equal(t, 4, matchingClosingToken(tokens, 0, "(", ")"))
}

func TestMatchingClosingTokenRejectsNonSymbolStart(t *testing.T) {
	tokens := []token{{kind: tokenString, value: "("}, {kind: tokenSymbol, value: ")"}}

	assert.Equal(t, -1, matchingClosingToken(tokens, 0, "(", ")"))
}

func TestCallArguments(t *testing.T) {
	t.Run("splits only top level arguments", func(t *testing.T) {
		tokens := lexPHP([]byte(`call('one', nested('two', 'three'), ['four', 'five'])`))

		arguments := callArguments(tokens, 1)

		assert.Equal(t, [][]string{
			{"one"},
			{"nested", "(", "two", ",", "three", ")"},
			{"[", "four", ",", "five", "]"},
		}, tokenValues(arguments))
	})

	t.Run("empty list", func(t *testing.T) {
		tokens := lexPHP([]byte(`call()`))

		assert.Empty(t, callArguments(tokens, 1))
	})

	t.Run("wrong opening", func(t *testing.T) {
		assert.Nil(t, callArguments(symbolTokens("name", ")"), 0))
	})

	t.Run("unmatched", func(t *testing.T) {
		assert.Nil(t, callArguments(symbolTokens("name", "(", "value"), 1))
	})

	t.Run("string argument matching a delimiter character", func(t *testing.T) {
		tokens := lexPHP([]byte(`call('(', 'value')`))

		arguments := callArguments(tokens, 1)

		assert.Equal(t, [][]string{{"("}, {"value"}}, tokenValues(arguments))
	})
}

func TestSplitOnTopLevelCommas(t *testing.T) {
	t.Run("top level commas", func(t *testing.T) {
		groups := splitOnTopLevelCommas(symbolTokens("one", ",", "two", ",", "three"))

		assert.Equal(t, [][]string{{"one"}, {"two"}, {"three"}}, tokenValues(groups))
	})

	t.Run("nested commas", func(t *testing.T) {
		groups := splitOnTopLevelCommas(symbolTokens(
			"first", ",",
			"(", "a", ",", "b", ")", ",",
			"[", "a", ",", "b", "]", ",",
			"{", "a", ",", "b", "}", ",",
			"#[", "Route", "(", "a", ",", "b", ")", "]", ",",
			"last",
		))

		assert.Equal(t, [][]string{
			{"first"},
			{"(", "a", ",", "b", ")"},
			{"[", "a", ",", "b", "]"},
			{"{", "a", ",", "b", "}"},
			{"#[", "Route", "(", "a", ",", "b", ")", "]"},
			{"last"},
		}, tokenValues(groups))
	})

	t.Run("empty", func(t *testing.T) {
		assert.Nil(t, splitOnTopLevelCommas(nil))
	})

	t.Run("trailing comma", func(t *testing.T) {
		groups := splitOnTopLevelCommas(symbolTokens("one", ","))

		assert.Equal(t, [][]string{{"one"}}, tokenValues(groups))
	})

	t.Run("ignores string literals that look like delimiters", func(t *testing.T) {
		tokens := []token{
			{kind: tokenString, value: "("},
			{kind: tokenSymbol, value: ","},
			{kind: tokenString, value: ","},
		}

		groups := splitOnTopLevelCommas(tokens)

		assert.Equal(t, [][]token{
			{{kind: tokenString, value: "("}},
			{{kind: tokenString, value: ","}},
		}, groups)
	})
}

func TestStaticStringArgument(t *testing.T) {
	arguments := [][]token{
		{{kind: tokenString, value: "/users"}},
		{{kind: tokenName, value: "$dynamic"}},
		{
			{kind: tokenString, value: "/users"},
			{kind: tokenSymbol, value: "."},
			{kind: tokenString, value: "/active"},
		},
	}

	value, ok := staticStringArgument(arguments, 0)
	assert.True(t, ok)
	assert.Equal(t, "/users", value)

	for _, index := range []int{-1, 1, 2, 3} {
		value, ok = staticStringArgument(arguments, index)
		assert.False(t, ok, "index %d", index)
		assert.Empty(t, value, "index %d", index)
	}

	value, ok = staticStringArgument(nil, 0)
	assert.False(t, ok)
	assert.Empty(t, value)
}

func symbolTokens(values ...string) []token {
	tokens := make([]token, 0, len(values))
	for _, value := range values {
		tokens = append(tokens, token{kind: tokenSymbol, value: value})
	}
	return tokens
}

func tokenValues(groups [][]token) [][]string {
	values := make([][]string, 0, len(groups))
	for _, group := range groups {
		row := make([]string, 0, len(group))
		for _, tok := range group {
			row = append(row, tok.value)
		}
		values = append(values, row)
	}
	return values
}
