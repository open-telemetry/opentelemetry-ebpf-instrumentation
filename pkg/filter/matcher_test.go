// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"strconv"
	"strings"
	"testing"

	"github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatches(t *testing.T) {
	matcher := Matcher[string]{
		Glob:   glob.MustCompile("hello_*"),
		Getter: strings.Clone, // pseudo-identity function
	}

	assert.True(t, matcher.Matches("hello_my_friend"))
	assert.False(t, matcher.Matches("my_friend_hello"))
}

func TestMatches_Negated(t *testing.T) {
	matcher := Matcher[string]{
		Glob:   glob.MustCompile("hello_*"),
		Negate: true,
		Getter: strings.Clone, // pseudo-identity function
	}

	assert.False(t, matcher.Matches("hello_my_friend"))
	assert.True(t, matcher.Matches("my_friend_hello"))
}

func TestMatchDefinition_Validate(t *testing.T) {
	require.NoError(t, (&MatchDefinition{Match: "foo"}).Validate())
	require.NoError(t, (&MatchDefinition{NotMatch: "foo"}).Validate())
	require.Error(t, (&MatchDefinition{Match: "foo", NotMatch: "foo"}).Validate())
	require.Error(t, (&MatchDefinition{}).Validate())
}

func TestMatches_GreaterEquals(t *testing.T) {
	comp := 12
	matcher := Matcher[int]{
		GreaterEquals: &comp,
		Getter:        strconv.Itoa,
		Glob:          glob.MustCompile("*"),
	}
	assert.False(t, matcher.Matches(11))
	assert.True(t, matcher.Matches(12))
	assert.True(t, matcher.Matches(13))
}

func TestMatches_Equals(t *testing.T) {
	comp := 42
	matcher := Matcher[int]{
		Equals: &comp,
		Getter: strconv.Itoa,
		Glob:   glob.MustCompile("*"),
	}
	assert.True(t, matcher.Matches(42))
	assert.False(t, matcher.Matches(43))
}

func TestMatches_Equals_NonNumericString(t *testing.T) {
	comp := 42
	matcher := Matcher[string]{
		Equals: &comp,
		Getter: func(s string) string { return s }, // Returns the string as-is
		Glob:   glob.MustCompile("*"),
	}
	// Non-numeric strings should fail to parse and return false
	assert.False(t, matcher.Matches("hello"))
	assert.False(t, matcher.Matches("abc123"))
	assert.False(t, matcher.Matches("not a number"))
	// But valid numeric strings should work
	assert.True(t, matcher.Matches("42"))
	assert.False(t, matcher.Matches("43"))
}

func TestMatches_NotEquals(t *testing.T) {
	comp := 0
	matcher := Matcher[int]{
		NotEquals: &comp,
		Getter:    strconv.Itoa,
		Glob:      glob.MustCompile("*"),
	}
	assert.True(t, matcher.Matches(1))
	assert.False(t, matcher.Matches(0))
}

func TestMatches_LessEquals(t *testing.T) {
	comp := 100
	matcher := Matcher[int]{
		LessEquals: &comp,
		Getter:     strconv.Itoa,
		Glob:       glob.MustCompile("*"),
	}
	assert.True(t, matcher.Matches(100))
	assert.True(t, matcher.Matches(50))
	assert.False(t, matcher.Matches(101))
}

func TestMatches_GreaterThan(t *testing.T) {
	comp := 5
	matcher := Matcher[int]{
		GreaterThan: &comp,
		Getter:      strconv.Itoa,
		Glob:        glob.MustCompile("*"),
	}
	assert.True(t, matcher.Matches(6))
	assert.False(t, matcher.Matches(5))
	assert.False(t, matcher.Matches(4))
}

func TestMatches_LessThan(t *testing.T) {
	comp := 20
	matcher := Matcher[int]{
		LessThan: &comp,
		Getter:   strconv.Itoa,
		Glob:     glob.MustCompile("*"),
	}
	assert.True(t, matcher.Matches(19))
	assert.False(t, matcher.Matches(20))
	assert.False(t, matcher.Matches(21))
}

func TestMatches_MultipleComparisons(t *testing.T) {
	ge := 10
	le := 100
	matcher := Matcher[int]{
		GreaterEquals: &ge,
		LessEquals:    &le,
		Getter:        strconv.Itoa,
		Glob:          glob.MustCompile("*"),
	}
	assert.True(t, matcher.Matches(10))
	assert.True(t, matcher.Matches(50))
	assert.True(t, matcher.Matches(100))
	assert.False(t, matcher.Matches(9))
	assert.False(t, matcher.Matches(101))
}
