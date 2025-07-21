// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter

import (
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
