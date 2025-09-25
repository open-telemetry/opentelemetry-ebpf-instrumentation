// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package split

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testInput struct {
	token string
	eof   bool
}

func runTest(t *testing.T, in string, delim string, expected []testInput) {
	sp := NewIterator(in, delim)

	for _, e := range expected {
		w, eof := sp.Next()
		assert.Equal(t, e.eof, eof)
		assert.Equal(t, e.token, w)
	}
}

func TestSplitIterator(t *testing.T) {
	in := "ab;cd;;fg;"

	expected := []testInput{
		{token: "ab;", eof: false},
		{token: "cd;", eof: false},
		{token: ";", eof: false},
		{token: "fg;", eof: false},
		{token: "", eof: true},
	}

	runTest(t, in, ";", expected)
}

func TestSplitIterator_empty(t *testing.T) {
	in := ""

	expected := []testInput{
		{token: "", eof: true},
	}

	runTest(t, in, ";", expected)
}

func TestSplitIterator_lead_trail(t *testing.T) {
	in := "oo;oo"

	expected := []testInput{
		{token: "oo;", eof: false},
		{token: "oo", eof: false},
		{token: "", eof: true},
	}

	runTest(t, in, ";", expected)
}

func TestSplitIterator_multi(t *testing.T) {
	in := "one\r\nline\r\nper\r\ntime\r\n"

	expected := []testInput{
		{token: "one\r\n", eof: false},
		{token: "line\r\n", eof: false},
		{token: "per\r\n", eof: false},
		{token: "time\r\n", eof: false},
		{token: "", eof: true},
	}

	runTest(t, in, "\r\n", expected)
}

func TestSplitIterator_reset(t *testing.T) {
	in := "one|line|per|time|"

	sp := NewIterator(in, "|")

	w, eof := sp.Next()
	assert.False(t, eof)
	assert.Equal(t, "one|", w)

	w, eof = sp.Next()
	assert.False(t, eof)
	assert.Equal(t, "line|", w)

	sp.Reset()

	w, eof = sp.Next()
	assert.False(t, eof)
	assert.Equal(t, "one|", w)
}
