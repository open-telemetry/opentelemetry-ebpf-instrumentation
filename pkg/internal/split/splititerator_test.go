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
	sp := NewStringIterator(in, delim)

	for _, e := range expected {
		w, eof := sp.Next()
		assert.Equal(t, e.eof, eof)
		assert.Equal(t, e.token, w)
	}
}

type bytesTestInput struct {
	token []byte
	eof   bool
}

func runBytesTest(t *testing.T, in []byte, delim []byte, expected []bytesTestInput) {
	sp := NewBytesIterator(in, delim)

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

	sp := NewStringIterator(in, "|")

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

func TestBytesIterator(t *testing.T) {
	in := []byte("ab;cd;;fg;")

	expected := []bytesTestInput{
		{token: []byte("ab;"), eof: false},
		{token: []byte("cd;"), eof: false},
		{token: []byte(";"), eof: false},
		{token: []byte("fg;"), eof: false},
		{token: nil, eof: true},
	}

	runBytesTest(t, in, []byte(";"), expected)
}

func TestBytesIterator_empty(t *testing.T) {
	runBytesTest(t, []byte{}, []byte(";"), []bytesTestInput{{token: nil, eof: true}})
}

func TestBytesIterator_lead_trail(t *testing.T) {
	in := []byte("oo;oo")

	expected := []bytesTestInput{
		{token: []byte("oo;"), eof: false},
		{token: []byte("oo"), eof: false},
		{token: nil, eof: true},
	}

	runBytesTest(t, in, []byte(";"), expected)
}

func TestBytesIterator_multi(t *testing.T) {
	in := []byte("one\r\nline\r\nper\r\ntime\r\n")

	expected := []bytesTestInput{
		{token: []byte("one\r\n"), eof: false},
		{token: []byte("line\r\n"), eof: false},
		{token: []byte("per\r\n"), eof: false},
		{token: []byte("time\r\n"), eof: false},
		{token: nil, eof: true},
	}

	runBytesTest(t, in, []byte("\r\n"), expected)
}

func TestStringIterator_emptyDelim_panics(t *testing.T) {
	assert.Panics(t, func() { NewStringIterator("abc", "") })
}

func TestBytesIterator_emptyDelim_panics(t *testing.T) {
	assert.Panics(t, func() { NewBytesIterator([]byte("abc"), []byte{}) })
}

func TestBytesIterator_reset(t *testing.T) {
	in := []byte("one|line|per|time|")

	sp := NewBytesIterator(in, []byte("|"))

	w, eof := sp.Next()
	assert.False(t, eof)
	assert.Equal(t, []byte("one|"), w)

	w, eof = sp.Next()
	assert.False(t, eof)
	assert.Equal(t, []byte("line|"), w)

	sp.Reset()

	w, eof = sp.Next()
	assert.False(t, eof)
	assert.Equal(t, []byte("one|"), w)
}
