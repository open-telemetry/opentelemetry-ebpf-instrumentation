// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package split provides a generic Iterator for zero-copy splitting of
// strings and byte slices.
package split // import "go.opentelemetry.io/obi/pkg/internal/split"

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCutByte(t *testing.T) {
	for _, tc := range []string{"assd", ":ssd", "adsfasf:", "adfsdsfa:lsadjflkdas", "", ":"} {
		t.Run(tc, func(t *testing.T) {
			cbl, cbr, cbf := CutByte([]byte(tc), ':')
			cl, cr, cf := bytes.Cut([]byte(tc), []byte{':'})
			assert.Equal(t, cl, cbl)
			assert.Equal(t, cr, cbr)
			assert.Equal(t, cf, cbf)
		})
	}
}

func TestStringCutByte(t *testing.T) {
	for _, tc := range []string{"assd", ":ssd", "adsfasf:", "adfsdsfa:lsadjflkdas", "", ":"} {
		t.Run(tc, func(t *testing.T) {
			cbl, cbr, cbf := StringsCutByte(tc, ':')
			cl, cr, cf := strings.Cut(tc, ":")
			assert.Equal(t, cl, cbl)
			assert.Equal(t, cr, cbr)
			assert.Equal(t, cf, cbf)
		})
	}
}

func BenchmarkCut(b *testing.B) {
	var sep = byte(':')
	var sepSl = []byte(":")
	var cut = func(b *testing.B, sentence []byte) {
		for range b.N {
			bytes.Cut(sentence, sepSl)
		}
	}
	var cutByte = func(b *testing.B, sentence []byte) {
		for range b.N {
			CutByte(sentence, sep)
		}
	}
	b.Run("bytes.Cut", func(b *testing.B) {
		b.Run("early find", func(b *testing.B) {
			cut(b, []byte("abcd:cdefg"))
		})
		b.Run("late find", func(b *testing.B) {
			cut(b, []byte("abcasdlfkjsadlkfjasdñlkfjdsañlkfjlñadkjfñalskjfdñlaskjfñlaksdjfñldaskjfdlñsadskfhdskjfhdsjgfshjdgfajhsgfjhsad:cdefg"))
		})
		b.Run("never found", func(b *testing.B) {
			cut(b, []byte("asldkjhflaksdjflaksdjflkajflkajlkfjadslfkjasdflkajsdlfkjasdlkfjasdklfjalksdjfklsadjfklajdsklfadjsflkadsjfdlkjafdsklfjdalkdf"))
		})
	})
	b.Run("CutByte", func(b *testing.B) {
		b.Run("early find", func(b *testing.B) {
			cutByte(b, []byte("abcd:cdefg"))
		})
		b.Run("late find", func(b *testing.B) {
			cutByte(b, []byte("abcasdlfkjsadlkfjasdñlkfjdsañlkfjlñadkjfñalskjfdñlaskjfñlaksdjfñldaskjfdlñsadskfhdskjfhdsjgfshjdgfajhsgfjhsad:cdefg"))
		})
		b.Run("never found", func(b *testing.B) {
			cutByte(b, []byte("asldkjhflaksdjflaksdjflkajflkajlkfjadslfkjasdflkajsdlfkjasdlkfjasdklfjalksdjfklsadjfklajdsklfadjsflkadsjfdlkjafdsklfjdalkdf"))
		})
	})
}

func BenchmarkStringsCut(b *testing.B) {
	const sep = ':'
	const sepStr = ":"
	var cut = func(b *testing.B, sentence string) {
		for range b.N {
			strings.Cut(sentence, sepStr)
		}
	}
	var stringsCutByte = func(b *testing.B, sentence string) {
		for range b.N {
			StringsCutByte(sentence, sep)
		}
	}
	b.Run("strings.Cut", func(b *testing.B) {
		b.Run("early find", func(b *testing.B) {
			cut(b, "abcd:cdefg")
		})
		b.Run("late find", func(b *testing.B) {
			cut(b, "abcasdlfkjsadlkfjasdñlkfjdsañlkfjlñadkjfñalskjfdñlaskjfñlaksdjfñldaskjfdlñsadskfhdskjfhdsjgfshjdgfajhsgfjhsad:cdefg")
		})
		b.Run("never found", func(b *testing.B) {
			cut(b, "asldkjhflaksdjflaksdjflkajflkajlkfjadslfkjasdflkajsdlfkjasdlkfjasdklfjalksdjfklsadjfklajdsklfadjsflkadsjfdlkjafdsklfjdalkdf")
		})
	})
	b.Run("StringsCutByte", func(b *testing.B) {
		b.Run("early find", func(b *testing.B) {
			stringsCutByte(b, string([]byte("abcd:cdefg")))
		})
		b.Run("late find", func(b *testing.B) {
			stringsCutByte(b, string([]byte("abcasdlfkjsadlkfjasdñlkfjdsañlkfjlñadkjfñalskjfdñlaskjfñlaksdjfñldaskjfdlñsadskfhdskjfhdsjgfshjdgfajhsgfjhsad:cdefg")))
		})
		b.Run("never found", func(b *testing.B) {
			stringsCutByte(b, string([]byte("asldkjhflaksdjflaksdjflkajflkajlkfjadslfkjasdflkajsdlfkjasdlkfjasdklfjalksdjfklsadjfklajdsklfadjsflkadsjfdlkjafdsklfjdalkdf")))
		})
	})
}
