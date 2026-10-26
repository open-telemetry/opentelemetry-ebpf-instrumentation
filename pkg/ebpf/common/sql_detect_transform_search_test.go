// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestASCIIIndexFold(t *testing.T) {
	for _, tt := range []struct {
		name   string
		input  string
		needle string
		want   int
	}{
		{name: "empty", want: -1},
		{name: "empty_needle", input: "SELECT", want: -1},
		{name: "short_input", input: "SELEC", needle: "SELECT", want: -1},
		{name: "mixed_case", input: "xx sElEcT SELECT", needle: "select", want: 3},
		{name: "overlap", input: "xaaAa", needle: "AAA", want: 1},
		{name: "punctuation", input: strings.Repeat("[", 128) + "{", needle: "{", want: 128},
		{name: "reverse_punctuation", input: strings.Repeat("{", 128) + "[", needle: "[", want: 128},
		{name: "high_bit", input: strings.Repeat("\xc1", 128) + "a", needle: "A", want: 128},
		{name: "embedded_nul", input: "xx\x00select", needle: "\x00SELECT", want: 2},
		{name: "candidate_misses", input: strings.Repeat("SELETT", 128) + "select", needle: "SELECT", want: 768},
		{name: "truncated_tail", input: strings.Repeat("x", 128) + "SELEC", needle: "SELECT", want: -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, asciiIndexFold([]byte(tt.input), []byte(tt.needle)))
		})
	}
}

func TestASCIIIndexFoldBoundaries(t *testing.T) {
	for _, needle := range []string{"S", "DROP", "ALTER", "SELECT", "EXECUTE ", "[a]", "\x80\x00"} {
		for offset := range 130 {
			for _, suffix := range []int{0, 1, 15, 16, 31, 32, 63, 64} {
				input := bytes.Repeat([]byte{0xff}, offset)
				input = append(input, needle...)
				input = append(input, bytes.Repeat([]byte{0xff}, suffix)...)
				if got := asciiIndexFold(input, []byte(needle)); got != offset {
					t.Fatalf("needle=%q offset=%d suffix=%d: got %d", needle, offset, suffix, got)
				}
			}
		}
	}
}

func TestASCIIIndexFoldMatchesScalar(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for range 5000 {
		input := make([]byte, rng.IntN(512))
		needle := make([]byte, rng.IntN(96))
		for i := range input {
			input[i] = byte(rng.UintN(256))
		}
		for i := range needle {
			needle[i] = byte(rng.UintN(256))
		}
		if len(needle) > 0 && len(input) >= len(needle) && rng.IntN(2) == 0 {
			offset := rng.IntN(len(input) - len(needle) + 1)
			copy(input[offset:], needle)
			for i, c := range needle {
				input[offset+i] = toLowerASCII(c)
			}
		}
		require.Equal(t, asciiIndexFoldScalar(input, needle), asciiIndexFold(input, needle),
			"input=%x needle=%x", input, needle)
	}
}

func FuzzASCIIIndexFold(f *testing.F) {
	f.Add([]byte("xx sElEcT SELECT"), []byte("select"))
	f.Add([]byte(strings.Repeat("SELETT", 32)+"select"), []byte("SELECT"))
	f.Add([]byte(strings.Repeat("[", 64)+"{"), []byte("{"))
	f.Add([]byte("\x00\xff\x80"), []byte("\x80"))
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, input, needle []byte) {
		require.Equal(t, asciiIndexFoldScalar(input, needle), asciiIndexFold(input, needle))
	})
}
