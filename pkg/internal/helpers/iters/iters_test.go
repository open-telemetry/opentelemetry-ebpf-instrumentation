// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package iters

import (
	"iter"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmpty2(t *testing.T) {
	assert.Empty(t, maps.Collect(Empty2[int, int]()))
}

func TestConcat2_Map2Seq(t *testing.T) {
	var new = func(k []int, v []int) iter.Seq2[int, int] {
		return func(yield func(int, int) bool) {
			for i := 0; i < len(k) && i < len(v); i++ {
				if !yield(k[i], v[i]) {
					return
				}
			}
		}
	}
	var kvTuple = func(k, v int) [2]int { return [2]int{k, v} }

	concat := Concat2[int, int](
		new([]int{1, 2, 3}, []int{4, 5, 6}),
		new([]int{7, 8, 9}, []int{10, 11, 12}),
		new([]int{13, 14, 15}, []int{16, 17, 18}),
	)

	assert.Equal(t,
		[][2]int{{1, 4}, {2, 5}, {3, 6}, {7, 10}, {8, 11}, {9, 12}, {13, 16}, {14, 17}, {15, 18}},
		slices.Collect(Map2Seq(concat, kvTuple)))
	// checking that sequences can be iterated multiple times
	assert.Equal(t,
		[][2]int{{1, 4}, {2, 5}, {3, 6}, {7, 10}, {8, 11}, {9, 12}, {13, 16}, {14, 17}, {15, 18}},
		slices.Collect(Map2Seq(concat, kvTuple)))
}
