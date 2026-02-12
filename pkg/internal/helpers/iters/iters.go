// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package iters provides some helper functions for confortably working with iter.Seq
// and iter.Seq2.
// The code is copied from https://github.com/mariomac/iters, but we only keep there
// the functions we need to minimize external dependencies, in number and surface.

package iters // import "go.opentelemetry.io/obi/pkg/internal/helpers/iters"

import "iter"

// Empty2 returns an empty iter.Seq2
func Empty2[T1, T2 any]() iter.Seq2[T1, T2] {
	return func(_ func(T1, T2) bool) {}
}

// Concat2 creates a lazily concatenated iter.Seq2 whose elements are all the elements of the first
// provided iter.Seq2 followed by all the elements of the second provided iter.Seq2, followed by the
// elements of the third iter.Seq2 (if any), and so on.
func Concat2[K, V any](seqs ...iter.Seq2[K, V]) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for _, seq := range seqs {
			for k, v := range seq {
				if !yield(k, v) {
					return
				}
			}
		}
	}
}

// Map2Seq transforms an input iter.Seq2 into an iter.Seq by applying a mapper function to each element
func Map2Seq[K, V, O any](input iter.Seq2[K, V], mapper func(K, V) O) iter.Seq[O] {
	return func(yield func(O) bool) {
		for k, v := range input {
			if !yield(mapper(k, v)) {
				return
			}
		}
	}
}
