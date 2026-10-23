// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build go1.27 && goexperiment.simd && (amd64 || arm64)

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"simd"

	"go.opentelemetry.io/obi/pkg/internal/split"
)

// asciiIndexFold returns the first ASCII case-insensitive match, or -1.
func asciiIndexFold(s, substr []byte) int {
	n := len(substr)
	if n == 0 || len(s) < n {
		return -1
	}
	if equalFoldASCII(s[:n], substr) {
		return 0
	}

	// Current Go SIMD vectors contain at most 64 bytes; wider vectors use the fallback.
	var candidates [64]byte
	var zero simd.Uint8s
	width := zero.Len()
	limit := len(s) - n + 1
	if simd.Emulated() || width > len(candidates) || limit <= width {
		return asciiIndexFoldScalar(s, substr)
	}

	first, last := toLowerASCII(substr[0]), toLowerASCII(substr[n-1])
	var firstFold, lastFold byte
	if first >= 'a' && first <= 'z' {
		firstFold = 'a' - 'A'
	}
	if last >= 'a' && last <= 'z' {
		lastFold = 'a' - 'A'
	}
	firstMask, lastMask := simd.BroadcastUint8s(firstFold), simd.BroadcastUint8s(lastFold)
	firstByte, lastByte := simd.BroadcastUint8s(first), simd.BroadcastUint8s(last)
	one := simd.BroadcastUint8s(1)

	i := 1
	for ; i <= limit-width; i += width {
		starts := simd.LoadUint8s(s[i:]).Or(firstMask).Equal(firstByte)
		ends := simd.LoadUint8s(s[i+n-1:]).Or(lastMask).Equal(lastByte)
		one.Masked(starts.And(ends)).Store(candidates[:width])

		for j := 0; j < width; j++ {
			before, _, found := split.CutByte(candidates[j:width], 1)
			if !found {
				break
			}
			j += len(before)
			if equalFoldASCII(s[i+j:i+j+n], substr) {
				return i + j
			}
		}
	}

	if tail := asciiIndexFoldScalar(s[i:], substr); tail >= 0 {
		return i + tail
	}
	return -1
}
