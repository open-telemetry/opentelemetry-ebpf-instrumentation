// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddSignedOffset(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address uint64
		offset  int64
		want    uint64
		ok      bool
	}{
		{"forward", 0x1000, 0x20, 0x1020, true},
		{"backward", 0x1000, -0x20, 0xfe0, true},
		{"zero at maximum", math.MaxUint64, 0, math.MaxUint64, true},
		{"reach maximum", math.MaxUint64 - 1, 1, math.MaxUint64, true},
		{"overflow", math.MaxUint64, 1, 0, false},
		{"reach zero", 1, -1, 0, true},
		{"underflow", 0, -1, 0, false},
		{"minimum signed offset", 1 << 63, math.MinInt64, 0, true},
		{"minimum signed offset underflow", 1<<63 - 1, math.MinInt64, 0, false},
		{"maximum signed offset", 1 << 63, math.MaxInt64, math.MaxUint64, true},
		{"maximum signed offset overflow", 1<<63 + 1, math.MaxInt64, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, ok := AddSignedOffset(tc.address, tc.offset)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.want, address)
		})
	}
}
