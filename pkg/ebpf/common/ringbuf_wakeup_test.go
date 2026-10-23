// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"math"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

const testRingBufSize = 1 << 20

func TestWakeupDataBytes(t *testing.T) {
	const maxWakeupDataBytes = testRingBufSize / 2
	httpInfoSize := unsafe.Sizeof(BPFHTTPInfo{})
	httpInfoRecord := uint32(httpInfoSize) + ringBufRecordHdrSize

	tests := []struct {
		name      string
		wakeupLen int
		expected  uint32
	}{
		{name: "zero", wakeupLen: 0, expected: 0},
		{name: "one", wakeupLen: 1, expected: 0},
		{name: "two", wakeupLen: 2, expected: 2 * httpInfoRecord},
		{name: "default", wakeupLen: 500, expected: 500 * httpInfoRecord},
		{name: "clamped", wakeupLen: 100_000, expected: maxWakeupDataBytes},
		{name: "uint32 overflow", wakeupLen: math.MaxUint32, expected: maxWakeupDataBytes},
		{name: "int overflow", wakeupLen: math.MaxInt, expected: maxWakeupDataBytes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, WakeupDataBytes(tt.wakeupLen, httpInfoSize, testRingBufSize))
		})
	}
}
