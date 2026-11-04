// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/require"
)

func TestJavaHTTP1CompareAndSwapProbeEncoding(t *testing.T) {
	atomics := 0
	for _, instruction := range javaHTTP1CompareAndSwapProbe() {
		if instruction.OpCode.AtomicOp() != asm.CmpXchg {
			continue
		}
		atomics++
		var encoded bytes.Buffer
		_, err := instruction.Marshal(&encoded, binary.LittleEndian)
		require.NoError(t, err)
		// The kernel reads CMPXCHG | BPF_FETCH (0xf1) from the immediate
		// field. An immediate of zero instead probes legacy atomic ADD.
		require.Equal(t, uint32(0xf1), binary.LittleEndian.Uint32(encoded.Bytes()[4:]))
	}
	require.Equal(t, 1, atomics)
}
