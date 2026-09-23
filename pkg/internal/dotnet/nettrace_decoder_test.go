// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNetTraceSequenceChecks(t *testing.T) {
	var decoder netTraceDecoder
	require.NoError(t, decoder.checkSequence(42, 100, true))
	require.NoError(t, decoder.checkSequence(99, 7, true))
	require.NoError(t, decoder.checkSequence(42, 101, true))
	require.ErrorContains(t, decoder.checkSequence(42, 103, true), "event loss")
	require.Equal(t, uint32(101), decoder.sequences[42], "rejected events must not advance the sequence")
	require.ErrorContains(t, decoder.checkSequence(42, 101, true), "event loss")
	require.NoError(t, decoder.checkSequence(1, ^uint32(0), true))
	require.NoError(t, decoder.checkSequence(1, 0, true))

	checkpoint := binary.LittleEndian.AppendUint64(nil, 1234)
	checkpoint = binary.LittleEndian.AppendUint32(checkpoint, 1)
	checkpoint = binary.LittleEndian.AppendUint64(checkpoint, 42)
	checkpoint = binary.LittleEndian.AppendUint32(checkpoint, 101)
	require.NoError(t, decoder.checkSequencePoint(checkpoint))
	binary.LittleEndian.PutUint32(checkpoint[20:], 102)
	require.ErrorContains(t, decoder.checkSequencePoint(checkpoint), "event loss")
	for size := range len(checkpoint) {
		require.Error(t, decoder.checkSequencePoint(checkpoint[:size]))
	}
	var unseen netTraceDecoder
	require.NoError(t, unseen.checkSequencePoint(checkpoint))
	require.NoError(t, unseen.checkSequence(42, 103, true))
}

func TestDecodeEventBlockRejectsUncompressed(t *testing.T) {
	// A 20-byte block header with compression disabled.
	payload, err := hex.DecodeString("1400000000000000000000000000000000000000")
	require.NoError(t, err)
	for _, name := range []string{"EventBlock", "MetadataBlock"} {
		t.Run(name, func(t *testing.T) {
			var decoder netTraceDecoder
			_, err := decoder.decodeEventBlock(name, payload)
			require.ErrorContains(t, err, "uncompressed NetTrace event blocks are unsupported")
		})
	}
}

func TestReadRuntimeCounters(t *testing.T) {
	const signatures = "Nettrace\x14\x00\x00\x00!FastSerialization.1"
	const header = "\x05\x05\x01\x04\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00Trace\x06"
	payload, err := hex.DecodeString("ea070900020008000a00070016009003fdc9c9107649000000ca9a3b00000000080000000f0000001000000040420f0006")
	require.NoError(t, err)
	wire := append([]byte(signatures+header), payload...)
	consume := func(runtimeCounter) error {
		t.Error("empty trace must not deliver a counter")
		return errors.New("unexpected counter in empty trace")
	}
	t.Run("explicit end marker", func(t *testing.T) {
		input := append(bytes.Clone(wire), 1)
		require.NoError(t, readRuntimeCounters(bytes.NewReader(input), 15, consume))
	})
	t.Run("unexpected EOF", func(t *testing.T) {
		require.ErrorIs(t, readRuntimeCounters(bytes.NewReader(wire), 15, consume), io.EOF)
	})
	t.Run("wrong process", func(t *testing.T) {
		require.ErrorContains(t, readRuntimeCounters(bytes.NewReader(wire), 42, consume),
			"does not match expected PID")
	})
}
