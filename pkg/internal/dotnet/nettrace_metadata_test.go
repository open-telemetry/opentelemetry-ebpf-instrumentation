// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadNetTraceFields(t *testing.T) {
	// One object named Payload containing a double named Mean.
	wire, err := hex.DecodeString("0100000001000000010000000e0000004d00650061006e0000005000610079006c006f00610064000000")
	require.NoError(t, err)
	reader := bytes.NewReader(append(bytes.Clone(wire), 0xab))
	fields, err := readNetTraceFields(reader, 0)
	require.NoError(t, err)
	require.Equal(t, []netTraceField{{
		Name: "Payload", Type: 1,
		Fields: []netTraceField{{Name: "Mean", Type: 14}},
	}}, fields)
	require.Equal(t, 1, reader.Len())
	for length := range len(wire) {
		fields, err := readNetTraceFields(bytes.NewReader(wire[:length]), 0)
		require.Error(t, err, "truncated at byte %d", length)
		require.Nil(t, fields)
	}
	t.Run("empty field list", func(t *testing.T) {
		fields, err := readNetTraceFields(bytes.NewReader([]byte{0, 0, 0, 0}), 0)
		require.NoError(t, err)
		require.Empty(t, fields)
	})
	t.Run("invalid count", func(t *testing.T) {
		for _, count := range []uint32{maximumNetTraceFields + 1, 0xffffffff} {
			bad := binary.LittleEndian.AppendUint32(nil, count)
			_, err := readNetTraceFields(bytes.NewReader(bad), 0)
			require.ErrorContains(t, err, "invalid NetTrace field count")
		}
	})
	t.Run("unsupported type", func(t *testing.T) {
		bad := bytes.Clone(wire)
		binary.LittleEndian.PutUint32(bad[4:], 19)
		_, err := readNetTraceFields(bytes.NewReader(bad), 0)
		require.ErrorContains(t, err, "unsupported NetTrace field type")
	})
	t.Run("nested object hits depth limit", func(t *testing.T) {
		_, err := readNetTraceFields(bytes.NewReader(wire), maximumNetTraceFieldDepth-1)
		require.ErrorContains(t, err, "nesting exceeds decoder limit")
	})
}

func TestReadNetTraceMetadataHeader(t *testing.T) {
	wire := binary.LittleEndian.AppendUint32(nil, 7)
	for _, character := range "System.Runtime\x00" {
		wire = binary.LittleEndian.AppendUint16(wire, uint16(character))
	}
	wire = binary.LittleEndian.AppendUint32(wire, 1)
	for _, character := range "EventCounters\x00" {
		wire = binary.LittleEndian.AppendUint16(wire, uint16(character))
	}
	wire = binary.LittleEndian.AppendUint64(wire, 2)
	wire = binary.LittleEndian.AppendUint32(wire, 0)
	wire = binary.LittleEndian.AppendUint32(wire, 4)
	t.Run("identity leaves field definitions unread", func(t *testing.T) {
		reader := bytes.NewReader(append(bytes.Clone(wire), 1, 0, 0, 0))
		header, err := readNetTraceMetadataHeader(reader)
		require.NoError(t, err)
		require.Equal(t, netTraceMetadataHeader{
			MetadataID: 7, ProviderName: "System.Runtime", EventID: 1,
			EventName: "EventCounters", Keywords: 2, Version: 0, Level: 4,
		}, header)
		require.Equal(t, 4, reader.Len())
	})
	t.Run("truncated header", func(t *testing.T) {
		for length := range len(wire) {
			header, err := readNetTraceMetadataHeader(bytes.NewReader(wire[:length]))
			require.Error(t, err, "truncated at byte %d", length)
			require.Zero(t, header)
		}
	})
	t.Run("reserved metadata ID", func(t *testing.T) {
		bad := bytes.Clone(wire)
		binary.LittleEndian.PutUint32(bad, 0)
		header, err := readNetTraceMetadataHeader(bytes.NewReader(bad))
		require.ErrorContains(t, err, "metadata ID zero is reserved")
		require.Zero(t, header)
	})
}

func TestReadNetTraceString(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		want string
	}{
		{"empty", "\x00\x00", ""},
		{"ASCII", "N\x00a\x00m\x00e\x00\x00\x00", "Name"},
		{"Unicode", "\xe9\x00\x3d\xd8\x00\xde\x00\x00", "é😀"},
		{"replacement character", "\xfd\xff\x00\x00", "�"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewBufferString(tc.wire + "remaining")
			bounded := bytes.NewReader(reader.Bytes())
			got, err := readNetTraceString(bounded)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			require.Equal(t, len("remaining"), bounded.Len())
		})
	}
	for _, wire := range []string{
		"", "A", "A\x00", "A\x00\x00",
		"\x00\xd8", "\x00\xd8\x00\x00",
		"\x00\xdc\x00\x00", "\x00\xd8A\x00\x00\x00",
	} {
		got, err := readNetTraceString(bytes.NewReader([]byte(wire)))
		require.Error(t, err, "invalid string %x", wire)
		require.Empty(t, got)
	}
}
