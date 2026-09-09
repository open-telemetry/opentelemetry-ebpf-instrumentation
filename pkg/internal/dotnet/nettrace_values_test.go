// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadNetTraceValues(t *testing.T) {
	fields := []netTraceField{{
		Name: "Payload", Type: netTraceTypeObject,
		Fields: []netTraceField{
			{Name: "Name", Type: netTraceTypeString},
			{Name: "Increment", Type: netTraceTypeDouble},
			{Name: "IntervalSec", Type: netTraceTypeSingle},
			{Name: "Count", Type: netTraceTypeInt32},
		},
	}}
	// UTF-16 "gc", double 3, float 1, and signed int32 -2.
	wire, err := hex.DecodeString("67006300000000000000000008400000803ffeffffff")
	require.NoError(t, err)
	reader := bytes.NewReader(append(bytes.Clone(wire), 0xab))
	values, err := readNetTraceValues(reader, fields)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"Payload": map[string]any{
		"Name": "gc", "Increment": float64(3), "IntervalSec": float32(1), "Count": int32(-2),
	}}, values)
	require.Equal(t, 1, reader.Len())
	for length := range len(wire) {
		values, err := readNetTraceValues(bytes.NewReader(wire[:length]), fields)
		require.Error(t, err, "truncated at byte %d", length)
		require.Nil(t, values)
	}
	t.Run("unsupported type", func(t *testing.T) {
		_, err := readNetTraceValues(bytes.NewReader(nil), []netTraceField{{Name: "x", Type: netTraceTypeBoolean}})
		require.ErrorContains(t, err, "unsupported NetTrace value type")
	})
	t.Run("duplicate name", func(t *testing.T) {
		_, err := readNetTraceValues(bytes.NewReader(make([]byte, 8)), []netTraceField{
			{Name: "x", Type: netTraceTypeInt32},
			{Name: "x", Type: netTraceTypeInt32},
		})
		require.ErrorContains(t, err, "duplicate NetTrace field name")
	})
}
