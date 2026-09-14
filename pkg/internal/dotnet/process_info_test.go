// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func processInfo2Fixture(t *testing.T) []byte {
	t.Helper()
	payload, err := hex.DecodeString(
		"2a00000000000000" + // PID 42
			"000102030405060708090a0b0c0d0e0f" + // Opaque runtime cookie
			"040000006100700070000000" + // app
			"060000004c0069006e00750078000000" + // Linux
			"040000007800360034000000" + // x64
			"040000006100700070000000" + // app
			"0700000038002e0030002e00330030000000", // 8.0.30
	)
	require.NoError(t, err)
	return payload
}

func TestDecodeProcessInfo2(t *testing.T) {
	info, err := decodeProcessInfo2(processInfo2Fixture(t))
	require.NoError(t, err)
	require.Equal(t, processInfo{
		PID:                42,
		RuntimeCookie:      [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		CommandLine:        "app",
		OperatingSystem:    "Linux",
		Architecture:       "x64",
		EntrypointAssembly: "app",
		CLRVersion:         "8.0.30",
	}, info)
}

func TestDecodeProcessInfo2Truncated(t *testing.T) {
	payload := processInfo2Fixture(t)
	for length := range len(payload) {
		info, err := decodeProcessInfo2(payload[:length])
		require.Error(t, err, "payload length %d", length)
		require.Zero(t, info, "payload length %d", length)
	}
}

func TestDecodeProcessInfo2TrailingData(t *testing.T) {
	info, err := decodeProcessInfo2(append(processInfo2Fixture(t), 0))
	require.ErrorContains(t, err, "unexpected trailing bytes")
	require.Zero(t, info)
}

func TestDecodeProcessInfo2InvalidStringLength(t *testing.T) {
	payload := processInfo2Fixture(t)
	copy(payload[24:28], []byte{0xff, 0xff, 0xff, 0xff})
	info, err := decodeProcessInfo2(payload)
	require.ErrorContains(t, err, "reading diagnostic command line")
	require.Zero(t, info)
}

func TestReadIPCString(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		want string
	}{
		{"zero length", "00000000", ""},
		{"empty terminated", "010000000000", ""},
		{"ASCII", "0200000041000000", "A"},
		{"non-ASCII", "02000000e9000000", "é"},
		{"surrogate pair", "030000003dd800de0000", "\U0001f600"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			require.NoError(t, err)
			reader := bytes.NewReader(append(wire, 0xab))
			value, err := readIPCString(reader)
			require.NoError(t, err)
			require.Equal(t, tc.want, value)
			require.Equal(t, 1, reader.Len())
		})
	}
}

func TestReadIPCStringMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
	}{
		{"missing length", ""},
		{"truncated length", "010000"},
		{"oversized length", "ffffffff"},
		{"missing data", "01000000"},
		{"partial code unit", "0100000000"},
		{"missing terminator", "010000004100"},
		{"unpaired high surrogate", "0200000000d80000"},
		{"unpaired low surrogate", "0200000000dc0000"},
		{"two high surrogates", "0300000000d800d80000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			require.NoError(t, err)
			value, err := readIPCString(bytes.NewReader(wire))
			require.Error(t, err)
			require.Empty(t, value)
		})
	}
}
