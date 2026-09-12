// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"io"
	"strconv"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

func TestReadIPCHeader(t *testing.T) {
	// A 276-byte message checks that the two-byte size is little endian.
	reader := bytes.NewReader([]byte("DOTNET_IPC_V1\x00\x14\x01\xff\x00\x00\x00payload"))
	header, err := readIPCHeader(reader)
	require.NoError(t, err)
	require.Equal(t, uint16(276), header.Size)
	require.Equal(t, uint8(0xff), header.CommandSet)
	require.Zero(t, header.CommandID)
	require.Zero(t, header.Reserved)
	require.Equal(t, len("payload"), reader.Len())
}

func TestReadIPCHeaderRejectsInvalidFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		err  string
	}{
		{"magic", "INVALID_IPC_V1\x00\x14\x00\xff\x00\x00\x00", "invalid diagnostic IPC magic"},
		{"version", "DOTNET_IPC_V2\x00\x14\x00\xff\x00\x00\x00", "invalid diagnostic IPC magic"},
		{"terminator", "DOTNET_IPC_V1!\x14\x00\xff\x00\x00\x00", "invalid diagnostic IPC magic"},
		{"zero size", "DOTNET_IPC_V1\x00\x00\x00\xff\x00\x00\x00", "smaller than its header"},
		{"short size", "DOTNET_IPC_V1\x00\x13\x00\xff\x00\x00\x00", "smaller than its header"},
		{"reserved low byte", "DOTNET_IPC_V1\x00\x14\x00\xff\x00\x01\x00", "reserved field is nonzero"},
		{"reserved high byte", "DOTNET_IPC_V1\x00\x14\x00\xff\x00\x00\x01", "reserved field is nonzero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header, err := readIPCHeader(bytes.NewBufferString(tc.wire))
			require.ErrorContains(t, err, tc.err)
			require.Zero(t, header)
		})
	}
}

func TestReadIPCHeaderTruncated(t *testing.T) {
	wire := []byte("DOTNET_IPC_V1\x00\x14\x00\xff\x00\x00\x00")
	for length := range len(wire) {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			header, err := readIPCHeader(bytes.NewReader(wire[:length]))
			if length == 0 {
				require.ErrorIs(t, err, io.EOF)
			} else {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			}
			require.Zero(t, header)
		})
	}
}

func TestReadIPCMessagePreservesContinuation(t *testing.T) {
	wire := bytes.NewBufferString("DOTNET_IPC_V1\x00\x1c\x00\xff\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08Nettrace")
	message, err := readIPCMessage(iotest.OneByteReader(wire))
	require.NoError(t, err)
	require.Equal(t, uint16(28), message.Header.Size)
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, message.Payload)
	require.Equal(t, "Nettrace", wire.String())
}

func TestReadIPCMessageEmptyPayload(t *testing.T) {
	message, err := readIPCMessage(bytes.NewBufferString("DOTNET_IPC_V1\x00\x14\x00\xff\x00\x00\x00"))
	require.NoError(t, err)
	require.Empty(t, message.Payload)
}

func TestReadIPCMessageMaximumSize(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 65535-20)
	wire := bytes.NewBufferString("DOTNET_IPC_V1\x00\xff\xff\xff\x00\x00\x00")
	wire.Write(payload)
	message, err := readIPCMessage(wire)
	require.NoError(t, err)
	require.Equal(t, payload, message.Payload)
}

func TestReadIPCMessageTruncatedPayload(t *testing.T) {
	message, err := readIPCMessage(bytes.NewBufferString("DOTNET_IPC_V1\x00\x18\x00\xff\x00\x00\x00ab"))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Zero(t, message)
}

func TestReadIPCMessageRejectsInvalidHeader(t *testing.T) {
	wire := bytes.NewBufferString("DOTNET_IPC_V1\x00\x13\x00\xff\x00\x00\x00payload")
	message, err := readIPCMessage(wire)
	require.ErrorContains(t, err, "smaller than its header")
	require.Zero(t, message)
	require.Equal(t, "payload", wire.String())
}

func TestEncodeIPCMessageProcessInfo2(t *testing.T) {
	message, err := encodeIPCMessage(0x04, 0x04, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("DOTNET_IPC_V1\x00\x14\x00\x04\x04\x00\x00"), message)
}

func TestEncodeIPCMessageWithPayload(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	message, err := encodeIPCMessage(0x02, 0x01, payload)
	require.NoError(t, err)
	require.Equal(t, []byte("DOTNET_IPC_V1\x00\x1c\x00\x02\x01\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08"), message)

	// The encoded request owns its payload even if the caller reuses its buffer.
	payload[0] = 0xff
	require.Equal(t, byte(1), message[20])
}

func TestEncodeIPCMessageSizeLimit(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 65535-20)
	message, err := encodeIPCMessage(0x02, 0x01, payload)
	require.NoError(t, err)
	require.Len(t, message, 65535)
	require.Equal(t, []byte("DOTNET_IPC_V1\x00\xff\xff\x02\x01\x00\x00"), message[:20])
	require.Equal(t, payload, message[20:])

	message, err = encodeIPCMessage(0x02, 0x01, append(payload, 0xab))
	require.ErrorContains(t, err, "exceeds the message size limit")
	require.Nil(t, message)
}

func TestReadIPCResponse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wire    string
		payload string
		err     string
	}{
		{
			name:    "success",
			wire:    "DOTNET_IPC_V1\x00\x18\x00\xff\x00\x00\x00abcd",
			payload: "abcd",
		},
		{
			name: "empty success",
			wire: "DOTNET_IPC_V1\x00\x14\x00\xff\x00\x00\x00",
		},
		{
			name: "unsupported command",
			wire: "DOTNET_IPC_V1\x00\x18\x00\xff\xff\x00\x00\x85\x13\x13\x80",
			err:  "HRESULT 0x80131385",
		},
		{
			name: "runtime not ready",
			wire: "DOTNET_IPC_V1\x00\x18\x00\xff\xff\x00\x00\x71\x13\x13\x80",
			err:  "HRESULT 0x80131371",
		},
		{
			name: "wrong command set",
			wire: "DOTNET_IPC_V1\x00\x14\x00\x04\x00\x00\x00",
			err:  "unexpected diagnostic IPC response command set",
		},
		{
			name: "unknown response command",
			wire: "DOTNET_IPC_V1\x00\x14\x00\xff\x01\x00\x00",
			err:  "unexpected diagnostic IPC response command:",
		},
		{
			name: "short HRESULT",
			wire: "DOTNET_IPC_V1\x00\x17\x00\xff\xff\x00\x00\x85\x13\x13",
			err:  "invalid diagnostic IPC error payload size: 3",
		},
		{
			name: "oversized HRESULT",
			wire: "DOTNET_IPC_V1\x00\x19\x00\xff\xff\x00\x00\x85\x13\x13\x80\x00",
			err:  "invalid diagnostic IPC error payload size: 5",
		},
		{
			name: "connection closed",
			err:  "EOF",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := readIPCResponse(bytes.NewBufferString(tc.wire))
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				require.Nil(t, payload)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.payload, string(payload))
		})
	}
}
