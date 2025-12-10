// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadUint8(t *testing.T) {
	tests := []struct {
		name        string
		pkt         []byte
		offset      Offset
		expectErr   bool
		expectedVal uint8
		expectedOff Offset
	}{
		{
			name:        "valid uint8",
			pkt:         []byte{0x42},
			offset:      0,
			expectErr:   false,
			expectedVal: 0x42,
			expectedOff: 1,
		},
		{
			name:      "insufficient data",
			pkt:       []byte{},
			offset:    0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewPacketReader(tt.pkt, tt.offset)
			val, err := r.ReadUint8()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedVal, val)
				assert.Equal(t, tt.expectedOff, r.Offset())
				assert.Equal(t, len(tt.pkt)-tt.expectedOff, r.Remaining())
			}
		})
	}
}

func TestReadUint16(t *testing.T) {
	tests := []struct {
		name        string
		pkt         []byte
		offset      Offset
		expectErr   bool
		expectedVal uint16
		expectedOff Offset
	}{
		{
			name:        "valid uint16",
			pkt:         []byte{0x12, 0x34},
			offset:      0,
			expectErr:   false,
			expectedVal: 0x1234,
			expectedOff: 2,
		},
		{
			name:        "zero value",
			pkt:         []byte{0x00, 0x00},
			offset:      0,
			expectErr:   false,
			expectedVal: 0,
			expectedOff: 2,
		},
		{
			name:        "maximum value",
			pkt:         []byte{0xFF, 0xFF},
			offset:      0,
			expectErr:   false,
			expectedVal: 0xFFFF,
			expectedOff: 2,
		},
		{
			name:      "insufficient data",
			pkt:       []byte{0x12},
			offset:    0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewPacketReader(tt.pkt, tt.offset)
			val, err := r.ReadUint16()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedVal, val)
				assert.Equal(t, tt.expectedOff, r.Offset())
				assert.Equal(t, len(tt.pkt)-tt.expectedOff, r.Remaining())
			}
		})
	}
}

func TestReadVariableByteInteger(t *testing.T) {
	tests := []struct {
		name        string
		pkt         []byte
		offset      Offset
		expectErr   bool
		expectedVal int
		expectedOff Offset
	}{
		{
			name:        "single byte encoding",
			pkt:         []byte{0x00},
			offset:      0,
			expectErr:   false,
			expectedVal: 0,
			expectedOff: 1,
		},
		{
			name:        "single byte encoding - value 5",
			pkt:         []byte{0x05},
			offset:      0,
			expectErr:   false,
			expectedVal: 5,
			expectedOff: 1,
		},
		{
			name:        "single byte encoding - max value",
			pkt:         []byte{0x7F},
			offset:      0,
			expectErr:   false,
			expectedVal: 127,
			expectedOff: 1,
		},
		{
			name:        "two byte encoding",
			pkt:         []byte{0x80, 0x01},
			offset:      0,
			expectErr:   false,
			expectedVal: 128,
			expectedOff: 2,
		},
		{
			name:        "two byte encoding - larger value",
			pkt:         []byte{0xFF, 0x7},
			offset:      0,
			expectErr:   false,
			expectedVal: 1023, // 127 + 7*128
			expectedOff: 2,
		},
		{
			name:        "three byte encoding",
			pkt:         []byte{0x80, 0x80, 0x01},
			offset:      0,
			expectErr:   false,
			expectedVal: 16384, // 0 + 0*128 + 1*128*128
			expectedOff: 3,
		},
		{
			name:        "with offset",
			pkt:         []byte{0x42, 0x80, 0x01, 0x99},
			offset:      1,
			expectErr:   false,
			expectedVal: 128,
			expectedOff: 3,
		},
		{
			name:      "insufficient data",
			pkt:       []byte{},
			offset:    0,
			expectErr: true,
		},
		{
			name:      "incomplete continuation",
			pkt:       []byte{0x80},
			offset:    0,
			expectErr: true,
		},
		{
			name:      "incomplete continuation with offset",
			pkt:       []byte{0x42, 0x80},
			offset:    1,
			expectErr: true,
		},
		{
			name:      "too many continuation bytes",
			pkt:       []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			offset:    0,
			expectErr: true,
		},
		{
			name:        "four byte encoding",
			pkt:         []byte{0x80, 0x80, 0x80, 0x01},
			offset:      0,
			expectErr:   false,
			expectedVal: 2097152,
			expectedOff: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewPacketReader(tt.pkt, tt.offset)
			val, err := r.ReadVariableByteInteger()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedVal, val)
				assert.Equal(t, tt.expectedOff, r.Offset())
				assert.Equal(t, len(tt.pkt)-tt.expectedOff, r.Remaining())
			}
		})
	}
}

func TestReadString(t *testing.T) {
	tests := []struct {
		name        string
		pkt         []byte
		offset      Offset
		expectErr   bool
		expectedStr string
		expectedOff Offset
	}{
		{
			name: "valid string",
			pkt: []byte{
				0x00, 0x04, // length = 4
				't', 'e', 's', 't', // "test"
			},
			offset:      0,
			expectErr:   false,
			expectedStr: "test",
			expectedOff: 6,
		},
		{
			name: "empty string",
			pkt: []byte{
				0x00, 0x00, // length = 0
			},
			offset:      0,
			expectErr:   false,
			expectedStr: "",
			expectedOff: 2,
		},
		{
			name: "string with offset",
			pkt: []byte{
				0x00, 0x00, // dummy
				0x00, 0x05, // length = 5
				'h', 'e', 'l', 'l', 'o', // "hello"
			},
			offset:      2,
			expectErr:   false,
			expectedStr: "hello",
			expectedOff: 9,
		},
		{
			name: "insufficient data for length",
			pkt: []byte{
				0x00, // only one byte
			},
			offset:    0,
			expectErr: true,
		},
		{
			name: "insufficient data for string content",
			pkt: []byte{
				0x00, 0x05, // length = 5
				'h', 'e', // only 2 bytes
			},
			offset:    0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewPacketReader(tt.pkt, tt.offset)
			str, err := r.ReadString()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedStr, str)
				assert.Equal(t, tt.expectedOff, r.Offset())
				assert.Equal(t, len(tt.pkt)-tt.expectedOff, r.Remaining())
			}
		})
	}
}
