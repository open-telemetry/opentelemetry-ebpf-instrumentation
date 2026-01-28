// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMQTTPackets(t *testing.T) {
	tests := []struct {
		name          string
		packet        []byte
		expectErr     bool
		expectedCount int
	}{
		{
			name: "single CONNECT packet",
			packet: []byte{
				0x10,       // CONNECT, flags=0
				0x0A,       // remaining length = 10
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x04, 0x02, 0x00, 0x3C, // level, flags, keep alive
			},
			expectErr:     false,
			expectedCount: 1,
		},
		{
			name: "multiple packets - CONNECT and PUBLISH",
			packet: []byte{
				// First packet: CONNECT
				0x10,       // CONNECT, flags=0
				0x0A,       // remaining length = 10
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x04, 0x02, 0x00, 0x3C, // level, flags, keep alive
				// Second packet: PUBLISH
				0x30,       // PUBLISH, flags=0
				0x05,       // remaining length = 5
				0x00, 0x03, // topic length = 3
				0x61, 0x2F, 0x62, // "a/b"
			},
			expectErr:     false,
			expectedCount: 2,
		},
		{
			name: "multiple packets - PINGREQ and PINGRESP",
			packet: []byte{
				// First packet: PINGREQ
				0xC0, // PINGREQ, flags=0
				0x00, // remaining length = 0
				// Second packet: PINGRESP
				0xD0, // PINGRESP, flags=0
				0x00, // remaining length = 0
			},
			expectErr:     false,
			expectedCount: 2,
		},
		{
			name: "incomplete packet at end",
			packet: []byte{
				// Complete CONNECT packet
				0x10,       // CONNECT, flags=0
				0x0A,       // remaining length = 10
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x04, 0x02, 0x00, 0x3C, // level, flags, keep alive
				// Incomplete PUBLISH packet
				0x30, // PUBLISH, flags=0
				0x05, // remaining length = 5, but only 2 bytes follow
				0x00, 0x03,
			},
			expectErr:     true, // Error because incomplete packet
			expectedCount: 1,    // Should parse first packet
		},
		{
			name:          "empty packet",
			packet:        []byte{},
			expectErr:     false,
			expectedCount: 0,
		},
		{
			name: "invalid header - insufficient data",
			packet: []byte{
				0x10, // CONNECT
				// Missing remaining length
			},
			expectErr:     false, // Not enough data, just stop parsing (no error)
			expectedCount: 0,
		},
		{
			name: "packet with variable length encoding",
			packet: []byte{
				// CONNECT with multi-byte remaining length
				0x10,       // CONNECT
				0x80, 0x01, // remaining length = 128 (2 bytes)
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x04, 0x02, 0x00, 0x3C, // level, flags, keep alive
				// ... more bytes to make up 128 total payload
			},
			expectErr:     true, // Will fail because we don't have 128 bytes
			expectedCount: 0,
		},
		{
			name: "invalid packet",
			packet: []byte{
				0x10,                   // CONNECT
				0x80, 0x80, 0x80, 0x80, // Invalid varint - continuation bit set on 4th byte but no 5th byte
			},
			expectErr:     true,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packets, err := ParseMQTTPackets(tt.packet)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.Len(t, packets, tt.expectedCount)
		})
	}
}

func TestParseMQTTPacketsMultiplePackets(t *testing.T) {
	// Test with multiple complete packets
	packet := []byte{
		// Packet 1: CONNECT
		0x10,       // CONNECT, flags=0
		0x0A,       // remaining length = 10
		0x00, 0x04, // protocol name length = 4
		0x4D, 0x51, 0x54, 0x54, // "MQTT"
		0x04, 0x02, 0x00, 0x3C, // level, flags, keep alive
		// Packet 2: PUBLISH QoS 0
		0x30,       // PUBLISH, flags=0
		0x0A,       // remaining length = 10 (2 topic len + 3 topic + 5 payload)
		0x00, 0x03, // topic length = 3
		0x61, 0x2F, 0x62, // "a/b"
		0x68, 0x65, 0x6C, 0x6C, 0x6F, // "hello"
		// Packet 3: PINGREQ
		0xC0, // PINGREQ, flags=0
		0x00, // remaining length = 0
	}

	packets, err := ParseMQTTPackets(packet)
	require.NoError(t, err)
	assert.Len(t, packets, 3)

	// Verify first packet (CONNECT)
	assert.Equal(t, PacketTypeCONNECT, packets[0].FixedHeader.PacketType)
	assert.Equal(t, 2, packets[0].FixedHeader.Length)
	assert.Equal(t, 12, packets[0].Length())

	// Verify second packet (PUBLISH)
	assert.Equal(t, PacketTypePUBLISH, packets[1].FixedHeader.PacketType)
	assert.Equal(t, 2, packets[1].FixedHeader.Length)
	assert.Equal(t, 12, packets[1].Length()) // 2 header + 10 payload

	// Verify third packet (PINGREQ)
	assert.Equal(t, PacketTypePINGREQ, packets[2].FixedHeader.PacketType)
	assert.Equal(t, 2, packets[2].FixedHeader.Length)
	assert.Equal(t, 2, packets[2].Length())
}

func TestNewMQTTControlPacket(t *testing.T) {
	tests := []struct {
		name                    string
		packet                  []byte
		expectErr               bool
		expectedType            PacketType
		expectedFlags           uint8
		expectedRemainingLength int
		expectedHeaderLength    int
	}{
		{
			name: "CONNECT packet with small remaining length",
			packet: []byte{
				0x10, // CONNECT (type=1), flags=0
				0x0A, // remaining length = 10
			},
			expectErr:               false,
			expectedType:            PacketTypeCONNECT,
			expectedFlags:           0,
			expectedRemainingLength: 10,
			expectedHeaderLength:    2,
		},
		{
			name: "PUBLISH packet QoS 0",
			packet: []byte{
				0x30, // PUBLISH (type=3), flags=0 (QoS 0, no retain)
				0x05, // remaining length = 5
			},
			expectErr:               false,
			expectedType:            PacketTypePUBLISH,
			expectedFlags:           0,
			expectedRemainingLength: 5,
			expectedHeaderLength:    2,
		},
		{
			name: "PUBLISH packet QoS 1 with retain",
			packet: []byte{
				0x33, // PUBLISH (type=3), flags=3 (QoS 1, retain=1)
				0x0F, // remaining length = 15
			},
			expectErr:               false,
			expectedType:            PacketTypePUBLISH,
			expectedFlags:           3,
			expectedRemainingLength: 15,
			expectedHeaderLength:    2,
		},
		{
			name: "SUBSCRIBE packet",
			packet: []byte{
				0x82, // SUBSCRIBE (type=8), flags=2 (reserved)
				0x20, // remaining length = 32
			},
			expectErr:               false,
			expectedType:            PacketTypeSUBSCRIBE,
			expectedFlags:           2,
			expectedRemainingLength: 32,
			expectedHeaderLength:    2,
		},
		{
			name: "remaining length with continuation byte",
			packet: []byte{
				0x10, // CONNECT
				0x80, // continuation bit set, value = 0
				0x01, // continuation bit clear, value = 1, total = 128
			},
			expectErr:               false,
			expectedType:            PacketTypeCONNECT,
			expectedFlags:           0,
			expectedRemainingLength: 128,
			expectedHeaderLength:    3,
		},
		{
			name: "remaining length with multiple continuation bytes",
			packet: []byte{
				0x10, // CONNECT
				0x80, // continuation bit set, value = 0
				0x80, // continuation bit set, value = 0 * 128 = 0
				0x01, // continuation bit clear, value = 1, total = 0 + 0*128 + 1*128^2 = 16384
			},
			expectErr:               false,
			expectedType:            PacketTypeCONNECT,
			expectedFlags:           0,
			expectedRemainingLength: 16384,
			expectedHeaderLength:    4,
		},
		{
			name: "packet too short",
			packet: []byte{
				0x10, // Only one byte
			},
			expectErr: true,
		},
		{
			name:      "empty packet",
			packet:    []byte{},
			expectErr: true,
		},
		{
			name: "remaining length incomplete",
			packet: []byte{
				0x10, // CONNECT
				0x80, // continuation bit set, but no more bytes
			},
			expectErr: true,
		},
		{
			name: "invalid packet type (0 is reserved)",
			packet: []byte{
				0x00, // type=0 (reserved), flags=0
				0x00, // remaining length = 0
			},
			expectErr: true,
		},
		{
			name: "actual CONNECT packet",
			packet: []byte{
				0x10,       // CONNECT, flags=0
				0x2B,       // remaining length = 43
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT" (77='M', 81='Q', 84='T', 84='T')
				0x04,       // protocol level = 4 (MQTT 3.1.1)
				0x02,       // connect flags (clean session=1)
				0x00, 0x3C, // keep alive = 60
				0x00, 0x1F, // client ID length = 31

				// Client ID: "pythonmqtt_publisher_1765206934"
				0x70, 0x79, 0x74, 0x68, 0x6F, 0x6E, // "python"
				0x6D, 0x71, 0x74, 0x74, // "mqtt"
				0x5F,                                                 // "_"
				0x70, 0x75, 0x62, 0x6C, 0x69, 0x73, 0x68, 0x65, 0x72, // "publisher"
				0x5F,                                                       // "_"
				0x31, 0x37, 0x36, 0x35, 0x32, 0x30, 0x36, 0x39, 0x33, 0x34, // "1765206934"
			},
			expectErr:               false,
			expectedType:            PacketTypeCONNECT,
			expectedFlags:           0,
			expectedRemainingLength: 43,
			expectedHeaderLength:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := NewMQTTControlPacket(tt.packet)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedType, parsed.FixedHeader.PacketType)
				assert.Equal(t, tt.expectedFlags, parsed.FixedHeader.Flags)
				assert.Equal(t, tt.expectedRemainingLength, parsed.FixedHeader.RemainingLength)
				assert.Equal(t, tt.expectedHeaderLength, parsed.FixedHeader.Length)
				assert.Equal(t, tt.expectedHeaderLength+tt.expectedRemainingLength, parsed.Length())
			}
		})
	}
}
