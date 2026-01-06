// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePublishPacketWithRealPacket(t *testing.T) {
	// Real MQTT PUBLISH packet captured from test environment logs
	// PUBLISH QoS=1, DUP=0, RETAIN=0, topic="test/topic", packet_id=1
	// Payload: "Hello from pythonmqtt! Message #1, Timestamp: 2026-01-06T12:27:18.682207"
	packet := []byte{
		0x32,       // PUBLISH, QoS=1, DUP=0, RETAIN=0 (fixed header)
		0x56,       // remaining length = 86
		0x00, 0x0A, // topic name length = 10
		// Topic: "test/topic"
		0x74, 0x65, 0x73, 0x74, 0x2F, 0x74, 0x6F, 0x70, 0x69, 0x63,
		0x00, 0x01, // packet ID = 1
		// Payload: "Hello from pythonmqtt! Message #1, Timestamp: 2026-01-06T12:27:18.682207"
		0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x66, 0x72, 0x6F, 0x6D, 0x20,
		0x70, 0x79, 0x74, 0x68, 0x6F, 0x6E, 0x6D, 0x71, 0x74, 0x74, 0x21,
		0x20, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x23, 0x31,
		0x2C, 0x20, 0x54, 0x69, 0x6D, 0x65, 0x73, 0x74, 0x61, 0x6D, 0x70,
		0x3A, 0x20, 0x32, 0x30, 0x32, 0x36, 0x2D, 0x30, 0x31, 0x2D, 0x30,
		0x36, 0x54, 0x31, 0x32, 0x3A, 0x32, 0x37, 0x3A, 0x31, 0x38, 0x2E,
		0x36, 0x38, 0x32, 0x32, 0x30, 0x37,
	}

	// Parse fixed header first
	parsed, err := NewMQTTControlPacket(packet)
	require.NoError(t, err)
	assert.Equal(t, PacketTypePUBLISH, parsed.FixedHeader.PacketType)
	assert.Equal(t, uint8(0x02), parsed.FixedHeader.Flags) // QoS=1
	assert.Equal(t, 86, parsed.FixedHeader.RemainingLength)
	assert.Equal(t, 2, parsed.FixedHeader.Length)

	// Parse PUBLISH packet starting from variable header
	publish, offset, err := ParsePublishPacket(packet, parsed.FixedHeader.Length, parsed.FixedHeader.Flags)
	require.NoError(t, err)
	require.NotNil(t, publish)

	assert.Equal(t, "test/topic", publish.TopicName)
	assert.Equal(t, QoSAtLeastOnce, publish.QoS)
	assert.False(t, publish.Dup)
	assert.False(t, publish.Retain)
	assert.Equal(t, uint16(1), publish.PacketID)

	// Verify offset is correct (header + variable header, payload not parsed)
	expectedOffset := parsed.FixedHeader.Length + 2 + 10 + 2 // fixed header + topic len + topic + packet ID
	assert.Equal(t, expectedOffset, offset)
}

func TestParsePublishPacket(t *testing.T) {
	tests := []struct {
		name           string
		packet         []byte
		offset         Offset
		flags          uint8
		expectErr      bool
		expected       *PublishPacket
		expectedOffset Offset
	}{
		{
			name: "QoS 0, no retain, no dup - simple publish",
			packet: []byte{
				0x00, 0x05, // topic name length = 5
				0x74, 0x65, 0x6D, 0x70, 0x2F, // "temp/"
				// payload: "25.5"
				0x32, 0x35, 0x2E, 0x35,
			},
			offset: 0,
			flags:  0x00, // QoS=0, DUP=0, RETAIN=0
			expected: &PublishPacket{
				TopicName: "temp/",
				QoS:       QoSAtMostOnce,
				Dup:       false,
				Retain:    false,
				PacketID:  0, // not present for QoS 0
			},
			expectedOffset: 7,
		},
		{
			name: "QoS 1 with packet ID",
			packet: []byte{
				0x00, 0x07, // topic name length = 7
				0x73, 0x65, 0x6E, 0x73, 0x6F, 0x72, 0x73, // "sensors"
				0x00, 0x2A, // packet ID = 42
				// payload: "data"
				0x64, 0x61, 0x74, 0x61,
			},
			offset: 0,
			flags:  0x02, // QoS=1, DUP=0, RETAIN=0
			expected: &PublishPacket{
				TopicName: "sensors",
				QoS:       QoSAtLeastOnce,
				Dup:       false,
				Retain:    false,
				PacketID:  42,
			},
			expectedOffset: 11,
		},
		{
			name: "QoS 2 with packet ID and retain flag",
			packet: []byte{
				0x00, 0x04, // topic name length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x12, 0x34, // packet ID = 0x1234 = 4660
				// payload: "hello"
				0x68, 0x65, 0x6C, 0x6C, 0x6F,
			},
			offset: 0,
			flags:  0x05, // QoS=2, DUP=0, RETAIN=1
			expected: &PublishPacket{
				TopicName: "test",
				QoS:       QoSExactlyOnce,
				Dup:       false,
				Retain:    true,
				PacketID:  0x1234,
			},
			expectedOffset: 8,
		},
		{
			name: "duplicate message with QoS 1",
			packet: []byte{
				0x00, 0x08, // topic name length = 8
				0x72, 0x65, 0x74, 0x72, 0x61, 0x6E, 0x73, 0x6D, // "retransm"
				0xAB, 0xCD, // packet ID = 0xABCD = 43981
				// payload: "retry"
				0x72, 0x65, 0x74, 0x72, 0x79,
			},
			offset: 0,
			flags:  0x0A, // QoS=1, DUP=1, RETAIN=0
			expected: &PublishPacket{
				TopicName: "retransm",
				QoS:       QoSAtLeastOnce,
				Dup:       true,
				Retain:    false,
				PacketID:  0xABCD,
			},
			expectedOffset: 12,
		},
		{
			name: "empty payload",
			packet: []byte{
				0x00, 0x06, // topic name length = 6
				0x73, 0x74, 0x61, 0x74, 0x75, 0x73, // "status"
			},
			offset: 0,
			flags:  0x00, // QoS=0, DUP=0, RETAIN=0
			expected: &PublishPacket{
				TopicName: "status",
				QoS:       QoSAtMostOnce,
				Dup:       false,
				Retain:    false,
				PacketID:  0,
			},
			expectedOffset: 8,
		},
		{
			name: "error: offset beyond packet",
			packet: []byte{
				0x00, 0x04, 0x74, 0x65, 0x73, 0x74, // "test"
			},
			offset:    10, // beyond packet length
			flags:     0x00,
			expectErr: true,
		},
		{
			name: "error: insufficient data for topic name length",
			packet: []byte{
				0x00, // only one byte for topic length
			},
			offset:    0,
			flags:     0x00,
			expectErr: true,
		},
		{
			name: "error: insufficient data for topic name",
			packet: []byte{
				0x00, 0x05, // topic name length = 5
				0x74, 0x65, 0x73, // only 3 bytes, need 5
			},
			offset:    0,
			flags:     0x00,
			expectErr: true,
		},
		{
			name: "error: insufficient data for packet ID in QoS 1",
			packet: []byte{
				0x00, 0x04, // topic name length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x00, // only one byte of packet ID
			},
			offset:    0,
			flags:     0x02, // QoS=1
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publish, offset, err := ParsePublishPacket(tt.packet, tt.offset, tt.flags)

			if tt.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, publish)
			assert.Equal(t, tt.expected.TopicName, publish.TopicName)
			assert.Equal(t, tt.expected.QoS, publish.QoS)
			assert.Equal(t, tt.expected.Dup, publish.Dup)
			assert.Equal(t, tt.expected.Retain, publish.Retain)
			assert.Equal(t, tt.expected.PacketID, publish.PacketID)
			assert.Equal(t, tt.expectedOffset, offset)
		})
	}
}

func TestPublishPacketReaderReadTopicName(t *testing.T) {
	tests := []struct {
		name           string
		pkt            []byte
		expectErr      bool
		expectedTopic  string
		expectedOffset int
	}{
		{
			name: "simple topic name",
			pkt: []byte{
				0x00, 0x04, // topic name length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
			},
			expectedTopic:  "test",
			expectedOffset: 6,
		},
		{
			name: "topic with slash",
			pkt: []byte{
				0x00, 0x0A, // topic name length = 10
				0x68, 0x6F, 0x6D, 0x65, 0x2F, 0x74, 0x65, 0x6D, 0x70, 0x31, // "home/temp1"
			},
			expectedTopic:  "home/temp1",
			expectedOffset: 12,
		},
		{
			name: "empty topic name",
			pkt: []byte{
				0x00, 0x00, // topic name length = 0
			},
			expectedTopic:  "",
			expectedOffset: 2,
		},
		{
			name: "insufficient data for topic length",
			pkt: []byte{
				0x00, // only one byte
			},
			expectErr: true,
		},
		{
			name: "insufficient data for topic name",
			pkt: []byte{
				0x00, 0x05, // topic name length = 5
				0x74, 0x65, 0x73, // only 3 bytes, need 5
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewPublishPacketReader(tt.pkt, 0)
			topicName, err := r.ReadTopicName()

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedTopic, topicName)
			assert.Equal(t, tt.expectedOffset, r.Offset())
		})
	}
}

func TestPublishPacketReaderReadPacketID(t *testing.T) {
	tests := []struct {
		name             string
		pkt              []byte
		expectErr        bool
		expectedPacketID uint16
		expectedOffset   int
	}{
		{
			name: "packet ID 42",
			pkt: []byte{
				0x00, 0x2A, // packet ID = 42
			},
			expectedPacketID: 42,
			expectedOffset:   2,
		},
		{
			name: "packet ID 65535 (max)",
			pkt: []byte{
				0xFF, 0xFF, // packet ID = 65535
			},
			expectedPacketID: 65535,
			expectedOffset:   2,
		},
		{
			name: "packet ID 0",
			pkt: []byte{
				0x00, 0x00, // packet ID = 0
			},
			expectedPacketID: 0,
			expectedOffset:   2,
		},
		{
			name: "insufficient data - one byte",
			pkt: []byte{
				0x00, // only one byte
			},
			expectErr: true,
		},
		{
			name:      "insufficient data - empty",
			pkt:       []byte{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewPublishPacketReader(tt.pkt, 0)
			packetID, err := r.ReadPacketID()

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedPacketID, packetID)
			assert.Equal(t, tt.expectedOffset, r.Offset())
		})
	}
}

func TestQoSLevel(t *testing.T) {
	tests := []struct {
		name string
		qos  QoSLevel
	}{
		{
			name: "QoS 0 - At most once",
			qos:  QoSAtMostOnce,
		},
		{
			name: "QoS 1 - At least once",
			qos:  QoSAtLeastOnce,
		},
		{
			name: "QoS 2 - Exactly once",
			qos:  QoSExactlyOnce,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// QoS levels are constants, testing they have expected values
			switch tt.qos {
			case QoSAtMostOnce:
				assert.Equal(t, uint8(0), uint8(tt.qos))
			case QoSAtLeastOnce:
				assert.Equal(t, uint8(1), uint8(tt.qos))
			case QoSExactlyOnce:
				assert.Equal(t, uint8(2), uint8(tt.qos))
			}
		})
	}
}
