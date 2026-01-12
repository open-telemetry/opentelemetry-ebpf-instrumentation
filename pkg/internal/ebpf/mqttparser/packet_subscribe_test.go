// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSubscribePacketWithRealPacket(t *testing.T) {
	// MQTT 3.1.1 SUBSCRIBE packet: PacketID=1, topic="test/topic", QoS=1
	packet := []byte{
		0x82,       // SUBSCRIBE (fixed header)
		0x0F,       // remaining length = 15
		0x00, 0x01, // packet ID = 1
		0x00, 0x0A, // topic filter length = 10
		// Topic: "test/topic"
		0x74, 0x65, 0x73, 0x74, 0x2F, 0x74, 0x6F, 0x70, 0x69, 0x63,
		0x01, // QoS = 1
	}

	// Parse fixed header first
	parsed, err := NewMQTTControlPacket(packet)
	require.NoError(t, err)
	assert.Equal(t, PacketTypeSUBSCRIBE, parsed.FixedHeader.PacketType)
	assert.Equal(t, uint8(0x02), parsed.FixedHeader.Flags) // SUBSCRIBE flags must be 0x02
	assert.Equal(t, 15, parsed.FixedHeader.RemainingLength)
	assert.Equal(t, 2, parsed.FixedHeader.Length)

	// Parse SUBSCRIBE packet starting from variable header
	subscribe, offset, err := ParseSubscribePacket(packet, parsed.FixedHeader.Length, parsed.FixedHeader.RemainingLength)
	require.NoError(t, err)
	require.NotNil(t, subscribe)

	assert.Equal(t, uint16(1), subscribe.PacketID)
	require.Len(t, subscribe.Subscriptions, 1)
	assert.Equal(t, "test/topic", subscribe.Subscriptions[0].TopicFilter)
	assert.Equal(t, QoSAtLeastOnce, subscribe.Subscriptions[0].QoS)

	// Verify offset is correct (end of packet)
	expectedOffset := parsed.Length()
	assert.Equal(t, expectedOffset, offset)
}

func TestParseSubscribePacket(t *testing.T) {
	tests := []struct {
		name            string
		packet          []byte
		offset          Offset
		remainingLength int // optional, defaults to len(packet) - offset
		expectErr       bool
		expected        *SubscribePacket
		expectedOffset  Offset
	}{
		{
			name: "MQTT 3.1.1: single subscription QoS 0",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
				0x00, 0x05, // topic filter length = 5
				0x74, 0x65, 0x6D, 0x70, 0x2F, // "temp/"
				0x00, // QoS = 0
			},
			offset: 0,
			expected: &SubscribePacket{
				PacketID: 1,
				Subscriptions: []Subscription{
					{TopicFilter: "temp/", QoS: QoSAtMostOnce},
				},
			},
			expectedOffset: 10,
		},
		{
			name: "MQTT 3.1.1: single subscription QoS 1",
			packet: []byte{
				0x00, 0x2A, // packet ID = 42
				0x00, 0x07, // topic filter length = 7
				0x73, 0x65, 0x6E, 0x73, 0x6F, 0x72, 0x73, // "sensors"
				0x01, // QoS = 1
			},
			offset: 0,
			expected: &SubscribePacket{
				PacketID: 42,
				Subscriptions: []Subscription{
					{TopicFilter: "sensors", QoS: QoSAtLeastOnce},
				},
			},
			expectedOffset: 12,
		},
		{
			name: "MQTT 3.1.1: single subscription QoS 2",
			packet: []byte{
				0x12, 0x34, // packet ID = 0x1234 = 4660
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x02, // QoS = 2
			},
			offset: 0,
			expected: &SubscribePacket{
				PacketID: 0x1234,
				Subscriptions: []Subscription{
					{TopicFilter: "test", QoS: QoSExactlyOnce},
				},
			},
			expectedOffset: 9,
		},
		{
			name: "MQTT 3.1.1: multiple subscriptions",
			packet: []byte{
				0x00, 0x05, // packet ID = 5
				0x00, 0x06, // topic filter length = 6
				0x74, 0x6F, 0x70, 0x69, 0x63, 0x31, // "topic1"
				0x00,       // QoS = 0
				0x00, 0x06, // topic filter length = 6
				0x74, 0x6F, 0x70, 0x69, 0x63, 0x32, // "topic2"
				0x01,       // QoS = 1
				0x00, 0x06, // topic filter length = 6
				0x74, 0x6F, 0x70, 0x69, 0x63, 0x33, // "topic3"
				0x02, // QoS = 2
			},
			offset: 0,
			expected: &SubscribePacket{
				PacketID: 5,
				Subscriptions: []Subscription{
					{TopicFilter: "topic1", QoS: QoSAtMostOnce},
					{TopicFilter: "topic2", QoS: QoSAtLeastOnce},
					{TopicFilter: "topic3", QoS: QoSExactlyOnce},
				},
			},
			expectedOffset: 29,
		},
		{
			name: "MQTT 3.1.1: wildcard subscription with +",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
				0x00, 0x08, // topic filter length = 8
				0x68, 0x6F, 0x6D, 0x65, 0x2F, 0x2B, 0x2F, 0x74, // "home/+/t"
				0x01, // QoS = 1
			},
			offset: 0,
			expected: &SubscribePacket{
				PacketID: 1,
				Subscriptions: []Subscription{
					{TopicFilter: "home/+/t", QoS: QoSAtLeastOnce},
				},
			},
			expectedOffset: 13,
		},
		{
			name: "MQTT 3.1.1: wildcard subscription with #",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
				0x00, 0x06, // topic filter length = 6
				0x68, 0x6F, 0x6D, 0x65, 0x2F, 0x23, // "home/#"
				0x02, // QoS = 2
			},
			offset: 0,
			expected: &SubscribePacket{
				PacketID: 1,
				Subscriptions: []Subscription{
					{TopicFilter: "home/#", QoS: QoSExactlyOnce},
				},
			},
			expectedOffset: 11,
		},
		{
			name: "MQTT 5.0: empty properties",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
				0x00,       // properties length = 0
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x01, // subscription options (QoS = 1)
			},
			offset: 0,
			expected: &SubscribePacket{
				PacketID: 1,
				Subscriptions: []Subscription{
					{TopicFilter: "test", QoS: QoSAtLeastOnce},
				},
			},
			expectedOffset: 10,
		},
		{
			name: "MQTT 5.0: with properties",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
				0x03,             // properties length = 3
				0x0B, 0x00, 0x01, // subscription identifier property
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x02, // subscription options (QoS = 2)
			},
			offset: 0,
			expected: &SubscribePacket{
				PacketID: 1,
				Subscriptions: []Subscription{
					{TopicFilter: "test", QoS: QoSExactlyOnce},
				},
			},
			expectedOffset: 13,
		},
		{
			name: "MQTT 5.0: subscription options with extra flags",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
				0x00,       // properties length = 0
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x1D, // subscription options: QoS=1, NL=0, RAP=1, Retain=2
			},
			offset: 0,
			expected: &SubscribePacket{
				PacketID: 1,
				Subscriptions: []Subscription{
					{TopicFilter: "test", QoS: QoSAtLeastOnce}, // only QoS bits 0-1
				},
			},
			expectedOffset: 10,
		},
		{
			name: "bounded read with extra data",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x01, // QoS = 1
				// Extra bytes (would be next packet)
				0xFF, 0xFF, 0xFF, 0xFF,
			},
			offset:          0,
			remainingLength: 9, // Only parse first 9 bytes
			expected: &SubscribePacket{
				PacketID: 1,
				Subscriptions: []Subscription{
					{TopicFilter: "test", QoS: QoSAtLeastOnce},
				},
			},
			expectedOffset: 9, // Should stop at remainingLength boundary
		},
		{
			name:      "error: remainingLength exceeds packet",
			packet:    []byte{0x00, 0x01},
			offset:    0,
			expectErr: true,
		},
		{
			name:      "error: insufficient data for packet ID",
			packet:    []byte{0x00},
			offset:    0,
			expectErr: true,
		},
		{
			name: "error: insufficient data for topic filter length",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
				0x00, // only one byte for topic length
			},
			offset:    0,
			expectErr: true,
		},
		{
			name: "error: insufficient data for topic filter",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
				0x00, 0x05, // topic filter length = 5
				0x74, 0x65, 0x73, // only 3 bytes, need 5
			},
			offset:    0,
			expectErr: true,
		},
		{
			name: "error: missing subscription options",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				// missing subscription options byte
			},
			offset:    0,
			expectErr: true,
		},
		{
			name: "error: no subscriptions (empty payload)",
			packet: []byte{
				0x00, 0x01, // packet ID = 1
			},
			offset:    0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use packet length as remainingLength for these tests, unless explicitly set
			remainingLength := len(tt.packet) - tt.offset
			if tt.remainingLength > 0 {
				remainingLength = tt.remainingLength
			}
			subscribe, offset, err := ParseSubscribePacket(tt.packet, tt.offset, remainingLength)

			if tt.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, subscribe)
			assert.Equal(t, tt.expected.PacketID, subscribe.PacketID)
			require.Len(t, subscribe.Subscriptions, len(tt.expected.Subscriptions))
			for i, expectedSub := range tt.expected.Subscriptions {
				assert.Equal(t, expectedSub.TopicFilter, subscribe.Subscriptions[i].TopicFilter)
				assert.Equal(t, expectedSub.QoS, subscribe.Subscriptions[i].QoS)
			}
			assert.Equal(t, tt.expectedOffset, offset)
		})
	}
}

func TestErrProtocolMismatch(t *testing.T) {
	// Verify ErrProtocolMismatch is a proper sentinel error
	err := ErrProtocolMismatch
	require.ErrorIs(t, err, ErrProtocolMismatch)

	// Wrapped error should not match (it's a new error, not wrapping)
	wrappedErr := errors.New("wrapped: " + err.Error())
	require.NotErrorIs(t, wrappedErr, ErrProtocolMismatch)
}

func TestSubscribePacketReaderReadPacketID(t *testing.T) {
	tests := []struct {
		name             string
		pkt              []byte
		expectErr        bool
		expectedPacketID uint16
		expectedOffset   int
	}{
		{
			name:             "packet ID 1",
			pkt:              []byte{0x00, 0x01},
			expectedPacketID: 1,
			expectedOffset:   2,
		},
		{
			name:             "packet ID 42",
			pkt:              []byte{0x00, 0x2A},
			expectedPacketID: 42,
			expectedOffset:   2,
		},
		{
			name:             "packet ID 65535 (max)",
			pkt:              []byte{0xFF, 0xFF},
			expectedPacketID: 65535,
			expectedOffset:   2,
		},
		{
			name:      "insufficient data - one byte",
			pkt:       []byte{0x00},
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
			r := NewSubscribePacketReader(tt.pkt, 0)
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

func TestSubscribePacketReaderSkipProperties(t *testing.T) {
	tests := []struct {
		name           string
		pkt            []byte
		expectErr      bool
		expectedOffset int
	}{
		{
			name: "skip 3 bytes of properties",
			pkt: []byte{
				0x03,             // properties length = 3
				0x0B, 0x00, 0x01, // subscription identifier
			},
			expectedOffset: 4,
		},
		{
			name: "empty properties",
			pkt: []byte{
				0x00, // properties length = 0
			},
			expectedOffset: 1,
		},
		{
			name:      "insufficient data for property length",
			pkt:       []byte{},
			expectErr: true,
		},
		{
			name: "insufficient data for properties",
			pkt: []byte{
				0x05,       // properties length = 5
				0x0B, 0x00, // only 2 bytes, need 5
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewSubscribePacketReader(tt.pkt, 0)
			err := r.SkipProperties()

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedOffset, r.Offset())
		})
	}
}

func TestSubscribePacketReaderReadSubscriptionsMQTT311(t *testing.T) {
	tests := []struct {
		name                  string
		pkt                   []byte
		expectErr             bool
		expectProtocolErr     bool
		expectedSubscriptions []Subscription
	}{
		{
			name: "valid 3.1.1 single subscription",
			pkt: []byte{
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x01, // QoS = 1 (valid for 3.1.1)
			},
			expectedSubscriptions: []Subscription{
				{TopicFilter: "test", QoS: QoSAtLeastOnce},
			},
		},
		{
			name: "valid 3.1.1 multiple subscriptions",
			pkt: []byte{
				0x00, 0x02, // topic filter length = 2
				0x61, 0x2F, // "a/"
				0x00,       // QoS = 0
				0x00, 0x02, // topic filter length = 2
				0x62, 0x2F, // "b/"
				0x02, // QoS = 2
			},
			expectedSubscriptions: []Subscription{
				{TopicFilter: "a/", QoS: QoSAtMostOnce},
				{TopicFilter: "b/", QoS: QoSExactlyOnce},
			},
		},
		{
			name: "invalid QoS triggers protocol mismatch",
			pkt: []byte{
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x03, // QoS = 3 (invalid for 3.1.1, triggers fallback)
			},
			expectErr:         true,
			expectProtocolErr: true,
		},
		{
			name: "MQTT 5.0 options trigger protocol mismatch",
			pkt: []byte{
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x2D, // options with extra bits set (triggers fallback)
			},
			expectErr:         true,
			expectProtocolErr: true,
		},
		{
			name:              "empty payload triggers protocol mismatch",
			pkt:               []byte{},
			expectErr:         true,
			expectProtocolErr: true,
		},
		{
			name: "read failure triggers protocol mismatch",
			pkt: []byte{
				0x00, 0x10, // topic filter length = 16 (more than available)
				0x74, 0x65, 0x73, 0x74, // only 4 bytes
			},
			expectErr:         true,
			expectProtocolErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewSubscribePacketReader(tt.pkt, 0)
			subscriptions, err := r.readSubscriptions(ProtocolLevelMQTT311)

			if tt.expectErr {
				require.Error(t, err)
				if tt.expectProtocolErr {
					require.ErrorIs(t, err, ErrProtocolMismatch)
				}
				return
			}

			require.NoError(t, err)
			require.Len(t, subscriptions, len(tt.expectedSubscriptions))
			for i, expected := range tt.expectedSubscriptions {
				assert.Equal(t, expected.TopicFilter, subscriptions[i].TopicFilter)
				assert.Equal(t, expected.QoS, subscriptions[i].QoS)
			}
		})
	}
}

func TestSubscribePacketReaderReadSubscriptionsMQTT50(t *testing.T) {
	tests := []struct {
		name                  string
		pkt                   []byte
		expectErr             bool
		expectedSubscriptions []Subscription
	}{
		{
			name: "single subscription",
			pkt: []byte{
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0x01, // QoS = 1
			},
			expectedSubscriptions: []Subscription{
				{TopicFilter: "test", QoS: QoSAtLeastOnce},
			},
		},
		{
			name: "multiple subscriptions",
			pkt: []byte{
				0x00, 0x02, // topic filter length = 2
				0x61, 0x2F, // "a/"
				0x00,       // QoS = 0
				0x00, 0x02, // topic filter length = 2
				0x62, 0x2F, // "b/"
				0x01, // QoS = 1
			},
			expectedSubscriptions: []Subscription{
				{TopicFilter: "a/", QoS: QoSAtMostOnce},
				{TopicFilter: "b/", QoS: QoSAtLeastOnce},
			},
		},
		{
			name: "subscription options with extra bits (masks to QoS)",
			pkt: []byte{
				0x00, 0x04, // topic filter length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
				0xFF, // all bits set, QoS = bits 0-1 = 11 = 3
			},
			expectedSubscriptions: []Subscription{
				{TopicFilter: "test", QoS: QoSLevel(3)},
			},
		},
		{
			name:      "empty payload",
			pkt:       []byte{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewSubscribePacketReader(tt.pkt, 0)
			subscriptions, err := r.readSubscriptions(ProtocolLevelMQTT50)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Len(t, subscriptions, len(tt.expectedSubscriptions))
			for i, expected := range tt.expectedSubscriptions {
				assert.Equal(t, expected.TopicFilter, subscriptions[i].TopicFilter)
				assert.Equal(t, expected.QoS, subscriptions[i].QoS)
			}
		})
	}
}

func TestSubscription(t *testing.T) {
	tests := []struct {
		name         string
		subscription Subscription
	}{
		{
			name: "QoS 0 subscription",
			subscription: Subscription{
				TopicFilter: "test/topic",
				QoS:         QoSAtMostOnce,
			},
		},
		{
			name: "QoS 1 subscription",
			subscription: Subscription{
				TopicFilter: "home/+/temperature",
				QoS:         QoSAtLeastOnce,
			},
		},
		{
			name: "QoS 2 subscription",
			subscription: Subscription{
				TopicFilter: "sensors/#",
				QoS:         QoSExactlyOnce,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.subscription.TopicFilter)
			assert.LessOrEqual(t, uint8(tt.subscription.QoS), uint8(2))
		})
	}
}
