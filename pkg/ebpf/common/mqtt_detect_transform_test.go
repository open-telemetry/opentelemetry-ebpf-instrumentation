// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"
)

func TestProcessMQTTEvent(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected *MQTTInfo
		ignore   bool
		err      bool
	}{
		{
			name: "PUBLISH QoS 0 - simple topic",
			request: []byte{
				0x30,       // PUBLISH, QoS 0, no flags
				0x0c,       // Remaining length: 12
				0x00, 0x0a, // Topic length: 10
				't', 'e', 's', 't', '/', 't', 'o', 'p', 'i', 'c', // Topic: "test/topic"
			},
			expected: &MQTTInfo{
				PacketType: mqttparser.PacketTypePUBLISH,
				Topic:      "test/topic",
				QoS:        mqttparser.QoSAtMostOnce,
				PacketID:   0,
			},
		},
		{
			name: "PUBLISH QoS 1 with packet ID",
			request: []byte{
				0x32,       // PUBLISH, QoS 1
				0x0e,       // Remaining length: 14
				0x00, 0x0a, // Topic length: 10
				't', 'e', 's', 't', '/', 't', 'o', 'p', 'i', 'c', // Topic: "test/topic"
				0x00, 0x01, // Packet ID: 1
			},
			expected: &MQTTInfo{
				PacketType: mqttparser.PacketTypePUBLISH,
				Topic:      "test/topic",
				QoS:        mqttparser.QoSAtLeastOnce,
				PacketID:   1,
			},
		},
		{
			name: "PUBLISH QoS 2 with packet ID",
			request: []byte{
				0x34,       // PUBLISH, QoS 2
				0x0e,       // Remaining length: 14
				0x00, 0x0a, // Topic length: 10
				't', 'e', 's', 't', '/', 't', 'o', 'p', 'i', 'c', // Topic: "test/topic"
				0x00, 0x2A, // Packet ID: 42
			},
			expected: &MQTTInfo{
				PacketType: mqttparser.PacketTypePUBLISH,
				Topic:      "test/topic",
				QoS:        mqttparser.QoSExactlyOnce,
				PacketID:   42,
			},
		},
		{
			name: "PUBLISH with DUP and RETAIN flags",
			request: []byte{
				0x3B,       // PUBLISH, DUP=1, QoS 1, RETAIN=1
				0x0e,       // Remaining length: 14
				0x00, 0x0a, // Topic length: 10
				's', 'e', 'n', 's', 'o', 'r', '/', 'd', 'a', 't', // Topic: "sensor/dat" (truncated for test)
				0x00, 0x05, // Packet ID: 5
			},
			expected: &MQTTInfo{
				PacketType: mqttparser.PacketTypePUBLISH,
				Topic:      "sensor/dat",
				QoS:        mqttparser.QoSAtLeastOnce,
				PacketID:   5,
			},
		},
		{
			name: "SUBSCRIBE MQTT 3.1.1 - single topic",
			request: []byte{
				0x82,       // SUBSCRIBE
				0x0e,       // Remaining length: 14
				0x00, 0x01, // Packet ID: 1
				0x00, 0x09, // Topic filter length: 9
				's', 'e', 'n', 's', 'o', 'r', 's', '/', '#', // Topic filter: "sensors/#"
				0x01, // QoS 1
			},
			expected: &MQTTInfo{
				PacketType: mqttparser.PacketTypeSUBSCRIBE,
				Topic:      "sensors/#",
				QoS:        mqttparser.QoSAtLeastOnce,
				PacketID:   1,
			},
		},
		{
			name: "SUBSCRIBE MQTT 3.1.1 - multiple topics (first returned)",
			request: []byte{
				0x82,       // SUBSCRIBE
				0x16,       // Remaining length: 22
				0x00, 0x02, // Packet ID: 2
				0x00, 0x06, // Topic filter length: 6
				't', 'e', 's', 't', '/', '+', // Topic filter: "test/+"
				0x00,       // QoS 0
				0x00, 0x08, // Topic filter length: 8
				's', 't', 'a', 't', 'u', 's', '/', '#', // Topic filter: "status/#"
				0x02, // QoS 2
			},
			expected: &MQTTInfo{
				PacketType: mqttparser.PacketTypeSUBSCRIBE,
				Topic:      "test/+",
				QoS:        mqttparser.QoSAtMostOnce,
				PacketID:   2,
			},
		},
		{
			name: "CONNECT MQTT 3.1.1 - ignored for span (returns error)",
			request: []byte{
				0x10,       // CONNECT
				0x18,       // Remaining length: 24
				0x00, 0x04, // Protocol name length: 4
				'M', 'Q', 'T', 'T', // Protocol name
				0x04,       // Protocol level: 4 (MQTT 3.1.1)
				0x02,       // Connect flags: Clean Session
				0x00, 0x3c, // Keep alive: 60
				0x00, 0x0c, // Client ID length: 12
				'm', 'y', '-', 'c', 'l', 'i', 'e', 'n', 't', '-', 'i', 'd',
			},
			// CONNECT packets are ignored for span creation, so ProcessMQTTEvent
			// returns an error indicating no span-worthy packets found
			ignore: true,
			err:    true,
		},
		{
			name: "CONNECT MQTT 5.0 - ignored for span (returns error)",
			request: []byte{
				0x10,       // CONNECT
				0x12,       // Remaining length: 18
				0x00, 0x04, // Protocol name length: 4
				'M', 'Q', 'T', 'T', // Protocol name
				0x05,       // Protocol level: 5 (MQTT 5.0)
				0x02,       // Connect flags: Clean Session
				0x00, 0x3c, // Keep alive: 60
				0x00,       // Properties length: 0
				0x00, 0x05, // Client ID length: 5
				't', 'e', 's', 't', '5', // Client ID: "test5"
			},
			// CONNECT packets are ignored for span creation
			ignore: true,
			err:    true,
		},
		{
			name: "PINGREQ - ignored control packet",
			request: []byte{
				0xc0, // PINGREQ
				0x00, // Remaining length: 0
			},
			ignore: true,
			err:    true, // Will error as no span-worthy packet found
		},
		{
			name: "PINGRESP - ignored control packet",
			request: []byte{
				0xd0, // PINGRESP
				0x00, // Remaining length: 0
			},
			ignore: true,
			err:    true,
		},
		{
			name: "DISCONNECT - ignored control packet",
			request: []byte{
				0xe0, // DISCONNECT
				0x00, // Remaining length: 0
			},
			ignore: true,
			err:    true,
		},
		{
			name: "PUBACK - ignored control packet",
			request: []byte{
				0x40,       // PUBACK
				0x02,       // Remaining length: 2
				0x00, 0x01, // Packet ID: 1
			},
			ignore: true,
			err:    true,
		},
		{
			name:    "Empty packet",
			request: []byte{},
			err:     true,
		},
		{
			name:    "Too short packet",
			request: []byte{0x30},
			err:     true,
		},
		{
			name: "Invalid remaining length",
			request: []byte{
				0x30,                   // PUBLISH
				0xFF, 0xFF, 0xFF, 0xFF, // Invalid variable length
			},
			err: true,
		},
		{
			name: "Non-MQTT data (HTTP)",
			request: []byte{
				'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1',
			},
			err: true,
		},
		{
			name: "Non-MQTT data (random)",
			request: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			err: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, ignore, err := ProcessMQTTEvent(tt.request)
			if tt.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.ignore, ignore, "ignore flag mismatch")
			if !tt.ignore {
				assert.Equal(t, tt.expected, res)
			}
		})
	}
}

func TestProcessPossibleMQTTEvent(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		response []byte
		expected *MQTTInfo
		err      bool
	}{
		{
			name: "PUBLISH in request buffer",
			request: []byte{
				0x30,       // PUBLISH, QoS 0
				0x0c,       // Remaining length: 12
				0x00, 0x0a, // Topic length: 10
				't', 'e', 's', 't', '/', 't', 'o', 'p', 'i', 'c',
			},
			response: []byte{},
			expected: &MQTTInfo{
				PacketType: mqttparser.PacketTypePUBLISH,
				Topic:      "test/topic",
				QoS:        mqttparser.QoSAtMostOnce,
				PacketID:   0,
			},
		},
		{
			name:    "PUBLISH in response buffer (reversed)",
			request: []byte{},
			response: []byte{
				0x30,       // PUBLISH, QoS 0
				0x0c,       // Remaining length: 12
				0x00, 0x0a, // Topic length: 10
				't', 'e', 's', 't', '/', 't', 'o', 'p', 'i', 'c',
			},
			expected: &MQTTInfo{
				PacketType: mqttparser.PacketTypePUBLISH,
				Topic:      "test/topic",
				QoS:        mqttparser.QoSAtMostOnce,
				PacketID:   0,
			},
		},
		{
			name:     "Neither buffer contains valid MQTT",
			request:  []byte{0x00, 0x00, 0x00},
			response: []byte{0x00, 0x00, 0x00},
			err:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &TCPRequestInfo{}
			res, _, err := ProcessPossibleMQTTEvent(event, tt.request, tt.response)
			if tt.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestPacketTypeToMethod(t *testing.T) {
	tests := []struct {
		packetType mqttparser.PacketType
		expected   string
	}{
		{mqttparser.PacketTypePUBLISH, request.MessagingPublish},
		{mqttparser.PacketTypeSUBSCRIBE, request.MessagingProcess},
		{mqttparser.PacketTypeCONNECT, "unknown"},
		{mqttparser.PacketType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			// Access the private function through a test helper
			info := &MQTTInfo{PacketType: tt.packetType}
			span := TCPToMQTTToSpan(&TCPRequestInfo{}, info)
			assert.Equal(t, tt.expected, span.Method)
		})
	}
}

func TestTCPToMQTTToSpan(t *testing.T) {
	trace := &TCPRequestInfo{
		StartMonotimeNs: 1000000,
		EndMonotimeNs:   2000000,
		Direction:       1, // Client
		ConnInfo: BpfConnectionInfoT{
			S_port: 54321,
			D_port: 1883,
		},
	}
	trace.Pid.HostPid = 1234
	trace.Pid.UserPid = 1234
	trace.Pid.Ns = 4026531840

	mqttInfo := &MQTTInfo{
		PacketType: mqttparser.PacketTypePUBLISH,
		Topic:      "sensors/temperature",
		QoS:        mqttparser.QoSAtLeastOnce,
		PacketID:   42,
	}

	span := TCPToMQTTToSpan(trace, mqttInfo)

	assert.Equal(t, request.MessagingPublish, span.Method)
	assert.Equal(t, "sensors/temperature", span.Path)
	assert.Equal(t, int64(1000000), span.RequestStart)
	assert.Equal(t, int64(1000000), span.Start)
	assert.Equal(t, int64(2000000), span.End)
	assert.Equal(t, int(54321), span.PeerPort)
	assert.Equal(t, int(1883), span.HostPort)
	assert.Equal(t, uint32(1234), span.Pid.HostPID)
	assert.Equal(t, uint32(1234), span.Pid.UserPID)
}

// Test with real-world MQTT packet captures
func TestProcessMQTTEvent_RealWorldPackets(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected *MQTTInfo
		ignore   bool
		err      bool
	}{
		{
			name: "real-world PUBLISH to home/temperature",
			request: []byte{
				0x30,       // PUBLISH QoS 0
				0x18,       // Remaining length: 24
				0x00, 0x10, // Topic length: 16
				'h', 'o', 'm', 'e', '/', 't', 'e', 'm', 'p', 'e', 'r', 'a', 't', 'u', 'r', 'e',
				// Payload: "22.5" (not parsed)
				'2', '2', '.', '5', 0x00, 0x00,
			},
			expected: &MQTTInfo{
				PacketType: mqttparser.PacketTypePUBLISH,
				Topic:      "home/temperature",
				QoS:        mqttparser.QoSAtMostOnce,
			},
		},
		{
			name: "AWS IoT style topic",
			request: []byte{
				0x32,       // PUBLISH QoS 1
				0x2a,       // Remaining length: 42
				0x00, 0x26, // Topic length: 38
				'$', 'a', 'w', 's', '/', 't', 'h', 'i', 'n', 'g', 's', '/',
				'm', 'y', '-', 't', 'h', 'i', 'n', 'g', '/',
				's', 'h', 'a', 'd', 'o', 'w', '/', 'u', 'p', 'd', 'a', 't', 'e',
				'/', 'd', 'e', 'l',
				0x00, 0x01, // Packet ID: 1
			},
			expected: &MQTTInfo{
				PacketType: mqttparser.PacketTypePUBLISH,
				Topic:      "$aws/things/my-thing/shadow/update/del",
				QoS:        mqttparser.QoSAtLeastOnce,
				PacketID:   1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, ignore, err := ProcessMQTTEvent(tt.request)
			if tt.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.ignore, ignore)
			if !tt.ignore {
				assert.Equal(t, tt.expected, res)
			}
		})
	}
}

func TestIsMQTT(t *testing.T) {
	// isMQTT is a thin wrapper around NewMQTTControlPacket that returns true/false.
	// We only need to verify the boolean conversion, not re-test the parsing logic.
	validPacket := []byte{0xC0, 0x00}   // PINGREQ - minimal valid MQTT packet
	invalidPacket := []byte{0x00, 0x00} // Reserved packet type (invalid)

	assert.True(t, isMQTT(validPacket), "valid MQTT packet should return true")
	assert.False(t, isMQTT(invalidPacket), "invalid packet should return false")
	assert.False(t, isMQTT(nil), "nil packet should return false")
}
