// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConnectPacketWithRealPacket(t *testing.T) {
	// Real MQTT CONNECT packet from test
	packet := []byte{
		0x10,       // CONNECT, flags=0
		0x2B,       // remaining length = 43
		0x00, 0x04, // protocol name length = 4
		0x4D, 0x51, 0x54, 0x54, // "MQTT"
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
	}

	// Parse fixed header first
	parsed, err := NewMQTTControlPacket(packet)
	require.NoError(t, err)
	assert.Equal(t, PacketTypeCONNECT, parsed.FixedHeader.PacketType)
	assert.Equal(t, uint8(0), parsed.FixedHeader.Flags)
	assert.Equal(t, 43, parsed.FixedHeader.RemainingLength)
	assert.Equal(t, 2, parsed.FixedHeader.Length)

	// Parse CONNECT packet starting from variable header
	connect, offset, err := ParseConnectPacket(packet, parsed.FixedHeader.Length)
	require.NoError(t, err)
	require.NotNil(t, connect)

	assert.Equal(t, ProtocolNameMQTT, connect.Protocol.Name)
	assert.Equal(t, "MQTT", connect.Protocol.Name.String())
	assert.Equal(t, ProtocolLevelMQTT311, connect.Protocol.Level)
	assert.True(t, connect.CleanStart)
	assert.Equal(t, uint16(60), connect.KeepAlive)
	assert.Equal(t, "pythonmqtt_publisher_1765206934", connect.ClientID)

	// Verify offset is correct (header + variable header + payload)
	expectedOffset := parsed.Length()
	assert.Equal(t, expectedOffset, offset)
}

func TestParseConnectPacket(t *testing.T) {
	tests := []struct {
		name           string
		packet         []byte
		offset         Offset
		expectErr      bool
		expected       *ConnectPacket
		expectedOffset Offset
	}{
		{
			name: "MQTT 3.1.1 with clean session",
			packet: []byte{
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x04,       // protocol level = 4 (MQTT 3.1.1)
				0x02,       // connect flags (clean session=1)
				0x00, 0x3C, // keep alive = 60
				0x00, 0x04, // client ID length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
			},
			offset: 0,
			expected: &ConnectPacket{
				Protocol: Protocol{
					Name:  ProtocolNameMQTT,
					Level: ProtocolLevelMQTT311,
				},
				CleanStart: true,
				KeepAlive:  60,
				ClientID:   "test",
			},
			expectedOffset: 16,
		},
		{
			name: "MQTT 3.1.1 without clean session",
			packet: []byte{
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x04,       // protocol level = 4
				0x00,       // connect flags (clean session=0)
				0x00, 0x3C, // keep alive = 60
				0x00, 0x04, // client ID length = 4
				0x74, 0x65, 0x73, 0x73, // "tess"
			},
			offset: 0,
			expected: &ConnectPacket{
				Protocol: Protocol{
					Name:  ProtocolNameMQTT,
					Level: ProtocolLevelMQTT311,
				},
				CleanStart: false,
				KeepAlive:  60,
				ClientID:   "tess",
			},
			expectedOffset: 16,
		},
		{
			name: "MQTT 3.1 (MQIsdp)",
			packet: []byte{
				0x00, 0x06, // protocol name length = 6
				0x4D, 0x51, 0x49, 0x73, 0x64, 0x70, // "MQIsdp"
				0x03,       // protocol level = 3 (MQTT 3.1)
				0x02,       // connect flags (clean session=1)
				0x00, 0x3C, // keep alive = 60
				0x00, 0x05, // client ID length = 5
				0x68, 0x65, 0x6C, 0x6C, 0x6F, // "hello"
			},
			offset: 0,
			expected: &ConnectPacket{
				Protocol: Protocol{
					Name:  ProtocolNameMQIsdp,
					Level: ProtocolLevelMQTT31,
				},
				CleanStart: true,
				KeepAlive:  60,
				ClientID:   "hello",
			},
			expectedOffset: 19,
		},
		{
			name: "MQTT 5.0 with properties",
			packet: []byte{
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x05,       // protocol level = 5 (MQTT 5.0)
				0x02,       // connect flags (clean session=1)
				0x00, 0x3C, // keep alive = 60
				0x03,             // Property Length = 3
				0x11, 0x22, 0x33, // Properties bytes (3 bytes)
				0x00, 0x04, // client ID length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
			},
			offset: 0,
			expected: &ConnectPacket{
				Protocol: Protocol{
					Name:  ProtocolNameMQTT,
					Level: ProtocolLevelMQTT50,
				},
				CleanStart: true,
				KeepAlive:  60,
				ClientID:   "test",
			},
			expectedOffset: 20,
		},
		{
			name: "MQTT 5.0 with empty properties",
			packet: []byte{
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x05,       // protocol level = 5 (MQTT 5.0)
				0x02,       // connect flags (clean session=1)
				0x00, 0x3C, // keep alive = 60
				0x00,       // Property Length = 0 (no properties)
				0x00, 0x04, // client ID length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
			},
			offset: 0,
			expected: &ConnectPacket{
				Protocol: Protocol{
					Name:  ProtocolNameMQTT,
					Level: ProtocolLevelMQTT50,
				},
				CleanStart: true,
				KeepAlive:  60,
				ClientID:   "test",
			},
			expectedOffset: 17,
		},
		{
			name:      "error: offset beyond packet",
			packet:    []byte{0x00},
			offset:    5,
			expectErr: true,
		},
		{
			name:      "error: ReadProtocol fails",
			packet:    []byte{0x00}, // insufficient for protocol name length
			offset:    0,
			expectErr: true,
		},
		{
			name: "error: ReadConnectFlags fails",
			packet: []byte{
				0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x04, // protocol level
				// missing connect flags
			},
			offset:    0,
			expectErr: true,
		},
		{
			name: "error: ReadKeepAlive fails",
			packet: []byte{
				0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x04, // protocol level
				0x02, // connect flags
				// missing keep alive
			},
			offset:    0,
			expectErr: true,
		},
		{
			name: "error: SkipProperties fails (MQTT 5.0)",
			packet: []byte{
				0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x05,       // protocol level = 5 (MQTT 5.0)
				0x02,       // connect flags
				0x00, 0x3C, // keep alive
				0x03, 0x11, // property length = 3, but only 1 byte
			},
			offset:    0,
			expectErr: true,
		},
		{
			name: "error: ReadClientID fails",
			packet: []byte{
				0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x04,       // protocol level
				0x02,       // connect flags
				0x00, 0x3C, // keep alive
				0x00, 0x04, // client ID length = 4
				0x74, 0x65, // only 2 bytes
			},
			offset:    0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connect, offset, err := ParseConnectPacket(tt.packet, tt.offset)

			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, connect)
			assert.Equal(t, tt.expected.Protocol.Name, connect.Protocol.Name)
			assert.Equal(t, tt.expected.Protocol.Level, connect.Protocol.Level)
			assert.Equal(t, tt.expected.CleanStart, connect.CleanStart)
			assert.Equal(t, tt.expected.KeepAlive, connect.KeepAlive)
			assert.Equal(t, tt.expected.ClientID, connect.ClientID)
			assert.Equal(t, tt.expectedOffset, offset)
		})
	}
}

func TestNewProtocol(t *testing.T) {
	tests := []struct {
		name      string
		protoName string
		level     uint8
		expectErr bool
		expected  *Protocol
	}{
		{
			name:      "valid MQTT 3.1.1",
			protoName: "MQTT",
			level:     4,
			expectErr: false,
			expected: &Protocol{
				Name:  ProtocolNameMQTT,
				Level: ProtocolLevelMQTT311,
			},
		},
		{
			name:      "valid MQTT 3.1",
			protoName: "MQIsdp",
			level:     3,
			expectErr: false,
			expected: &Protocol{
				Name:  ProtocolNameMQIsdp,
				Level: ProtocolLevelMQTT31,
			},
		},
		{
			name:      "valid MQTT 5.0",
			protoName: "MQTT",
			level:     5,
			expectErr: false,
			expected: &Protocol{
				Name:  ProtocolNameMQTT,
				Level: ProtocolLevelMQTT50,
			},
		},
		{
			name:      "invalid protocol name",
			protoName: "HTTP",
			level:     4,
			expectErr: true,
		},
		{
			name:      "invalid protocol level",
			protoName: "MQTT",
			level:     6,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proto, err := NewProtocol(tt.protoName, tt.level)

			if tt.expectErr {
				require.Error(t, err)
				assert.Nil(t, proto)
			} else {
				require.NoError(t, err)
				require.NotNil(t, proto)
				assert.Equal(t, tt.expected.Name, proto.Name)
				assert.Equal(t, tt.expected.Level, proto.Level)
			}
		})
	}
}

func TestProtocolIsValid(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		expected bool
	}{
		{
			name: "valid MQTT 3.1",
			protocol: Protocol{
				Name:  ProtocolNameMQIsdp,
				Level: ProtocolLevelMQTT31,
			},
			expected: true,
		},
		{
			name: "valid MQTT 3.1.1",
			protocol: Protocol{
				Name:  ProtocolNameMQTT,
				Level: ProtocolLevelMQTT311,
			},
			expected: true,
		},
		{
			name: "valid MQTT 5.0",
			protocol: Protocol{
				Name:  ProtocolNameMQTT,
				Level: ProtocolLevelMQTT50,
			},
			expected: true,
		},
		{
			name: "invalid - MQTT 3.1 with wrong name",
			protocol: Protocol{
				Name:  ProtocolNameMQTT,
				Level: ProtocolLevelMQTT31,
			},
			expected: false,
		},
		{
			name: "invalid - MQTT 3.1.1 with wrong name",
			protocol: Protocol{
				Name:  ProtocolNameMQIsdp,
				Level: ProtocolLevelMQTT311,
			},
			expected: false,
		},
		{
			name: "invalid - unknown level",
			protocol: Protocol{
				Name:  ProtocolNameMQTT,
				Level: ProtocolLevel(99),
			},
			expected: false,
		},
		{
			name: "invalid - zero value",
			protocol: Protocol{
				Name:  "",
				Level: 0,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.protocol.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewProtocolLevel(t *testing.T) {
	tests := []struct {
		name           string
		level          uint8
		expectErr      bool
		expected       ProtocolLevel
		expectedString string
	}{
		{
			name:           "valid MQTT 3.1",
			level:          3,
			expectErr:      false,
			expected:       ProtocolLevelMQTT31,
			expectedString: "3.1",
		},
		{
			name:           "valid MQTT 3.1.1",
			level:          4,
			expectErr:      false,
			expected:       ProtocolLevelMQTT311,
			expectedString: "3.1.1",
		},
		{
			name:           "valid MQTT 5.0",
			level:          5,
			expectErr:      false,
			expected:       ProtocolLevelMQTT50,
			expectedString: "5.0",
		},
		{
			name:           "unknown level",
			level:          42,
			expectErr:      true,
			expectedString: "42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, err := NewProtocolLevel(tt.level)

			if tt.expectErr {
				require.Error(t, err)
				assert.Equal(t, ProtocolLevel(0), level)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, level)
			}
			assert.Equal(t, tt.expectedString, ProtocolLevel(tt.level).String())
		})
	}
}

func TestConnectPacketReaderReadProtocol(t *testing.T) {
	tests := []struct {
		name           string
		pkt            []byte
		expectErr      bool
		expectedName   ProtocolName
		expectedLevel  ProtocolLevel
		expectedOffset int
	}{
		{
			name: "valid MQTT 3.1.1",
			pkt: []byte{
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x04, // protocol level = 4 (MQTT 3.1.1)
			},
			expectErr:      false,
			expectedName:   ProtocolNameMQTT,
			expectedLevel:  ProtocolLevelMQTT311,
			expectedOffset: 7,
		},
		{
			name: "valid MQTT 5.0",
			pkt: []byte{
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				0x05, // protocol level = 5 (MQTT 5.0)
			},
			expectErr:      false,
			expectedName:   ProtocolNameMQTT,
			expectedLevel:  ProtocolLevelMQTT50,
			expectedOffset: 7,
		},
		{
			name: "valid MQIsdp (MQTT 3.1)",
			pkt: []byte{
				0x00, 0x06, // protocol name length = 6
				0x4D, 0x51, 0x49, 0x73, 0x64, 0x70, // "MQIsdp"
				0x03, // protocol level = 3 (MQTT 3.1)
			},
			expectErr:      false,
			expectedName:   ProtocolNameMQIsdp,
			expectedLevel:  ProtocolLevelMQTT31,
			expectedOffset: 9,
		},
		{
			name: "insufficient data for protocol name length",
			pkt: []byte{
				0x00, // only one byte
			},
			expectErr: true,
		},
		{
			name: "insufficient data for protocol name",
			pkt: []byte{
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, // only 2 bytes, need 4
			},
			expectErr: true,
		},
		{
			name: "invalid protocol name",
			pkt: []byte{
				0x00, 0x04, // protocol name length = 4
				0x48, 0x54, 0x54, 0x50, // "HTTP" (invalid)
				0x04, // protocol level
			},
			expectErr: true,
		},
		{
			name: "insufficient data for protocol level",
			pkt: []byte{
				0x00, 0x04, // protocol name length = 4
				0x4D, 0x51, 0x54, 0x54, // "MQTT"
				// missing protocol level
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewConnectPacketReader(tt.pkt, 0)
			protocol, err := r.ReadProtocol()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedName, protocol.Name)
				assert.Equal(t, tt.expectedLevel, protocol.Level)
				assert.Equal(t, tt.expectedOffset, r.Offset())
			}
		})
	}
}

func TestConnectPacketReaderReadConnectFlags(t *testing.T) {
	tests := []struct {
		name               string
		pkt                []byte
		expectErr          bool
		expectedCleanStart bool
	}{
		{
			name:               "clean start set",
			pkt:                []byte{0x02}, // bit 1 set
			expectErr:          false,
			expectedCleanStart: true,
		},
		{
			name:               "clean start not set",
			pkt:                []byte{0x00},
			expectErr:          false,
			expectedCleanStart: false,
		},
		{
			name:               "clean start with other flags",
			pkt:                []byte{0xFE}, // all bits except bit 0 set
			expectErr:          false,
			expectedCleanStart: true,
		},
		{
			name:      "insufficient data",
			pkt:       []byte{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewConnectPacketReader(tt.pkt, 0)
			cleanStart, err := r.ReadConnectFlags()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCleanStart, cleanStart)
			}
		})
	}
}

func TestConnectPacketReaderReadKeepAlive(t *testing.T) {
	tests := []struct {
		name              string
		pkt               []byte
		expectErr         bool
		expectedKeepAlive uint16
	}{
		{
			name:              "keep alive 60 seconds",
			pkt:               []byte{0x00, 0x3C}, // 60
			expectErr:         false,
			expectedKeepAlive: 60,
		},
		{
			name:              "keep alive 0 (disabled)",
			pkt:               []byte{0x00, 0x00},
			expectErr:         false,
			expectedKeepAlive: 0,
		},
		{
			name:              "keep alive max value",
			pkt:               []byte{0xFF, 0xFF}, // 65535
			expectErr:         false,
			expectedKeepAlive: 65535,
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
			r := NewConnectPacketReader(tt.pkt, 0)
			keepAlive, err := r.ReadKeepAlive()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedKeepAlive, keepAlive)
			}
		})
	}
}

func TestConnectPacketReaderSkipProperties(t *testing.T) {
	tests := []struct {
		name           string
		pkt            []byte
		expectErr      bool
		expectedOffset int
	}{
		{
			name: "valid properties skip",
			pkt: []byte{
				0x03,             // property length = 3
				0x11, 0x22, 0x33, // properties bytes
			},
			expectErr:      false,
			expectedOffset: 4,
		},
		{
			name: "empty properties",
			pkt: []byte{
				0x00, // property length = 0
			},
			expectErr:      false,
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
				0x03,       // property length = 3
				0x11, 0x22, // only 2 bytes, need 3
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewConnectPacketReader(tt.pkt, 0)
			err := r.SkipProperties()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedOffset, r.Offset())
			}
		})
	}
}

func TestConnectPacketReaderReadClientID(t *testing.T) {
	tests := []struct {
		name             string
		pkt              []byte
		expectErr        bool
		expectedClientID string
		expectedOffset   int
	}{
		{
			name: "simple client ID",
			pkt: []byte{
				0x00, 0x04, // client ID length = 4
				0x74, 0x65, 0x73, 0x74, // "test"
			},
			expectErr:        false,
			expectedClientID: "test",
			expectedOffset:   6,
		},
		{
			name: "empty client ID",
			pkt: []byte{
				0x00, 0x00, // client ID length = 0
			},
			expectErr:        false,
			expectedClientID: "",
			expectedOffset:   2,
		},
		{
			name: "long client ID",
			pkt: []byte{
				0x00, 0x1F, // client ID length = 31
				// "pythonmqtt_publisher_1765206934"
				0x70, 0x79, 0x74, 0x68, 0x6F, 0x6E, // "python"
				0x6D, 0x71, 0x74, 0x74, // "mqtt"
				0x5F,                                                 // "_"
				0x70, 0x75, 0x62, 0x6C, 0x69, 0x73, 0x68, 0x65, 0x72, // "publisher"
				0x5F,                                                       // "_"
				0x31, 0x37, 0x36, 0x35, 0x32, 0x30, 0x36, 0x39, 0x33, 0x34, // "1765206934"
			},
			expectErr:        false,
			expectedClientID: "pythonmqtt_publisher_1765206934",
			expectedOffset:   33,
		},
		{
			name: "insufficient data for length",
			pkt: []byte{
				0x00, // only one byte
			},
			expectErr: true,
		},
		{
			name: "insufficient data for client ID",
			pkt: []byte{
				0x00, 0x04, // client ID length = 4
				0x74, 0x65, // only 2 bytes, need 4
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewConnectPacketReader(tt.pkt, 0)
			clientID, err := r.ReadClientID()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedClientID, clientID)
				assert.Equal(t, tt.expectedOffset, r.Offset())
			}
		})
	}
}
