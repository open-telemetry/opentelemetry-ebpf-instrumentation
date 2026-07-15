// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"
)

func TestIsValidMQTTPacket(t *testing.T) {
	tests := []struct {
		name     string
		info     *MQTTInfo
		expected bool
	}{
		{
			name: "valid packet with client ID",
			info: &MQTTInfo{
				ClientID:   "test-client",
				Topic:      "",
				PacketType: mqttparser.PacketTypePUBLISH,
			},
			expected: true,
		},
		{
			name: "valid packet with topic",
			info: &MQTTInfo{
				ClientID:   "",
				Topic:      "test/topic",
				PacketType: mqttparser.PacketTypePUBLISH,
			},
			expected: true,
		},
		{
			name: "invalid packet - both empty",
			info: &MQTTInfo{
				ClientID:   "",
				Topic:      "",
				PacketType: mqttparser.PacketTypePUBLISH,
			},
			expected: false,
		},
		{
			name: "invalid packet - nil info",
			info: nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidMQTTPacket(tt.info)
			if result != tt.expected {
				t.Errorf("isValidMQTTPacket() = %v, want %v", result, tt.expected)
			}
		})
	}
}