// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"fmt"
	"testing"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"
)

const maxMQTTFuzzInput = 4096

func mqttFuzzPacket(first byte, body ...byte) []byte {
	packet := []byte{first}
	remaining := len(body)
	for {
		encoded := byte(remaining % 128)
		remaining /= 128
		if remaining > 0 {
			encoded |= 0x80
		}
		packet = append(packet, encoded)
		if remaining == 0 {
			break
		}
	}
	return append(packet, body...)
}

func mqttParserSeeds() [][]byte {
	largePublishBody := append([]byte{0x00, 0x01, 'a'}, make([]byte, 125)...)
	publish := mqttFuzzPacket(0x3b,
		0x00, 0x08, 'a', '/', 'b', '/', 'c', '/', 'd', 'e',
		0x12, 0x34, 'b', 'o', 'd', 'y')
	subscribe := mqttFuzzPacket(0x82,
		0x00, 0x07, 0x00, 0x03, 'a', '/', '+', 0x01,
		0x00, 0x03, 'b', '/', '#', 0x02)
	subscribeV5 := mqttFuzzPacket(0x82,
		0x00, 0x08, 0x02, 0x0b, 0x01,
		0x00, 0x03, 'c', '/', '+', 0x05)
	connectV5 := mqttFuzzPacket(0x10,
		0x00, 0x04, 'M', 'Q', 'T', 'T', 0x05, 0x02, 0x00, 0x3c,
		0x02, 0x21, 0x01, 0x00, 0x03, 'c', 'l', 'i')
	validPublish := mqttFuzzPacket(0x30, 0x00, 0x03, 'a', '/', 'b')

	return [][]byte{
		publish,
		mqttFuzzPacket(0x30, largePublishBody...),
		subscribe,
		subscribeV5,
		connectV5,
		append([]byte{0x30, 0x02, 0x00, 0x01}, validPublish...),
		append([]byte{0x10, 0x02, 0x00, 0x04}, validPublish...),
		validPublish[:len(validPublish)-1],
		{0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'a'},
		{0x30, 0x80, 0x00},
		{0x30, 0x80, 0x80, 0x00},
		{0x30, 0x80, 0x80, 0x80, 0x00},
		{0x30, 0x80, 0x80, 0x80, 0x80},
		{0x30, 0x80, 0x80, 0x80, 0x80, 0x00},
		{0x36, 0x03, 0x00, 0x01, 'a'},
	}
}

func checkMQTTParser(t *testing.T, data []byte) {
	t.Helper()
	if len(data) > maxMQTTFuzzInput {
		return
	}

	packets, parseErr := mqttparser.ParseMQTTPackets(data)
	info, ignore, err := ProcessMQTTEvent(data)
	if parseErr != nil {
		if err == nil {
			t.Fatal("event parser accepted invalid MQTT framing")
		}
		return
	}

	offset := 0
	var expected *MQTTInfo
	for i, packet := range packets {
		length := packet.Length()
		if packet.FixedHeader.Length < mqttparser.MinPacketLen ||
			packet.FixedHeader.Length > 5 || length < packet.FixedHeader.Length {
			t.Fatalf("packet %d has invalid lengths: header=%d total=%d",
				i, packet.FixedHeader.Length, length)
		}
		if offset > len(data) || length > len(data)-offset {
			t.Fatalf("packet %d extends past input: offset=%d length=%d input=%d",
				i, offset, length, len(data))
		}

		end := offset + length
		boundedInfo, boundedIgnore, boundedErr := ProcessMQTTEvent(data[offset:end])
		if expected == nil && boundedErr == nil && !boundedIgnore {
			expected = boundedInfo
		}
		offset = end
	}
	if len(data)-offset >= mqttparser.MinPacketLen {
		t.Fatalf("parser left %d unconsumed bytes", len(data)-offset)
	}

	if expected == nil {
		if err == nil {
			t.Fatalf("segment produced span-worthy packet from adjacent data: %+v", info)
		}
		return
	}
	if err != nil {
		t.Fatalf("bounded packet parsed but segment failed: %v", err)
	}
	if ignore || info == nil {
		t.Fatalf("successful parse returned ignore=%v info=%+v", ignore, info)
	}
	if *info != *expected {
		t.Fatalf("segment result used data outside packet: got %+v, want %+v", info, expected)
	}
}

func TestMQTTParserCorpus(t *testing.T) {
	for i, seed := range mqttParserSeeds() {
		t.Run(fmt.Sprintf("seed-%d", i), func(t *testing.T) {
			checkMQTTParser(t, seed)
		})
	}
}

func FuzzMQTTParser(f *testing.F) {
	for _, seed := range mqttParserSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		checkMQTTParser(t, data)
	})
}
