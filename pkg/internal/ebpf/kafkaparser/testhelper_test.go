// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import (
	"encoding/binary"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

// newTestHeader creates a minimal valid KafkaRequestHeader for body-parser tests.
func newTestHeader(apiKey KafkaAPIKey, apiVersion int16) KafkaRequestHeader {
	flexible := false
	switch apiKey {
	case APIKeyProduce:
		flexible = apiVersion >= 9
	case APIKeyFetch:
		flexible = apiVersion >= 12
	case APIKeyMetadata:
		flexible = apiVersion >= 9
	}
	size := MinKafkaRequestLen
	if flexible {
		size++ // 0x00 byte for empty tagged-fields varint
	}
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[0:4], uint32(size))
	binary.BigEndian.PutUint16(buf[4:6], uint16(int16(apiKey)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(apiVersion))
	binary.BigEndian.PutUint32(buf[8:12], 1) // CorrelationID = 1
	// buf[12:14] = 0 (clientID length = 0)
	// buf[14]   = 0 if flexible (tagged fields = empty, already 0 from make)
	h, err := NewKafkaRequestHeader(largebuf.NewLargeBufferFrom(buf))
	if err != nil {
		panic("newTestHeader: " + err.Error())
	}
	return h
}

// newUncheckedHeader creates a KafkaRequestHeader bypassing validation,
// for tests that need to exercise internal helpers with otherwise-invalid field combos.
func newUncheckedHeader(apiKey KafkaAPIKey, apiVersion int16) KafkaRequestHeader {
	buf := make([]byte, MinKafkaRequestLen)
	binary.BigEndian.PutUint16(buf[4:6], uint16(int16(apiKey)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(apiVersion))
	return KafkaRequestHeader{lb: largebuf.NewLargeBufferFrom(buf)}
}

// buildRawHeaderBuf returns a 14-byte LargeBuffer encoding exactly the four
// fixed header fields. Used by TestValidateKafkaHeader to test validate() in
// isolation without going through NewKafkaRequestHeader.
func buildRawHeaderBuf(msgSize int32, apiKey KafkaAPIKey, apiVersion int16, correlationID int32) *largebuf.LargeBuffer {
	buf := make([]byte, MinKafkaRequestLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(msgSize))
	binary.BigEndian.PutUint16(buf[4:6], uint16(int16(apiKey)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(apiVersion))
	binary.BigEndian.PutUint32(buf[8:12], uint32(correlationID))
	return largebuf.NewLargeBufferFrom(buf)
}
