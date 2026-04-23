// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	frameHeaderSize = 8

	// dataOffsetUnit: per AMQP 1.0 the body offset is expressed in 4-byte words.
	dataOffsetUnit = 4

	// minDataOffsetWords: doff >= 2 ensures the body offset covers the 8-byte frame header
	minDataOffsetWords = 2

	describedTypeConstructor byte = 0x00

	formatCodeSmallULong byte = 0x53
	formatCodeULong      byte = 0x80

	// Described-type prefix sizes: 0x00 constructor + format code + (1|8)-byte value.
	smallULongDescriptorSize = 3
	uLongDescriptorSize      = 10

	frameTypeAMQP frameType = 0x00
	frameTypeSASL frameType = 0x01

	descriptorOpen        descriptor = 0x10
	descriptorBegin       descriptor = 0x11
	descriptorAttach      descriptor = 0x12
	descriptorFlow        descriptor = 0x13
	descriptorTransfer    descriptor = 0x14
	descriptorDisposition descriptor = 0x15
	descriptorDetach      descriptor = 0x16
	descriptorEnd         descriptor = 0x17
	descriptorClose       descriptor = 0x18

	descriptorSASLMechanisms descriptor = 0x40
	descriptorSASLInit       descriptor = 0x41
	descriptorSASLChallenge  descriptor = 0x42
	descriptorSASLResponse   descriptor = 0x43
	descriptorSASLOutcome    descriptor = 0x44
)

// errIncompleteFrame signals the buffer ends before the full frame body; callers may
// try to recover the performative from the available prefix.
var errIncompleteFrame = errors.New("incomplete AMQP frame")

type frameType uint8

type descriptor uint64

type frameHeader struct {
	Size            uint32
	DataOffsetWords uint8
	Type            frameType
}

func (h frameHeader) bodyOffset() int {
	return int(h.DataOffsetWords) * dataOffsetUnit
}

// parseFrameHeader validates and parses the fixed 8-byte AMQP frame header.
func parseFrameHeader(frame []byte) (frameHeader, error) {
	if len(frame) < frameHeaderSize {
		return frameHeader{}, fmt.Errorf("packet too short for AMQP frame header: have %d bytes, need %d", len(frame), frameHeaderSize)
	}

	size := binary.BigEndian.Uint32(frame[:4])
	if size < frameHeaderSize {
		return frameHeader{}, fmt.Errorf("invalid AMQP frame size %d (must be >= %d)", size, frameHeaderSize)
	}

	doff := frame[4]
	if doff < minDataOffsetWords {
		return frameHeader{}, fmt.Errorf("invalid AMQP frame data offset %d (must be >= %d)", doff, minDataOffsetWords)
	}

	h := frameHeader{
		Size:            size,
		DataOffsetWords: doff,
		Type:            frameType(frame[5]),
	}

	if h.bodyOffset() > int(h.Size) {
		return frameHeader{}, fmt.Errorf("invalid AMQP frame body offset %d (exceeds frame size %d)", h.bodyOffset(), h.Size)
	}

	switch h.Type {
	case frameTypeAMQP, frameTypeSASL:
	default:
		return frameHeader{}, fmt.Errorf("invalid AMQP frame type 0x%02X", byte(h.Type))
	}

	if int(size) > len(frame) {
		return h, errIncompleteFrame
	}

	return h, nil
}

// parsePerformativeDescriptor reads the described-type ulong descriptor from a frame
// payload.
func parsePerformativeDescriptor(frame []byte, header frameHeader) (descriptor, bool, error) {
	bodyStart := header.bodyOffset()
	if bodyStart > len(frame) {
		return 0, false, fmt.Errorf("AMQP frame body offset %d out of range (frame len %d)", bodyStart, len(frame))
	}
	body := frame[bodyStart:]

	desc, _, found, err := parseDescriptor(body, header.Type)
	return desc, found, err
}

// parseDescriptor attempts to decode a described-type ulong descriptor from the start of the provided body.
func parseDescriptor(body []byte, ft frameType) (descriptor, int, bool, error) {
	if len(body) == 0 {
		// AMQP heartbeat: zero-length body.
		return 0, 0, false, nil
	}
	if len(body) < smallULongDescriptorSize {
		return 0, 0, false, fmt.Errorf("AMQP frame body too short for performative: %d bytes", len(body))
	}
	if body[0] != describedTypeConstructor {
		return 0, 0, false, fmt.Errorf("AMQP performative is not described (first byte 0x%02X)", body[0])
	}

	var desc descriptor
	var descriptorLen int
	switch body[1] {
	case formatCodeSmallULong:
		desc = descriptor(body[2])
		descriptorLen = smallULongDescriptorSize
	case formatCodeULong:
		if len(body) < uLongDescriptorSize {
			return 0, 0, false, fmt.Errorf("AMQP ulong descriptor truncated: %d bytes, need %d", len(body), uLongDescriptorSize)
		}
		desc = descriptor(binary.BigEndian.Uint64(body[2:uLongDescriptorSize]))
		descriptorLen = uLongDescriptorSize
	default:
		return 0, 0, false, fmt.Errorf("unsupported AMQP descriptor encoding 0x%02X", body[1])
	}

	if !isKnownPerformativeDescriptor(ft, desc) {
		return 0, 0, false, fmt.Errorf("unknown AMQP performative descriptor 0x%X on frame type 0x%02X", uint64(desc), byte(ft))
	}

	return desc, descriptorLen, true, nil
}

// isKnownPerformativeDescriptor reports whether descriptor is a standard AMQP 1.0
// performative for the provided frame type.
func isKnownPerformativeDescriptor(ft frameType, descriptor descriptor) bool {
	switch ft {
	case frameTypeAMQP:
		switch descriptor {
		case descriptorOpen,
			descriptorBegin,
			descriptorAttach,
			descriptorFlow,
			descriptorTransfer,
			descriptorDisposition,
			descriptorDetach,
			descriptorEnd,
			descriptorClose:
			return true
		}
	case frameTypeSASL:
		switch descriptor {
		case descriptorSASLMechanisms,
			descriptorSASLInit,
			descriptorSASLChallenge,
			descriptorSASLResponse,
			descriptorSASLOutcome:
			return true
		}
	}

	return false
}
