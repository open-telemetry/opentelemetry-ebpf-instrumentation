// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"

import (
	"errors"
)

const maxFramesParsed = 128

var ErrNotAMQP = errors.New("not AMQP 1.0")

type Result struct {
	LooksLikeAMQP bool
	Truncated     bool
	TransferCount int
}

type frameParseResult struct {
	nextOffset int
	descriptor descriptor
	found      bool
	stop       bool
}

type parserState struct {
	Result
	framesParsed int
}

// Parse parses an AMQP 1.0 payload and returns transfer facts for span creation.
func Parse(data []byte) (Result, error) {
	if len(data) < len(amqpMagic) {
		return Result{}, ErrNotAMQP
	}

	state := parserState{}
	offset := 0
	for offset < len(data) {
		if startsWithMagic(data[offset:]) {
			nextOffset, err := parseProtocolHeaderAt(data, offset)
			if err != nil {
				return state.resultOrError(err)
			}
			state.LooksLikeAMQP = true
			offset = nextOffset
			continue
		}

		if len(data[offset:]) < frameHeaderSize {
			if state.LooksLikeAMQP {
				break
			}
			return Result{}, ErrNotAMQP
		}

		frame, err := parseFrame(data, offset, state.LooksLikeAMQP)
		if err != nil {
			return state.resultOrError(err)
		}
		if frame.found {
			state.LooksLikeAMQP = true
			if frame.descriptor == descriptorTransfer {
				state.TransferCount++
			}
		}
		if frame.stop {
			break
		}

		offset = frame.nextOffset
		state.framesParsed++
		if state.framesParsed >= maxFramesParsed {
			state.Truncated = offset < len(data)
			break
		}
	}

	if state.LooksLikeAMQP {
		return state.Result, nil
	}
	return Result{}, ErrNotAMQP
}

func parseProtocolHeaderAt(data []byte, offset int) (int, error) {
	if len(data[offset:]) < protocolHeaderSize {
		return 0, errors.New("truncated AMQP protocol header")
	}
	if _, err := parseProtocolHeader(data[offset:]); err != nil {
		return 0, err
	}
	return offset + protocolHeaderSize, nil
}

func parseFrame(data []byte, offset int, alreadyAMQP bool) (frameParseResult, error) {
	header, err := parseFrameHeader(data[offset:])
	if errors.Is(err, errIncompleteFrame) {
		descriptor, found, derr := decodeBodyDescriptor(data[offset:], header)
		if derr != nil && alreadyAMQP {
			return frameParseResult{}, derr
		}
		return frameParseResult{
			descriptor: descriptor,
			found:      found,
			stop:       true,
		}, nil
	}
	if err != nil {
		return frameParseResult{}, err
	}

	frameEnd := offset + int(header.Size)
	descriptor, found, err := parsePerformativeDescriptor(data[offset:frameEnd], header)
	if err != nil {
		return frameParseResult{}, err
	}
	return frameParseResult{
		nextOffset: frameEnd,
		descriptor: descriptor,
		found:      found,
	}, nil
}

func (s parserState) resultOrError(err error) (Result, error) {
	if s.LooksLikeAMQP {
		return s.Result, err
	}
	return Result{}, ErrNotAMQP
}

func decodeBodyDescriptor(frame []byte, header frameHeader) (descriptor, bool, error) {
	bodyStart := header.bodyOffset()
	if bodyStart >= len(frame) {
		return 0, false, nil
	}
	return parsePerformativeDescriptor(frame, header)
}
