// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// AMQP 0-9-1 method frame payloads, as bpf/generictracer/protocol_amqp.h copies
// them into its events: class id, method id, then the method arguments.

// Operation091 is the Basic method that carried a message
type Operation091 uint8

const (
	Publish091 Operation091 = iota + 1
	Deliver091
	GetOk091
)

const (
	classBasic091 = 60

	methodPublish091 = 40
	methodDeliver091 = 60
	methodGetOk091   = 71

	shortSize091       = 2
	deliveryTagSize091 = 8
	// Basic.Publish starts with a reserved short, the access ticket of older versions
	publishTicketSize091 = shortSize091
	// Basic.Deliver and Basic.Get-Ok carry a redelivered bit in its own octet
	redeliveredSize091 = 1
)

var (
	ErrNotMessage091 = errors.New("not an AMQP 0-9-1 Basic.Publish, Basic.Deliver or Basic.Get-Ok")
	errTruncated091  = errors.New("AMQP 0-9-1 method frame truncated")
)

// Message091 is what a Basic method frame says about the message it carries
type Message091 struct {
	Operation  Operation091
	Exchange   string
	RoutingKey string
	// DeliveryTag numbers a delivered message in its channel; zero for a publish
	DeliveryTag uint64
}

// ParseMethod091 decodes the payload of a Basic.Publish, Basic.Deliver or
// Basic.Get-Ok method frame. A payload cut inside the exchange or routing key
// yields their characters before the cut, along with errTruncated091.
func ParseMethod091(payload []byte) (Message091, error) {
	r := reader091{buf: payload}
	classID, okClass := r.uint16()
	methodID, okMethod := r.uint16()
	if !okClass || !okMethod || classID != classBasic091 {
		return Message091{}, ErrNotMessage091
	}

	var msg Message091
	switch methodID {
	case methodPublish091:
		msg.Operation = Publish091
		if !r.skip(publishTicketSize091) {
			return msg, errTruncated091
		}
	case methodDeliver091:
		msg.Operation = Deliver091
		if _, ok := r.shortString(); !ok {
			return msg, errTruncated091
		}
		if !r.delivery(&msg) {
			return msg, errTruncated091
		}
	case methodGetOk091:
		msg.Operation = GetOk091
		if !r.delivery(&msg) {
			return msg, errTruncated091
		}
	default:
		return Message091{}, ErrNotMessage091
	}

	var ok bool
	if msg.Exchange, ok = r.shortString(); !ok {
		return msg, errTruncated091
	}
	if msg.RoutingKey, ok = r.shortString(); !ok {
		return msg, errTruncated091
	}
	return msg, nil
}

type reader091 struct {
	buf []byte
	off int
}

func (r *reader091) uint16() (uint16, bool) {
	if len(r.buf)-r.off < shortSize091 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.buf[r.off:])
	r.off += shortSize091
	return v, true
}

func (r *reader091) skip(n int) bool {
	if len(r.buf)-r.off < n {
		return false
	}
	r.off += n
	return true
}

func (r *reader091) delivery(msg *Message091) bool {
	if len(r.buf)-r.off < deliveryTagSize091+redeliveredSize091 {
		return false
	}
	msg.DeliveryTag = binary.BigEndian.Uint64(r.buf[r.off:])
	r.off += deliveryTagSize091 + redeliveredSize091
	return true
}

// shortString reads a length octet and that many bytes; a cut string yields the
// characters before the cut and false
func (r *reader091) shortString() (string, bool) {
	if r.off >= len(r.buf) {
		return "", false
	}
	n := int(r.buf[r.off])
	r.off++
	if len(r.buf)-r.off < n {
		s := string(trimCutRune(r.buf[r.off:]))
		r.off = len(r.buf)
		return s, false
	}
	s := string(r.buf[r.off : r.off+n])
	r.off += n
	return s, true
}

// trimCutRune drops the first bytes of a UTF-8 character the cut splits
func trimCutRune(b []byte) []byte {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if !utf8.RuneStart(b[i]) {
			continue
		}
		if !utf8.FullRune(b[i:]) {
			return b[:i]
		}
		return b
	}
	return b
}
