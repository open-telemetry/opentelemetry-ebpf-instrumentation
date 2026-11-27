// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	iso8583BinaryLength  = 2
	iso8583ASCIILength   = 4
	iso8583MTISize       = 4
	iso8583BitmapSize    = 8
	iso8583HexBitmapSize = 2 * iso8583BitmapSize
	iso8583MinPayload    = iso8583MTISize/2 + iso8583BitmapSize
	iso8583Extended      = uint64(1) << 63
	iso8583MaxFrames     = 32 // covers every minimum-size frame in the default inline capture
	// Both bitmaps and all fields through DE11 in the ASCII timing profile.
	iso8583TimingPrefix = iso8583MTISize + 2*iso8583HexBitmapSize + 2 + 19 + 6 + 3*12 + 10 + 3*8 + 6
)

// Numeric values of the four MTI digits, shared by ASCII and packed BCD messages.
const (
	iso8583Version1993             = 1
	iso8583Version2003             = 2
	iso8583ClassAuthorization      = 1
	iso8583ClassFinancial          = 2
	iso8583ClassNetworkManagement  = 8
	iso8583FunctionRequestResponse = 1
	iso8583FunctionInstructionAck  = 7
	iso8583OriginOtherRepeat       = 5
	iso8583FunctionResponseBit     = 1 // Odd functions are responses or acknowledgements.
)

type iso8583Message struct {
	bitmap       uint64
	mti          [iso8583MTISize]byte
	transmission [10]byte // DE7, MMDDhhmmss
	stan         [6]byte  // DE11, systems trace audit number
	rrn          [12]byte // DE37, retrieval reference number
	packed       bool
	outcome      request.ISO8583AuthOutcome
}

func (m iso8583Message) isResponse() bool {
	return (m.mti[2]-'0')&iso8583FunctionResponseBit != 0
}

func (m iso8583Message) acceptsResponse(r iso8583Message) bool {
	if m.packed != r.packed || m.isResponse() {
		return false
	}

	expected := m.mti
	expected[2]++

	// A response to a repeat can carry the original origin digit (0201 -> 0210).
	if expected[3] != r.mti[3] && expected[3]%2 == 1 {
		expected[3]--
	}

	if expected != r.mti {
		return false
	}

	shared := m.bitmap & r.bitmap
	return (shared&iso8583FieldBit(iso8583TransmissionField) == 0 || (m.transmission[0] != 0 && m.transmission == r.transmission)) &&
		(shared&iso8583FieldBit(iso8583STANField) == 0 || (m.stan[0] != 0 && m.stan == r.stan))
}

// lastFieldToRead returns the last field OBI needs in wire order, or zero to skip the payload.
func (m *iso8583Message) lastFieldToRead(decision bool) int {
	supportedLayout := m.mti[0]-'0' != iso8583Version2003
	switch {
	case supportedLayout && decision && m.hasField(iso8583ResponseCodeField):
		return iso8583ResponseCodeField
	case supportedLayout && m.hasField(iso8583RRNField):
		return iso8583RRNField
	case m.hasField(iso8583STANField):
		return iso8583STANField
	case m.hasField(iso8583TransmissionField):
		return iso8583TransmissionField
	default:
		return 0
	}
}

func (m *iso8583Message) hasField(field int) bool {
	return m.bitmap&iso8583FieldBit(field) != 0
}

func iso8583PayloadSize(prefix []byte) int {
	if len(prefix) == iso8583BinaryLength {
		return int(binary.BigEndian.Uint16(prefix))
	}

	return iso8583DecimalLength(prefix, false)
}

func validISO8583MTI(data []byte) bool {
	var version, class, function, origin byte

	if data[0] < '0' {
		version, class = data[0]>>4, data[0]&0xf
		function, origin = data[1]>>4, data[1]&0xf
	} else {
		version, class = data[0]-'0', data[1]-'0'
		function, origin = data[2]-'0', data[3]-'0'
	}

	return version <= iso8583Version2003 &&
		class >= iso8583ClassAuthorization && class <= iso8583ClassNetworkManagement &&
		function <= iso8583FunctionInstructionAck && origin <= iso8583OriginOtherRepeat
}

func hasISO8583Prefix(buf *largebuf.LargeBuffer) bool {
	if buf.Len() < iso8583BinaryLength+iso8583MinPayload {
		return false
	}

	var header [iso8583ASCIILength + iso8583MTISize]byte
	_ = buf.CopyAt(0, header[:])

	if binary.BigEndian.Uint16(header[:]) >= iso8583MinPayload && validISO8583MTI(header[iso8583BinaryLength:]) {
		return true
	}

	return iso8583PayloadSize(header[:iso8583ASCIILength]) >= iso8583MinPayload && validISO8583MTI(header[iso8583ASCIILength:])
}

func iso8583Bitmap(data []byte) (uint64, bool) {
	if len(data) == iso8583BitmapSize {
		return binary.BigEndian.Uint64(data), true
	}

	var bitmap [iso8583BitmapSize]byte
	_, err := hex.Decode(bitmap[:], data)

	return binary.BigEndian.Uint64(bitmap[:]), err == nil
}

func readISO8583Message(buf *largebuf.LargeBuffer, start, size int) (iso8583Message, bool) {
	var m iso8583Message
	captured := min(size, buf.Len()-start)
	data, _ := buf.UnsafeViewAt(start, min(captured, iso8583TimingPrefix))
	if len(data) < iso8583MinPayload || !validISO8583MTI(data) {
		return m, false
	}

	m.packed = data[0] < '0'
	mtiSize, bitmapSize := iso8583MTISize, iso8583HexBitmapSize

	if m.packed {
		mtiSize, bitmapSize = iso8583MTISize/2, iso8583BitmapSize
		hex.Encode(m.mti[:], data[:mtiSize])
	} else {
		copy(m.mti[:], data[:mtiSize])
	}

	offset := mtiSize + bitmapSize
	if offset > len(data) {
		return m, false
	}

	primary, ok := iso8583Bitmap(data[mtiSize:offset])
	if !ok || primary == 0 {
		return m, false
	}

	secondaryFields := 0
	if primary&iso8583Extended != 0 {
		if offset+bitmapSize > len(data) {
			return m, false
		}
		secondary, ok := iso8583Bitmap(data[offset : offset+bitmapSize])
		if !ok || secondary == 0 || secondary&iso8583Extended != 0 {
			return m, false
		}

		secondaryFields = bits.OnesCount64(secondary)
		offset += bitmapSize
	}

	fieldCount := bits.OnesCount64(primary&^iso8583Extended) + secondaryFields
	if size-offset < fieldCount {
		return m, false
	}

	m.bitmap = primary

	class, function := m.mti[1]-'0', m.mti[2]-'0'
	decision := function == iso8583FunctionRequestResponse && (class == iso8583ClassAuthorization || class == iso8583ClassFinancial)
	if !decision {
		m.outcome = request.ISO8583NotApplicable
	}

	lastField := m.lastFieldToRead(decision)
	if lastField == 0 {
		return m, true
	}

	used := m.readTimingFields(data[offset:])
	if used >= 0 && lastField > iso8583STANField {
		m.readReferenceAndOutcome(buf, start+offset+used, start+size, secondaryFields, lastField)
	}

	return m, true
}

type iso8583Stream struct {
	prefix   int
	messages []iso8583Message
	complete bool
}

func readISO8583Stream(buf *largebuf.LargeBuffer, prefix, observed int, capped bool) iso8583Stream {
	stream := iso8583Stream{prefix: prefix}
	var length [iso8583ASCIILength]byte
	for offset := 0; offset+prefix <= buf.Len() && len(stream.messages) < iso8583MaxFrames; {
		_ = buf.CopyAt(offset, length[:prefix])
		size := iso8583PayloadSize(length[:prefix])
		frameEnd := offset + prefix + size

		if size < iso8583MinPayload || (frameEnd > observed && !capped) {
			break
		}

		message, ok := readISO8583Message(buf, offset+prefix, size)
		if !ok {
			break
		}

		stream.messages = append(stream.messages, message)
		stream.complete = frameEnd >= observed
		if stream.complete {
			break
		}
		offset = frameEnd
	}

	return stream
}

func (conn *iso8583Connection) exchange(x tcpExchange) ([]request.Span, bool) {
	firstOp, recordedFirst := x.firstOperation()
	opposite := x.oppositeOperation()

	var first, second iso8583Stream
	if hasISO8583Prefix(firstOp.data) && hasISO8583Prefix(opposite.data) {
		first, second = readISO8583Exchange(firstOp, opposite)
	}

	var confirmed *iso8583Connection
	if second.complete {
		confirmed = conn
		conn.prefix, conn.packed = first.prefix, first.messages[0].packed
	}

	var spans []request.Span
	for op := range x.initialOperations {
		for _, prefix := range [...]int{iso8583BinaryLength, iso8583ASCIILength} {
			stream := readISO8583Stream(op.data, prefix, op.length, false)
			if stream.complete {
				spans = append(spans, iso8583Responses(x.event, stream, true, op.observed, conn.zone, nil, confirmed)...)
				break
			}
		}
	}

	if !second.complete {
		return spans, false
	}

	var paired *iso8583Message
	if len(first.messages) == 1 {
		call := first.messages[0]
		if !recordedFirst && !call.isResponse() {
			conn.remember(call, first.prefix, firstOp.direction, firstOp.observed)
		}

		if firstOp.length == x.initialWireLen() &&
			len(second.messages) == 1 && call.acceptsResponse(second.messages[0]) {
			paired = &call
		}
	}

	return append(spans, iso8583Responses(x.event, second, false, opposite.observed, conn.zone, paired, confirmed)...), true
}

func readISO8583Exchange(initial, opposite tcpOperation) (iso8583Stream, iso8583Stream) {
	for _, prefix := range [...]int{iso8583BinaryLength, iso8583ASCIILength} {
		first := readISO8583Stream(initial.data, prefix, initial.length, false)
		if !first.complete {
			continue
		}
		second := readISO8583Stream(opposite.data, prefix, opposite.length, opposite.capped)
		if second.complete && first.messages[0].packed == second.messages[0].packed {
			return first, second
		}
	}
	return iso8583Stream{}, iso8583Stream{}
}

func iso8583Responses(event *TCPRequestInfo, stream iso8583Stream, first bool, observed uint64, zone *time.Location, paired *iso8583Message, conn *iso8583Connection) []request.Span {
	var spans []request.Span
	if observed == 0 {
		return nil
	}

	direction := event.Direction
	if !first {
		direction = reverseDirection(direction)
	}

	var wallTime time.Time
	for _, reply := range stream.messages {
		if !reply.isResponse() {
			if conn != nil && (!first || (stream.prefix == conn.prefix && reply.packed == conn.packed)) {
				conn.remember(reply, stream.prefix, direction, observed)
			}
			continue
		}

		if reply.transmission[0] != 0 && wallTime.IsZero() {
			wallTime = timing.KernelTime(observed)
		}

		age, estimated := iso8583ResponseTime(reply.transmission, wallTime, zone)
		mti := reply.mti
		mti[2]--

		var direct iso8583Pending
		if paired != nil {
			direct = iso8583Pending{message: *paired, observed: event.StartMonotimeNs}
		}

		matched := conn.take(reply, stream.prefix, direction, observed, direct)
		start := matched.observed

		if start != 0 {
			mti = matched.message.mti
		}

		estimated = estimated && uint64(age) <= observed
		if estimated {
			start = observed - uint64(age)
		}

		if start == 0 || start > observed {
			continue
		}

		span := iso8583Span(event, string(mti[:]), first, start, observed)
		span.ISO8583Field7Timing = estimated
		span.ISO8583Outcome = reply.outcome
		span.ISO8583References = reply.references(matched.message)
		if paired != nil && matched.observed == event.StartMonotimeNs {
			span.ContentLength = int64(event.ReqLen)
			span.TraceID = event.Tp.TraceId
			span.SpanID = event.Tp.SpanId
			span.ParentSpanID = event.Tp.ParentId
			span.TraceFlags = event.Tp.Flags
			span.ParentConditional = event.ParentStatus == parentStatusConditional
		}

		spans = append(spans, span)
	}

	return spans
}

// Use the reply's identifiers when available, falling back to its matched request.
func (m iso8583Message) references(call iso8583Message) *request.ISO8583References {
	stan := cmp.Or(m.stan, call.stan)
	rrn := cmp.Or(m.rrn, call.rrn)
	if stan[0] == 0 && rrn[0] == 0 {
		return nil
	}

	refs := &request.ISO8583References{}
	if stan[0] != 0 {
		refs.STAN = string(stan[:])
	}

	if rrn[0] != 0 {
		refs.RRN = strings.TrimRight(string(rrn[:]), " ")
	}

	return refs
}

func iso8583Span(event *TCPRequestInfo, mti string, first bool, start, end uint64) request.Span {
	kind := request.EventTypeISO8583Server
	if (event.Direction == directionRecv) == first {
		kind = request.EventTypeISO8583Client
	}

	var peer, host string
	peerPort, hostPort := event.ConnInfo.S_port, event.ConnInfo.D_port
	if peerPort != 0 || hostPort != 0 {
		peer, host = (*BPFConnInfo)(&event.ConnInfo).reqHostInfo()
	}

	// TCP normalizes its endpoints around the first captured direction.
	if first {
		peer, host = host, peer
		peerPort, hostPort = hostPort, peerPort
	}

	return request.Span{
		Type:         kind,
		Method:       mti,
		Peer:         peer,
		PeerPort:     int(peerPort),
		Host:         host,
		HostPort:     int(hostPort),
		RequestStart: int64(start),
		Start:        int64(start),
		End:          int64(end),
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
	}
}
