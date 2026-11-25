// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
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

// The probe copies a possible standalone reply without consuming it. Leave protocol state,
// HTTP/2 rerouting and span emission to the normal TCP record if the copy is ambiguous.
func matchesOtherStandaloneTCPProtocol(cfg *config.EBPFTracer, event *TCPRequestInfo, buf, empty *largebuf.LargeBuffer) bool {
	if event.EventSource == GenericEventSourceTypeKProbes && isHTTP2(buf, int(event.Len)) {
		return true
	}

	if _, ok := parsePostgresStartup(buf); ok {
		return true
	}

	if buf.Len() >= msgHeaderSize {
		if header, err := parseMongoHeader(buf.UnsafeView()); err == nil && header.OpCode == opMsg {
			return true
		}
	}

	var stateless EBPFParseContext
	// MongoDB correlation needs a live request cache. Its OP_MSG header above is
	// sufficient for a standalone copy. The other generic matchers can run without state.
	if _, _, matched, _ := matchSQL(&stateless, cfg, event, buf, empty); matched {
		return true
	}
	if _, _, matched, _ := matchFastCGI(event, buf, empty); matched {
		return true
	}
	if _, _, matched, _ := matchCouchbase(&stateless, cfg, event, buf, empty); matched {
		return true
	}
	if _, _, matched, _ := matchMemcachedNoreply(&stateless, event, buf, empty); matched {
		return true
	}

	_, _, matched, _ := detectHeuristicProtocol(&stateless, event, buf, empty)

	return matched
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

	fields := bits.OnesCount64(primary &^ iso8583Extended)
	if primary&iso8583Extended != 0 {
		if offset+bitmapSize > len(data) {
			return m, false
		}
		secondary, ok := iso8583Bitmap(data[offset : offset+bitmapSize])
		if !ok || secondary == 0 || secondary&iso8583Extended != 0 {
			return m, false
		}

		fields += bits.OnesCount64(secondary)
		offset += bitmapSize
	}

	if size-offset < fields {
		return m, false
	}

	m.bitmap = primary

	class, function := m.mti[1]-'0', m.mti[2]-'0'
	decision := function == iso8583FunctionRequestResponse && (class == iso8583ClassAuthorization || class == iso8583ClassFinancial)
	if !decision {
		m.outcome = request.ISO8583NotApplicable
	}

	readOutcome := decision && primary&iso8583FieldBit(39) != 0 && m.mti[0]-'0' != iso8583Version2003
	if readOutcome || primary&(iso8583FieldBit(iso8583TransmissionField)|iso8583FieldBit(iso8583STANField)) != 0 {
		used := m.readTimingFields(primary, data[offset:])
		if readOutcome && used >= 0 {
			laterFields := fields - bits.OnesCount64((primary&^iso8583Extended)>>(64-39))
			m.outcome = m.readAuthOutcome(buf, start+offset+used, start+size, laterFields)
		}
	}

	return m, true
}

type iso8583Stream struct {
	messages []iso8583Message
	complete bool
}

func readISO8583Stream(buf *largebuf.LargeBuffer, prefix, observed int, capped bool) iso8583Stream {
	var stream iso8583Stream
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
		offset = frameEnd
	}

	return stream
}

// Only unclassified exchanges with plausible headers on both sides reach the decoder.
func isPossibleISO8583Exchange(event *TCPRequestInfo, req, resp *largebuf.LargeBuffer) bool {
	return event.ProtocolType == ProtocolTypeUnknown && hasISO8583Prefix(req) && hasISO8583Prefix(resp)
}

func detectISO8583(ctx *EBPFParseContext, cfg *config.EBPFTracer, event *TCPRequestInfo, req, resp *largebuf.LargeBuffer) (request.Span, bool) {
	reqLen := max(int(event.ReqLen), int(event.Len), req.Len())
	respLen := max(int(event.RespLen), resp.Len())
	for _, prefix := range [...]int{iso8583BinaryLength, iso8583ASCIILength} {
		first := readISO8583Stream(req, prefix, reqLen, false)

		// An embedded frame can carry a valid DE7 while ending in the middle of a foreign write.
		if !first.complete {
			continue
		}

		var spans []request.Span
		// A standalone reply can also enter TCP aggregation as its first buffer.
		// Report it once, from the probe's timestamped copy.
		if event.ProtocolType == ProtocolTypeISO8583 {
			spans = iso8583Responses(event, first, true, event.StartMonotimeNs, cfg.ISO8583TransmissionLocation, nil)
		} else {
			second := readISO8583Stream(resp, prefix, respLen, int(event.RespLen) == len(event.Rbuf))
			if !second.complete || first.messages[0].packed != second.messages[0].packed {
				continue
			}

			var paired *iso8583Message
			if len(first.messages) == 1 && len(second.messages) == 1 && first.messages[0].acceptsResponse(second.messages[0]) {
				paired = &first.messages[0]
			}

			spans = iso8583Responses(event, second, false, event.EndMonotimeNs, cfg.ISO8583TransmissionLocation, paired)
		}
		if len(spans) != 0 {
			if event.ProtocolType == ProtocolTypeISO8583 && matchesOtherStandaloneTCPProtocol(cfg, event, req, resp) {
				return request.Span{}, false
			}

			ctx.emitExtraSpans(spans[1:]...)
			return spans[0], true
		}
	}

	return request.Span{}, false
}

func iso8583Responses(event *TCPRequestInfo, stream iso8583Stream, first bool, observed uint64, zone *time.Location, paired *iso8583Message) []request.Span {
	var spans []request.Span
	var wallTime time.Time
	for _, reply := range stream.messages {
		if !reply.isResponse() || observed == 0 {
			continue
		}

		if reply.transmission[0] != 0 && wallTime.IsZero() {
			wallTime = timing.KernelTime(observed)
		}

		age, estimated := iso8583ResponseTime(reply.transmission, wallTime, zone)
		mti := reply.mti
		mti[2]--
		var start uint64
		if paired != nil {
			mti = paired.mti
			start = event.StartMonotimeNs
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
		if paired != nil {
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
