// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/couchbasekv"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/sunrpcparser"
)

func iso8583TestFrame(body string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...)
}

func iso8583TestBody(tb testing.TB, mti string, packed bool, fields []int, data string) []byte {
	tb.Helper()
	var bitmap uint64
	for _, field := range fields {
		bitmap |= iso8583FieldBit(field)
	}
	header := fmt.Sprintf("%s%016X", mti, bitmap)
	if packed {
		raw, err := hex.DecodeString(header)
		require.NoError(tb, err)
		return append(raw, data...)
	}
	return []byte(header + data)
}

func TestISO8583MTIBounds(t *testing.T) {
	for _, tc := range []struct {
		mti   string
		valid bool
	}{
		{"0100", true},
		{"2875", true},
		{"3100", false},
		{"0000", false},
		{"0900", false},
		{"0180", false},
		{"0106", false},
	} {
		t.Run(tc.mti, func(t *testing.T) {
			for _, packed := range []bool{false, true} {
				body := iso8583TestBody(t, tc.mti, packed, []int{3}, "000000")
				assert.Equal(t, tc.valid, validISO8583MTI(body))
			}
		})
	}
}

func TestISO8583AuthOutcome(t *testing.T) {
	for _, tc := range []struct {
		name, mti string
		packed    bool
		fields    []int
		data      string
		want      request.ISO8583AuthOutcome
	}{
		{"approval", "0110", false, []int{39}, "00", request.ISO8583Approved},
		{"partial approval", "0210", false, []int{39}, "10", request.ISO8583PartiallyApproved},
		{"technical failure", "0111", false, []int{39}, "91", request.ISO8583TechnicalError},
		{"private response code", "0110", false, []int{39}, "Z9", request.ISO8583Unknown},
		{"issuer decline", "0110", true, []int{39}, "51", request.ISO8583Declined},
		{"DE39 is text in packed 1987", "0110", true, []int{39}, "\x00\x00", request.ISO8583Unknown},
		{"no DE39", "0110", false, []int{38}, "000000", request.ISO8583Unknown},
		{"request", "0100", false, []int{39}, "00", request.ISO8583NotApplicable},
		{"advice acknowledgment", "0130", false, []int{39}, "00", request.ISO8583NotApplicable},
		{"reversal", "0430", false, []int{39}, "00", request.ISO8583NotApplicable},
		{"network management", "0810", false, []int{39}, "00", request.ISO8583NotApplicable},
		{"2003 layout", "2110", false, []int{39}, "0000", request.ISO8583Unknown},
		{"1993 ASCII", "1210", false, []int{12, 22, 31, 37, 39}, "261119152201" + "012345678901" + "03REF" + "012345678901" + "002", request.ISO8583PartiallyApproved},
		{"1993 packed", "1110", true, []int{35, 38, 39}, "\x05ABCDE" + "123456" + "\x11\x60", request.ISO8583Declined},
		{"1993 issuer unavailable", "1110", false, []int{39}, "907", request.ISO8583TechnicalError},
		{"1993 private code", "1110", false, []int{39}, "199", request.ISO8583Unknown},
		{"1993 malformed code", "1110", false, []int{39}, "11A", request.ISO8583Unknown},
		{"invalid packed padding", "1110", true, []int{39}, "\x00\x0f", request.ISO8583Unknown},
		{"invalid packed digits", "1110", true, []int{39}, "\x1a\x00", request.ISO8583Unknown},
		{"malformed LLVAR", "0110", false, []int{32, 39}, "A100", request.ISO8583Unknown},
		{"oversized institution ID", "0110", false, []int{32, 39}, "12abcdefghijkl00", request.ISO8583Unknown},
		{"malformed BCD length", "0110", true, []int{36, 39}, "\x0a\x0000", request.ISO8583Unknown},
		{"malformed PAN prefix", "0110", true, []int{2, 39}, "\x1f00", request.ISO8583Unknown},
		{"too short for DE38", "0110", false, []int{38, 39}, "123400", request.ISO8583Unknown},
		{"different DE39 width", "0110", false, []int{39}, "000", request.ISO8583Unknown},
		{"no room for following field", "0110", false, []int{39, 41}, "00", request.ISO8583Unknown},
		{
			"packed numeric and text fields", "0210", true,
			[]int{2, 19, 28, 32, 34, 35, 36, 37, 38, 39},
			"\x05\x12\x34\x5f" + "\x08\x40" + "C\x00\x00\x00\x01" + "\x03\x12\x30" +
				"\x03ABC" + "\x05\x12\x3d\x4f" + "\x00\x03ABC" + "123456789012" + "123456" + "00", request.ISO8583Approved,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := iso8583TestBody(t, tc.mti, tc.packed, tc.fields, tc.data)
			m, ok := readISO8583Message(largebuf.NewLargeBufferFrom(body), 0, len(body))
			require.True(t, ok)
			assert.Equal(t, tc.want, m.outcome)
		})
	}
}

func TestISO8583AuthOutcomeCaptureBoundaries(t *testing.T) {
	// DE39 sits beyond both the timing prefix and the inline reply capture.
	// The secondary bitmap declares DE70 after the response code.
	body := iso8583TestBody(t, "0110", false, []int{1, 11, 32, 36, 38, 39},
		"0400000000000000"+"123456"+"03123"+"104"+strings.Repeat("0", 104)+"000000"+"51"+"301")
	codeEnd := len(body) - 3
	for i := 0; i <= len(body); i++ {
		m, ok := readISO8583Message(largebuf.NewLargeBufferFrom(body[:i]), 0, len(body))
		if i < codeEnd {
			assert.Equal(t, request.ISO8583Unknown, m.outcome)
		} else {
			require.True(t, ok)
			assert.Equal(t, request.ISO8583Declined, m.outcome)
		}
		chunks := largebuf.NewLargeBufferFrom(body[:i])
		chunks.AppendChunk(body[i:])
		m, ok = readISO8583Message(chunks, 0, len(body))
		require.True(t, ok)
		assert.Equal(t, request.ISO8583Declined, m.outcome)
	}

	call := iso8583TestFrame("0100002000000200000012345600") // DE39 on the request must be ignored.
	event := TCPRequestInfo{Flags: EventTypeTCP, Direction: directionSend, StartMonotimeNs: 10, EndMonotimeNs: 25}
	event.Len = uint32(copy(event.Buf[:], call))
	event.ReqLen = event.Len
	event.RespLen = uint32(copy(event.Rbuf[:], iso8583TestFrame(string(body))))
	span, ignore, err := dispatchTraceRecord(traceRecordBytes(&event))
	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, request.ISO8583Unknown, span.ISO8583Outcome)
	assert.EqualValues(t, 15, span.End-span.Start)

	truncated := iso8583TestFrame("011000000000020000000")
	next := iso8583TestFrame("0110000000000200000000")
	batch := largebuf.NewLargeBufferFrom(append(truncated, next...))
	stream := readISO8583Stream(batch, 2, batch.Len(), false)
	require.Len(t, stream.messages, 2)
	assert.Equal(t, request.ISO8583Unknown, stream.messages[0].outcome)
	assert.Equal(t, request.ISO8583Approved, stream.messages[1].outcome)
}

func BenchmarkISO8583AuthOutcome(b *testing.B) {
	body := iso8583TestBody(b, "0110", false, []int{11, 32, 37, 38, 39}, "123456"+"041234"+"123456789012"+"123456"+"51")
	buf := largebuf.NewLargeBufferFrom(body)
	b.ReportAllocs()
	for b.Loop() {
		m, ok := readISO8583Message(buf, 0, len(body))
		if !ok || m.outcome != request.ISO8583Declined {
			b.Fatal("missing issuer decline")
		}
	}
}

func TestISO8583ReferenceCapture(t *testing.T) {
	for _, tc := range []struct {
		name, mti, value, want string
		packed                 bool
	}{
		{"1987 ASCII request", "0200", "00ABC1234567", "00ABC1234567", false},
		{"1987 packed advice", "0430", "00ABC1234567", "00ABC1234567", true},
		{"1993 ASCII", "1210", "000000000000", "000000000000", false},
		{"1993 packed", "1210", "00ABC       ", "00ABC", true},
		{"blank", "0110", "            ", "", false},
		{"non-text", "0110", "00ABC\x01123456", "", false},
		{"2003 field layout", "2110", "00ABC1234567", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := "000123041234" // DE11, then an LLVAR acquirer ID in DE32.
			if tc.packed {
				prefix = "\x00\x01\x23\x04\x12\x34"
			}
			body := iso8583TestBody(t, tc.mti, tc.packed, []int{11, 32, 37}, prefix+tc.value)
			buf := largebuf.NewLargeBufferFrom(body[:len(body)-1])
			read := func() *request.ISO8583References {
				msg, ok := readISO8583Message(buf, 0, len(body))
				require.True(t, ok)
				return msg.references(iso8583Message{})
			}
			assert.Equal(t, &request.ISO8583References{STAN: "000123"}, read())
			buf.AppendChunk(body[len(body)-1:])
			assert.Equal(t, &request.ISO8583References{STAN: "000123", RRN: tc.want}, read())
		})
	}

	// A short DE37 must not borrow its last byte from the next frame.
	body := iso8583TestFrame("01100000000008000000" + "12345678901")
	next := iso8583AuthReply("000123", "00")
	buf := largebuf.NewLargeBufferFrom(append(body, next...))
	stream := readISO8583Stream(buf, 2, buf.Len(), false)
	require.Len(t, stream.messages, 2)
	assert.Nil(t, stream.messages[0].references(iso8583Message{}))
}

func TestISO8583RequestOnlyReferences(t *testing.T) {
	call := iso8583TestFrame(string(iso8583TestBody(t, "0100", false, []int{11, 37}, "000123"+"00ABC1234567")))
	reply := iso8583TestFrame(string(iso8583TestBody(t, "0110", false, []int{39}, "00")))
	event := newTCPTestRecord(directionSend, 100, 300, call, reply)
	spans := iso8583TestDispatch(t)(event.raw())
	require.Len(t, spans, 1)
	assert.Equal(t, &request.ISO8583References{STAN: "000123", RRN: "00ABC1234567"}, spans[0].ISO8583References)
}

func TestISO8583ResponseTime(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)
	kathmandu, err := time.LoadLocation("Asia/Kathmandu")
	require.NoError(t, err)
	now := time.Date(2026, 1, 1, 0, 0, 2, 250000000, time.UTC)
	for _, tc := range []struct {
		name, field string
		zone        *time.Location
		want        time.Duration
		ok          bool
	}{
		{"year rollover", "1231235958", nil, 4250 * time.Millisecond, true},
		{"same second", "0101000002", nil, 250 * time.Millisecond, true},
		{"New York clock", "1231185958", ny, 4250 * time.Millisecond, true},
		{"fractional timezone", "0101054458", kathmandu, 4250 * time.Millisecond, true},
		{"future", "0101000003", nil, 0, false},
		{"over two minutes", "1231235802", nil, 0, false},
		{"hour alias", "1231230002", nil, 0, false},
		{"day alias", "1231000002", nil, 0, false},
		{"invalid date", "0231000002", nil, 0, false},
		{"invalid minute", "0101006002", nil, 0, false},
		{"invalid second", "0101000060", nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := iso8583ResponseTime([10]byte([]byte(tc.field)), now, tc.zone)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
	got, ok := iso8583ResponseTime([10]byte([]byte("1231235802")), now.Truncate(time.Second), nil)
	assert.True(t, ok)
	assert.Equal(t, 2*time.Minute, got)
}

func TestISO8583EncodedTimingFields(t *testing.T) {
	const timestamp = "0610153451"
	const stan = "123456"
	for _, packed := range []bool{false, true} {
		t.Run(fmt.Sprintf("packed=%t", packed), func(t *testing.T) {
			// Set DE2 through DE11 and a secondary bitmap. DE2 has an odd digit count.
			header := "0210FFE00000000000000400000000000000"
			pan := "12345"
			if packed {
				pan += "F"
			}
			encoded := header + "05" + pan + strings.Repeat("0", 6+3*12) + timestamp + strings.Repeat("0", 3*8) + stan + "0301"
			body := []byte(encoded)
			if packed {
				var err error
				body, err = hex.DecodeString(encoded)
				require.NoError(t, err)
			}
			m, ok := readISO8583Message(largebuf.NewLargeBufferFrom(body), 0, len(body))
			require.True(t, ok)
			assert.Equal(t, timestamp, string(m.transmission[:]))
			assert.Equal(t, stan, string(m.stan[:]))
			for end := range len(body) {
				m, _ := readISO8583Message(largebuf.NewLargeBufferFrom(body[:end]), 0, len(body))
				if m.transmission[0] != 0 {
					assert.Equal(t, timestamp, string(m.transmission[:]))
				}
			}
		})
	}
}

func decodeTestTCP(event *TCPRequestInfo, req, resp, large *largebuf.LargeBuffer, trailer []byte) []request.Span {
	var mux tcpMultiplex
	return mux.decode(&config.EBPFTracer{}, newTCPExchange(event, req, resp, large, trailer))
}

func TestISO8583AsynchronousResponse(t *testing.T) {
	now := uint64(timing.MonoTimeNow())
	f7 := timing.KernelTime(now).UTC().Add(-5 * time.Second).Format("0102150405")
	message := func(mti, stamp, stan string) []byte {
		if mti == "0210" {
			return iso8583TestFrame(mti + "0220000002000000" + stamp + stan + "51")
		}
		return iso8583TestFrame(mti + "0220000000000000" + stamp + stan)
	}
	call := message("0200", f7, "111111")
	reply := message("0210", f7, "111111")
	empty := largebuf.NewLargeBuffer()
	event := TCPRequestInfo{StartMonotimeNs: now - uint64(time.Millisecond), EndMonotimeNs: now, Direction: directionSend}
	event.Tp.TraceId[0], event.Tp.SpanId[0], event.Tp.ParentId[0] = 1, 2, 3
	exchange := func(req, resp []byte) []request.Span {
		return decodeTestTCP(&event, largebuf.NewLargeBufferFrom(req), largebuf.NewLargeBufferFrom(resp), nil, nil)
	}
	spans := exchange(call, reply)
	require.Len(t, spans, 1)
	span := spans[0]
	assert.True(t, span.ISO8583Field7Timing)
	assert.EqualValues(t, event.Tp.TraceId, span.TraceID)
	assert.InDelta(t, 5.5, time.Duration(span.End-span.Start).Seconds(), 0.51)

	// The response follows an unrelated request with the same MTI.
	other := message("0200", f7, "222222")
	spans = exchange(other, reply)
	require.Len(t, spans, 1)
	span = spans[0]
	assert.False(t, span.ParentSpanID.IsValid())
	assert.False(t, span.TraceID.IsValid())
	assert.True(t, span.ISO8583Field7Timing)

	// A response in the first buffer is timestamped when the write occurred.
	event.EndMonotimeNs = now + uint64(time.Minute)
	standalone := func(data []byte) []request.Span {
		r := newTCPTestRecord(event.Direction, event.StartMonotimeNs, event.EndMonotimeNs, data, nil)
		r.ConnInfo = event.ConnInfo
		return decodeTestTCP(&r.TCPRequestInfo, largebuf.NewLargeBufferFrom(data), empty, nil, r.trailer())
	}
	spans = standalone(reply)
	require.Len(t, spans, 1)
	span = spans[0]
	assert.Equal(t, request.EventTypeISO8583Server, span.Type)
	assert.Equal(t, "0200", span.Method)
	assert.EqualValues(t, event.StartMonotimeNs, span.End)
	assert.InDelta(t, 5.5, time.Duration(span.End-span.Start).Seconds(), 0.51)
	assert.Empty(t, span.Statement)

	batch := append(bytes.Clone(reply), message("0430", f7, "222222")...)
	event.Direction = directionRecv
	event.ConnInfo = BpfConnectionInfoT{S_port: 45000, D_port: 8583}
	spans = standalone(batch)
	require.Len(t, spans, 2)
	span = spans[0]
	assert.Equal(t, "0200", span.Method)
	assert.Equal(t, "0420", spans[1].Method)
	assert.Equal(t, request.ISO8583Declined, span.ISO8583Outcome)
	assert.Equal(t, request.ISO8583NotApplicable, spans[1].ISO8583Outcome)
	assert.Equal(t, request.EventTypeISO8583Client, spans[1].Type)
	assert.Equal(t, 45000, spans[1].HostPort)
	assert.Equal(t, 8583, spans[1].PeerPort)
	assert.Equal(t, span.End, spans[1].End)
	assert.False(t, spans[1].ParentSpanID.IsValid())
	assert.Empty(t, standalone(append(bytes.Clone(batch), 0xff)))

	stale := message("0210", "0231000099", "111111")
	assert.Empty(t, standalone(stale))
	event.EndMonotimeNs = now
	sameCall := message("0200", "0231000099", "111111")
	spans = exchange(sameCall, stale)
	require.Len(t, spans, 1)
	span = spans[0]
	assert.False(t, span.ISO8583Field7Timing)
	assert.Equal(t, time.Millisecond, time.Duration(span.End-span.Start))
	// An invalid or absent DE7 cannot make a mismatched STAN look like a measured exchange.
	assert.Empty(t, exchange(other, stale))
	badCall := message("0200", "0231000099", "??????")
	badReply := message("0210", "0231000099", "??????")
	assert.Empty(t, exchange(badCall, badReply))
}

func TestISO8583TCPExchange(t *testing.T) {
	for _, tt := range []struct {
		name   string
		req    []byte
		resp   []byte
		mti    string
		server bool
	}{
		{"ASCII with binary length", iso8583TestFrame("02002000000000000000000000"), iso8583TestFrame("0210000000000200000000"), "0200", false},
		{"four-digit length and repeat advice", []byte("002604212000000000000000000000"), []byte("00220430000000000200000000"), "0421", true},
		{"packed BCD with secondary bitmap", iso8583TestFrame("\x08\x00\x80\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x03\x01"), iso8583TestFrame("\x08\x10\x00\x00\x00\x00\x02\x00\x00\x00" + "00"), "0800", false},
		{"four-digit length and packed BCD", []byte("0013\x08\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), []byte("0013\x08\x10\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), "0800", true},
		{"headers fit, data exceeds inline capture", iso8583TestFrame("12000000000000010000300" + strings.Repeat("A", 300)), iso8583TestFrame("12100000000000010000200" + strings.Repeat("B", 200)), "1200", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event := TCPRequestInfo{
				Flags: EventTypeTCP, Direction: directionSend, IsServer: tt.server,
				ReqLen: uint32(len(tt.req)), StartMonotimeNs: 10, EndMonotimeNs: 25,
				ConnInfo:     BpfConnectionInfoT{S_port: 45000, D_port: 8583},
				Pid:          BpfPidInfoT{HostPid: 12, UserPid: 5, Ns: 3},
				ParentStatus: parentStatusConditional,
			}
			wantType := request.EventTypeISO8583Client
			if tt.server {
				event.Direction = directionRecv
				wantType = request.EventTypeISO8583Server
			}
			event.Tp.TraceId[0], event.Tp.SpanId[0], event.Tp.ParentId[0], event.Tp.Flags = 1, 2, 3, 1
			event.Len = uint32(copy(event.Buf[:], tt.req))
			event.RespLen = uint32(copy(event.Rbuf[:], tt.resp))
			span, ignore, err := dispatchTraceRecord(traceRecordBytes(&event))
			require.NoError(t, err)
			require.False(t, ignore)
			assert.Equal(t, wantType, span.Type)
			assert.Equal(t, tt.mti, span.Method)
			assert.Equal(t, "ISO 8583 "+tt.mti, span.TraceName())
			assert.Equal(t, !tt.server, span.IsClientSpan())
			assert.Equal(t, request.StatusCodeUnset, request.SpanStatusCode(&span))
			assert.Equal(t, 45000, span.PeerPort)
			assert.Equal(t, 8583, span.HostPort)
			assert.EqualValues(t, event.Tp.TraceId, span.TraceID)
			assert.EqualValues(t, event.Tp.SpanId, span.SpanID)
			assert.EqualValues(t, event.Tp.ParentId, span.ParentSpanID)
			assert.Equal(t, event.Tp.Flags, span.TraceFlags)
			assert.True(t, span.ParentConditional)
			assert.EqualValues(t, event.StartMonotimeNs, span.RequestStart)
			assert.EqualValues(t, event.EndMonotimeNs, span.End)
			assert.EqualValues(t, event.Pid.UserPid, span.Pid.UserPID)
			assert.Empty(t, span.RequestBodyContent)
			assert.Empty(t, span.ResponseBodyContent)
			assert.Empty(t, span.Statement)
		})
	}
}

func TestISO8583DetectionPriority(t *testing.T) {
	now := uint64(timing.MonoTimeNow())
	stamp := timing.KernelTime(now).UTC().Add(-time.Second).Format("0102150405")
	reply := iso8583TestFrame("02100200000000000000" + stamp)
	packedBody, err := hex.DecodeString("02100200000000000000" + stamp)
	require.NoError(t, err)
	packedReply := append(fmt.Appendf(nil, "%04d", len(packedBody)), packedBody...)
	query := "SELECT * FROM accounts"
	var tdsQuery []byte
	for _, c := range []byte(query) {
		tdsQuery = append(tdsQuery, c, 0)
	}
	fcgi := appendFastCGIRecord(nil, fcgiFrameTypeBeginReq, []byte{0, 1, 0, 0, 0, 0, 0, 0})
	fcgi = appendFastCGIRecord(fcgi, fcgiFrameTypeParams, appendFastCGINameValue(nil, requestMethodKey, "GET"))
	fcgi = appendFastCGIRecord(fcgi, fcgiFrameTypeParams, nil)
	amqp := append(makeAMQP10Header(0), makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)
	mqtt := mqttFuzzPacket(0x30, append([]byte{0, 1, 't'}, reply...)...)

	const (
		nativeDetectors = iota
		unmarkedTCP
		markedInline
		markedLarge
	)
	read := func(t *testing.T, protocol BpfProtocolType, req, resp []byte, mode int) (request.Span, bool, error) {
		t.Helper()
		ctx, cfg, filter := newTraceDispatcherTestContext()
		defer ctx.Close()
		cfg.HeuristicSQLDetect = true
		event := TCPRequestInfo{
			Flags: EventTypeTCP, ProtocolType: protocol, Direction: directionSend,
			StartMonotimeNs: now, EndMonotimeNs: now,
			ReqLen: uint32(len(req)),
		}
		event.Len = uint32(copy(event.Buf[:], req))
		event.RespLen = uint32(copy(event.Rbuf[:], resp))
		if mode == markedLarge {
			event.HasLargeBuffers = 1
			event.LbReqBytes, event.LbResBytes = uint32(len(req)), uint32(len(resp))
			kind := protocolToLargeBufferKind(protocol)
			ctx.largeBuffers.Add(largeBufferKey{packetType: packetTypeRequest, direction: directionSend, kind: kind}, largebuf.NewLargeBufferFrom(req))
			if len(resp) > 0 {
				ctx.largeBuffers.Add(largeBufferKey{packetType: packetTypeResponse, direction: directionRecv, kind: kind}, largebuf.NewLargeBufferFrom(resp))
			}
		}
		if mode != nativeDetectors {
			ctx.emitSpans = func(spans []request.Span) {
				for _, span := range spans {
					assert.NotEqual(t, request.EventTypeISO8583Server, span.Type)
					assert.NotEqual(t, request.EventTypeISO8583Client, span.Type)
				}
			}
			raw := traceRecordBytes(&event)
			if mode == markedInline || mode == markedLarge {
				event.Flags = EventTypeTCPMultiplex
				r := tcpTestRecord{TCPRequestInfo: event, operations: []BpfTcpIoRangeT{{
					Timestamp: now, Len: uint32(len(req)), InlineLen: uint16(event.Len), LargeLen: event.LbReqBytes,
				}}}
				raw = r.raw()
			}
			return ReadBPFTraceAsSpan(ctx, cfg, &ringbuf.Record{RawSample: raw}, filter)
		}
		// Replay the other three detection stages on a fresh context to compare their exact result.
		requestBuf, responseBuf, _ := getBuffers(ctx, &event)
		if s, ignore, matched, err := dispatchKernelAssignedProtocol(ctx, &event, requestBuf, responseBuf); matched {
			return s, ignore, err
		}
		if s, ignore, matched, err := detectGenericProtocol(ctx, cfg, &event, requestBuf, responseBuf); matched {
			return s, ignore, err
		}
		s, ignore, matched, err := detectHeuristicProtocol(ctx, &event, requestBuf, responseBuf)
		return s, !matched || ignore, err
	}

	for _, tt := range []struct {
		name      string
		req, resp []byte
		tag       BpfProtocolType
		want      request.EventType // zero for a recognized control message or HTTP/2 reroute
	}{
		{"SQL", []byte(query), nil, ProtocolTypeUnknown, request.EventTypeSQLClient},
		{"MySQL", mysqlPacket(kMySQLQuery, []byte(query)), mysqlOKResponsePacket(), ProtocolTypeMySQL, request.EventTypeSQLClient},
		{"Postgres", pgWireMsg(kPostgresQuery, query), pgWireMsg(kPostgresCommand, "SELECT 1"), ProtocolTypePostgres, request.EventTypeSQLClient},
		{"Postgres startup", pgStartupMessage("user", "postgres"), nil, ProtocolTypeUnknown, 0},
		{"MSSQL", makeTDSPacket(kMSSQLBatch, 1, tdsQuery), nil, ProtocolTypeMSSQL, request.EventTypeSQLClient},
		{"FastCGI", fcgi, nil, ProtocolTypeUnknown, request.EventTypeHTTPClient},
		{"MongoDB", getRequestPayload(nil, 0, sectionTypeBody, nil), getResponsePayload(nil, 0, sectionTypeBody, nil), ProtocolTypeUnknown, request.EventTypeMongoClient},
		{"Couchbase", makeCouchbaseRequestPacket(couchbasekv.OpcodeGet, "k", "", nil), makeCouchbaseResponsePacket(couchbasekv.OpcodeGet, couchbasekv.StatusSuccess, "v"), ProtocolTypeUnknown, request.EventTypeCouchbaseClient},
		{"Redis", redisBenchmarkCommand("GET", "k"), []byte("$1\r\nv\r\n"), ProtocolTypeUnknown, request.EventTypeRedisClient},
		{"Memcached", []byte("get k\r\n"), []byte("END\r\n"), ProtocolTypeUnknown, request.EventTypeMemcachedClient},
		{"Memcached noreply", []byte("set k 0 0 1 noreply\r\nv\r\n"), nil, ProtocolTypeUnknown, 0},
		{"HTTP2", makeHeadersFrame(t, []byte{0x82, 0x86}), nil, ProtocolTypeUnknown, 0},
		{"NATS", []byte("PUB orders 1\r\nx\r\n"), []byte("+OK\r\n"), ProtocolTypeNATS, request.EventTypeNATSClient},
		{"AMQP", amqp, nil, ProtocolTypeAMQP, request.EventTypeAMQPClient},
		{"MQTT", mqtt, nil, ProtocolTypeMQTT, request.EventTypeMQTTClient},
		{"Kafka", fetchPayments, nil, ProtocolTypeKafka, request.EventTypeKafkaClient},
		{"SunRPC", wrapSunRPCTCPRecord(buildSunRPCCallRecord(7, sunrpcparser.ProgramNFS, 3, 6, "auth_null")), wrapSunRPCTCPRecord(buildSunRPCAcceptedReply(7)), ProtocolTypeSunRPC, request.EventTypeSunRPCClient},
		{"Aerospike", mustHex(t, fixtureHex(t, "get")), mustHex(t, aerospikeGetOKResp), ProtocolTypeAerospike, request.EventTypeAerospikeClient},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rerouted := startMisclassifiedEventReceiver(t)
			tags := []BpfProtocolType{ProtocolTypeUnknown}
			if tt.tag != ProtocolTypeUnknown {
				tags = append(tags, tt.tag)
			}
			for _, tag := range tags {
				for _, mode := range []int{markedInline, markedLarge} {
					span, ignore, err := read(t, tag, tt.req, tt.resp, mode)
					require.NoError(t, err)
					require.Equal(t, tt.want == 0, ignore)
					require.Equal(t, tt.want, span.Type)
					if tt.name == "HTTP2" {
						select {
						case e := <-rerouted:
							require.Equal(t, EventTypeKHTTP2, e.EventType)
						case <-time.After(time.Second):
							t.Fatal("HTTP/2 record was not rerouted")
						}
					}
				}

				// A timed ISO reply in the opposite direction cannot claim a foreign record,
				// including protocols that require both buffers to recognize the exchange.
				for _, iso := range [][]byte{reply, packedReply} {
					for _, pair := range [][2][]byte{{tt.req, iso}, {iso, tt.req}, {tt.resp, iso}, {iso, tt.resp}} {
						want, wantIgnore, wantErr := read(t, tag, pair[0], pair[1], nativeDetectors)
						got, ignore, err := read(t, tag, pair[0], pair[1], unmarkedTCP)
						assert.Equal(t, errorText(wantErr), errorText(err))
						assert.Equal(t, wantIgnore, ignore)
						assert.Equal(t, want, got)
						assert.NotEqual(t, request.EventTypeISO8583Client, got.Type)
						assert.NotEqual(t, request.EventTypeISO8583Server, got.Type)
					}
				}
			}
		})
	}

	t.Run("FastCGI and ISO 8583 both decode", func(t *testing.T) {
		// A FastCGI parameter can even contain the current time at the packed DE7 offset.
		params := appendFastCGINameValue(nil, "XY", string(packedBody[iso8583MinPayload:]))
		params = appendFastCGINameValue(params, requestMethodKey, "GET")
		params = append(params, bytes.Repeat([]byte{1, 1, 'X', 'Y'}, 124)...)
		packet := appendFastCGIRecord(nil, fcgiFrameTypeParams, params)
		// A FastCGI request ID can be a packed response MTI, and the content length can advertise DE7.
		binary.BigEndian.PutUint16(packet[2:4], 0x0210)
		// A read ending at the ISO length boundary is valid in both decoders.
		overlap := packet[:iso8583BinaryLength+int(binary.BigEndian.Uint16(packet))]
		response := iso8583TestFrame(string(packedBody))
		event := TCPRequestInfo{ReqLen: uint32(len(overlap)), StartMonotimeNs: now, EndMonotimeNs: now}
		require.NotEmpty(t, decodeTestTCP(&event, largebuf.NewLargeBufferFrom(overlap), largebuf.NewLargeBufferFrom(response), nil, nil))
		s, ignore, err := read(t, ProtocolTypeUnknown, overlap, response, markedInline)
		require.NoError(t, err)
		require.False(t, ignore)
		assert.Equal(t, request.EventTypeHTTPClient, s.Type)
		assert.Equal(t, "GET", s.Method)
	})

	span, ignore, err := read(t, ProtocolTypeUnknown, reply, nil, markedInline)
	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, request.EventTypeISO8583Server, span.Type)
	// A real 260-byte ISO response has the same leading bytes as FastCGI PARAMS.
	longReply := iso8583TestFrame("02100200000000010000" + stamp + "227" + strings.Repeat("X", 227))
	span, ignore, err = read(t, ProtocolTypeUnknown, longReply, nil, markedInline)
	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, "0200", span.Method)
	// An unmarked first-direction buffer alone cannot emit a standalone reply.
	_, ignore, err = read(t, ProtocolTypeUnknown, reply, nil, unmarkedTCP)
	require.NoError(t, err)
	assert.True(t, ignore)
	_, ignore, err = read(t, ProtocolTypeUnknown, reply, iso8583TestFrame("08002000000000000000000000"), unmarkedTCP)
	require.NoError(t, err)
	assert.True(t, ignore)
	_, ignore, err = read(t, ProtocolTypeUnknown, reply, iso8583TestFrame(string(packedBody)), unmarkedTCP)
	require.NoError(t, err)
	assert.True(t, ignore)
}

func iso8583AuthCall(stan string) []byte {
	return iso8583TestFrame("01000020000000000000" + stan)
}

func iso8583AuthReply(stan, code string) []byte {
	return iso8583TestFrame("01100020000002000000" + stan + code)
}

func iso8583TestDispatch(t *testing.T) func([]byte) []request.Span {
	t.Helper()
	ctx, cfg, filter := newTraceDispatcherTestContext()
	t.Cleanup(ctx.Close)
	return func(raw []byte) []request.Span {
		t.Helper()
		var extras []request.Span
		ctx.emitSpans = func(spans []request.Span) { extras = append(extras, spans...) }
		span, ignore, err := ReadBPFTraceAsSpan(ctx, cfg, &ringbuf.Record{RawSample: raw}, filter)
		require.NoError(t, err)
		if ignore {
			return extras
		}
		return append([]request.Span{span}, extras...)
	}
}

func TestISO8583MultiplexedAuthorizations(t *testing.T) {
	a := iso8583TestFrame(string(iso8583TestBody(t, "0100", false, []int{11, 37}, "123456"+"000REQ000001")))
	b := iso8583TestFrame(string(iso8583TestBody(t, "0100", false, []int{11, 37}, "123457"+"000REQ000002")))
	approved := iso8583TestFrame(string(iso8583TestBody(t, "0110", false, []int{11, 37, 39}, "123456"+"000RES000001"+"00")))
	declined := iso8583AuthReply("123457", "51")
	references := map[request.ISO8583AuthOutcome]*request.ISO8583References{
		request.ISO8583Approved: {STAN: "123456", RRN: "000RES000001"},
		request.ISO8583Declined: {STAN: "123457", RRN: "000REQ000002"},
	}
	for _, direction := range []uint8{directionSend, directionRecv} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("direction=%d/reverse=%t", direction, reverse), func(t *testing.T) {
				dispatch := iso8583TestDispatch(t)
				first, last := approved, declined
				wantFirst, wantLast := request.ISO8583Approved, request.ISO8583Declined
				firstStart, lastStart := int64(100), int64(200)
				if reverse {
					first, last = last, first
					wantFirst, wantLast = wantLast, wantFirst
					firstStart, lastStart = lastStart, firstStart
				}
				event := newTCPTestRecord(direction, 100, 350, a, first)
				event.appendOperation(200, b)
				check := func(raw []byte, outcome request.ISO8583AuthOutcome, start, end int64) {
					t.Helper()
					spans := dispatch(raw)
					require.Len(t, spans, 1)
					span := spans[0]
					assert.Equal(t, "0100", span.Method)
					assert.Equal(t, outcome, span.ISO8583Outcome)
					assert.Equal(t, references[outcome], span.ISO8583References)
					assert.Equal(t, "capture", span.ISO8583DurationSource())
					assert.Equal(t, start, span.Start)
					assert.Equal(t, end, span.End)
					assert.Equal(t, direction == directionRecv, span.Type == request.EventTypeISO8583Server)
				}
				check(event.raw(), wantFirst, firstStart, 350)
				late := event.continuation(500, last)
				check(late, wantLast, lastStart, 500)
				assert.Empty(t, dispatch(late))
			})
		}
	}
}

func TestISO8583MultiplexedRecordBoundaries(t *testing.T) {
	a, b, c := iso8583AuthCall("000001"), iso8583AuthCall("000002"), iso8583AuthCall("000003")
	replyA, replyB, replyC := iso8583AuthReply("000001", "00"), iso8583AuthReply("000002", "51"), iso8583AuthReply("000003", "00")

	for _, tc := range []struct {
		name                    string
		firstReply, secondReply []byte
		firstStart, secondStart int64
	}{
		{"A completes before C is sent", replyA, replyB, 100, 200},
		{"B completes before C is sent", replyB, replyA, 200, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dispatch := iso8583TestDispatch(t)
			check := func(raw []byte, start, end int64) {
				t.Helper()
				spans := dispatch(raw)
				require.Len(t, spans, 1)
				assert.Equal(t, start, spans[0].Start)
				assert.Equal(t, end, spans[0].End)
			}
			first := newTCPTestRecord(directionSend, 100, 300, a, tc.firstReply)
			first.appendOperation(200, b)
			check(first.raw(), tc.firstStart, 300)

			next := newTCPTestRecord(directionSend, 400, 500, c, tc.secondReply)
			next.header.PreviousRecord = first.StartMonotimeNs
			check(next.raw(), tc.secondStart, 500)
			require.Empty(t, dispatch(first.continuation(550, replyC)))
			wrongPID := next
			wrongPID.Pid.HostPid++
			require.Empty(t, dispatch(wrongPID.continuation(550, replyC)))
			check(next.continuation(600, replyC), 400, 600)
		})
	}

	t.Run("reuse of a closed connection tuple", func(t *testing.T) {
		dispatch := iso8583TestDispatch(t)
		first := newTCPTestRecord(directionSend, 100, 300, a, replyB)
		first.appendOperation(200, b)
		require.Len(t, dispatch(first.raw()), 1)
		next := newTCPTestRecord(directionSend, 400, 500, c, replyA)
		require.Empty(t, dispatch(next.raw()))
		require.Len(t, dispatch(next.continuation(600, replyC)), 1)
	})

	t.Run("protocol already claimed", func(t *testing.T) {
		dispatch := iso8583TestDispatch(t)
		first := newTCPTestRecord(directionSend, 100, 300, a, replyB)
		first.appendOperation(200, b)
		require.Len(t, dispatch(first.raw()), 1)
		mqtt := mqttFuzzPacket(0x30, append([]byte{0, 1, 't'}, a...)...)
		event := newTCPTestRecord(directionSend, 400, 500, mqtt, nil)
		event.ProtocolType = ProtocolTypeMQTT
		spans := dispatch(event.raw())
		require.Len(t, spans, 1)
		assert.Equal(t, request.EventTypeMQTTClient, spans[0].Type)
		now := uint64(timing.MonoTimeNow())
		stamp := timing.KernelTime(now).UTC().Add(-time.Second).Format("0102150405")
		require.Empty(t, dispatch(event.continuation(now, iso8583TestFrame("01100200000000000000"+stamp))))
		next := newTCPTestRecord(directionSend, 600, 700, c, replyA)
		next.header.PreviousRecord = event.StartMonotimeNs
		require.Empty(t, dispatch(next.raw()))
	})

	t.Run("ambiguous STAN", func(t *testing.T) {
		dispatch := iso8583TestDispatch(t)
		event := newTCPTestRecord(directionSend, 100, 300, a, replyA)
		event.appendOperation(200, a)
		require.Empty(t, dispatch(event.raw()))
		require.Empty(t, dispatch(event.continuation(400, replyA)))
	})

	t.Run("batched calls and replies", func(t *testing.T) {
		dispatch := iso8583TestDispatch(t)
		event := newTCPTestRecord(directionRecv, 100, 300, append(a, b...), append(replyB, replyA...))
		spans := dispatch(event.raw())
		require.Len(t, spans, 2)
		assert.Equal(t, request.ISO8583Declined, spans[0].ISO8583Outcome)
		assert.Equal(t, request.ISO8583Approved, spans[1].ISO8583Outcome)
		for _, span := range spans {
			assert.EqualValues(t, 100, span.Start)
			assert.EqualValues(t, 300, span.End)
		}
	})

	t.Run("uncaptured trailing calls", func(t *testing.T) {
		dispatch := iso8583TestDispatch(t)
		event := newTCPTestRecord(directionSend, 100, 400, a, replyB)
		event.appendOperation(250, b)
		event.ReqLen = uint32(len(event.Buf) + len(c))
		event.Len = event.ReqLen
		spans := dispatch(event.raw())
		require.Len(t, spans, 1)
		assert.EqualValues(t, 250, spans[0].Start)
		require.Len(t, dispatch(event.continuation(500, replyA)), 1)
		require.Empty(t, dispatch(event.continuation(600, replyC)))
	})

	t.Run("missing initial large-buffer capture", func(t *testing.T) {
		dispatch := iso8583TestDispatch(t)
		event := newTCPTestRecord(directionSend, 100, 400, a, replyB)
		event.appendOperation(200, b)
		// The large buffer starts with a fragment from a later write. Both
		// requests and their boundaries are still available in the inline record.
		event.HasLargeBuffers, event.LbReqBytes = 1, 8
		header := TCPLargeBufferHeader{Type: EventTypeTCPLargeBuffer, PacketType: packetTypeRequest, Direction: directionSend, ConnInfo: event.ConnInfo, Len: event.LbReqBytes}
		sortConnectionInfo(&header.ConnInfo)
		require.Empty(t, dispatch(toRingbufRecord(t, header, string(b[len(b)-8:])).RawSample))
		require.Len(t, dispatch(event.raw()), 1)
		require.Len(t, dispatch(event.continuation(500, replyA)), 1)
	})
}

func TestISO8583MultiplexedLargeReply(t *testing.T) {
	// DE39 follows a long DE36 and is beyond the inline response prefix.
	body := iso8583TestBody(t, "0110", false, []int{11, 36, 39}, "000001104"+strings.Repeat("0", 104)+"51")
	reply := iso8583TestFrame(string(body))
	for _, tc := range []struct {
		name     string
		captured int
		want     request.ISO8583AuthOutcome
	}{
		{"inline", 0, request.ISO8583Unknown},
		{"complete", len(reply), request.ISO8583Declined},
		{"missing chunk", len(reply) - 1, request.ISO8583Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dispatch := iso8583TestDispatch(t)
			event := newTCPTestRecord(directionSend, 100, 300, iso8583AuthCall("000001"), iso8583AuthReply("000002", "00"))
			event.appendOperation(210, iso8583AuthCall("000002"))
			require.Len(t, dispatch(event.raw()), 1)
			late := BpfTcpMultiplexContT{
				Flags: EventTypeTCPMultiplexCont, Direction: reverseDirection(event.Direction), ConnInfo: event.ConnInfo,
				RecordStart: event.StartMonotimeNs, Observed: 500, Len: uint32(len(reply)),
			}
			copy(late.Buf[:], reply)
			if tc.captured > 0 {
				late.LargeLen = late.Len
				header := TCPLargeBufferHeader{Type: EventTypeTCPLargeBuffer, PacketType: packetTypeResponse, Direction: directionRecv, ConnInfo: event.ConnInfo, Len: uint32(tc.captured)}
				sortConnectionInfo(&header.ConnInfo)
				require.Empty(t, dispatch(toRingbufRecord(t, header, string(reply[:tc.captured])).RawSample))
			}
			spans := dispatch(traceRecordBytes(&late))
			require.Len(t, spans, 1)
			assert.EqualValues(t, 100, spans[0].Start)
			assert.Equal(t, tc.want, spans[0].ISO8583Outcome)
		})
	}
}

func TestISO8583MarkedWrites(t *testing.T) {
	now := uint64(timing.MonoTimeNow())
	stamp := timing.KernelTime(now).UTC().Add(-5 * time.Second).Format("0102150405")
	frame := func(mti string) []byte { return iso8583TestFrame(mti + "0200000000000000" + stamp) }
	second := frame("0130")
	batchWithRoom := func(room int) []byte {
		first := "02100200000000010000" + stamp
		next := frame("0430")
		padding := len(TCPRequestInfo{}.Buf) - room - len(iso8583TestFrame(first+"000")) - len(next)
		fields := fmt.Sprintf("%03d%s", padding, strings.Repeat("X", padding))
		return append(iso8583TestFrame(first+fields), next...)
	}
	for _, tc := range []struct {
		name       string
		first      []byte
		large      bool
		wantSecond bool
	}{
		{"inline append", append(frame("0210"), frame("0430")...), false, true},
		{"append fills the inline buffer", batchWithRoom(len(second)), false, true},
		{"only one byte of inline space left", batchWithRoom(1), false, false},
		{"inline buffer full", batchWithRoom(0), false, false},
		{"large-buffer append after inline fills", batchWithRoom(0), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cfg, filter := newTraceDispatcherTestContext()
			defer ctx.Close()
			var extras []request.Span
			ctx.emitSpans = func(spans []request.Span) { extras = append(extras, spans...) }
			event := newTCPTestRecord(directionRecv, now, now+uint64(time.Minute), tc.first, nil)
			event.IsServer = false // unsolicited replies received by the client
			event.ConnInfo = BpfConnectionInfoT{S_port: 8583, D_port: 43000}
			event.Len = uint32(len(tc.first) + len(second))
			event.ReqLen = event.Len
			later := now + uint64(time.Second)
			op := BpfTcpIoRangeT{Timestamp: later, Len: uint32(len(second))}
			if len(tc.first) < len(event.Buf) {
				op.InlineOffset = uint16(len(tc.first))
				op.InlineLen = uint16(copy(event.Buf[len(tc.first):], second))
			}
			if tc.large {
				event.HasLargeBuffers = 1
				event.operations[0].LargeLen = uint32(len(tc.first))
				event.LbResBytes = event.Len
				op.LargeOffset, op.LargeLen = uint32(len(tc.first)), uint32(len(second))
				conn := event.ConnInfo
				sortConnectionInfo(&conn)
				key := largeBufferKey{connInfo: conn, packetType: packetTypeResponse, direction: directionRecv, kind: KindLayerWire}
				buffer := largebuf.NewLargeBufferFrom(tc.first)
				buffer.AppendChunk(second)
				ctx.largeBuffers.Add(key, buffer)
			}
			if op.InlineLen > 0 || op.LargeLen > 0 {
				event.operations = append(event.operations, op)
			}
			raw := event.raw()
			span, ignore, err := ReadBPFTraceAsSpan(ctx, cfg, &ringbuf.Record{RawSample: raw}, filter)
			require.NoError(t, err)
			require.False(t, ignore)
			assert.Equal(t, request.EventTypeISO8583Client, span.Type)
			assert.Equal(t, "0200", span.Method)
			assert.EqualValues(t, now, span.End)
			require.NotEmpty(t, extras)
			assert.Equal(t, "0420", extras[0].Method)
			assert.EqualValues(t, now, extras[0].End)
			if tc.wantSecond {
				require.Len(t, extras, 2)
				assert.Equal(t, "0120", extras[1].Method)
				assert.EqualValues(t, later, extras[1].End)
				assert.InDelta(t, 6.5, time.Duration(extras[1].End-extras[1].Start).Seconds(), 0.51)
			} else {
				assert.Len(t, extras, 1)
			}
		})
	}
}

func TestISO8583AppendInsideMQTT(t *testing.T) {
	now := uint64(timing.MonoTimeNow())
	stamp := timing.KernelTime(now).UTC().Add(-time.Second).Format("0102150405")
	reply := iso8583TestFrame("06100200000000000000" + stamp)
	packet := mqttFuzzPacket(0x30, append([]byte{0, 1, 't'}, reply...)...)
	offset := len(packet) - len(reply)
	for _, captureLarge := range []bool{false, true} {
		t.Run(fmt.Sprintf("large=%t", captureLarge), func(t *testing.T) {
			ctx, cfg, filter := newTraceDispatcherTestContext()
			defer ctx.Close()
			event := TCPRequestInfo{
				Flags: EventTypeTCPMultiplex, Direction: directionSend, StartMonotimeNs: now, EndMonotimeNs: now,
				Len: uint32(len(packet)), ReqLen: uint32(len(packet)),
			}
			copy(event.Buf[:], packet)
			write := BpfTcpIoRangeT{Timestamp: now, Len: uint32(len(reply)), InlineOffset: uint16(offset), InlineLen: uint16(len(reply))}
			if captureLarge {
				event.HasLargeBuffers, event.LbReqBytes = 1, event.Len
				write.LargeOffset, write.LargeLen = uint32(offset), write.Len
				header := TCPLargeBufferHeader{Type: EventTypeTCPLargeBuffer, PacketType: packetTypeRequest, Direction: event.Direction, Len: uint32(offset)}
				_, _, err := appendTCPLargeBuffer(ctx, toRingbufRecord(t, header, string(packet[:offset])))
				require.NoError(t, err)
				header.Action, header.Len = largeBufferActionAppend, write.Len
				_, _, err = appendTCPLargeBuffer(ctx, toRingbufRecord(t, header, string(reply)))
				require.NoError(t, err)
			}
			r := tcpTestRecord{TCPRequestInfo: event, operations: []BpfTcpIoRangeT{write}}
			iso := decodeTestTCP(&event, largebuf.NewLargeBufferFrom(packet), largebuf.NewLargeBuffer(), nil, r.trailer())
			require.Len(t, iso, 1)
			require.Equal(t, "0600", iso[0].Method)
			ctx.emitSpans = func(spans []request.Span) { assert.Empty(t, spans) }
			span, ignore, err := ReadBPFTraceAsSpan(ctx, cfg, &ringbuf.Record{RawSample: r.raw()}, filter)
			require.NoError(t, err)
			require.False(t, ignore)
			assert.Equal(t, request.EventTypeMQTTClient, span.Type)
		})
	}
}

func TestISO8583FirstWriteUsesCompleteLargeCapture(t *testing.T) {
	now := uint64(timing.MonoTimeNow())
	stamp := timing.KernelTime(now).UTC().Add(-time.Second).Format("0102150405")
	first := iso8583TestFrame("04300200000000010000" + stamp + "240" + strings.Repeat("X", 240))
	last := iso8583TestFrame("01300200000000000000" + stamp)
	wireLen := uint32(len(first) + len(last))
	event := TCPRequestInfo{
		Flags: EventTypeTCPMultiplex, LbReqBytes: wireLen, Direction: directionSend,
		StartMonotimeNs: now, EndMonotimeNs: now,
	}
	event.Len = uint32(copy(event.Buf[:], first))
	require.Greater(t, len(first), len(event.Buf))
	inline := largebuf.NewLargeBufferFrom(event.Buf[:])
	empty := largebuf.NewLargeBuffer()
	large := largebuf.NewLargeBufferFrom(first)
	large.AppendChunk(last)
	r := tcpTestRecord{TCPRequestInfo: event, operations: []BpfTcpIoRangeT{{Timestamp: now, Len: wireLen, InlineLen: uint16(event.Len)}}}
	// Later captured chunks cannot stand in for a failed first large-buffer read.
	require.Empty(t, decodeTestTCP(&event, inline, empty, large, r.trailer()))
	r.operations[0].LargeLen = wireLen
	spans := decodeTestTCP(&event, inline, empty, large, r.trailer())
	require.Len(t, spans, 2)
	assert.Equal(t, "0420", spans[0].Method)
	assert.Equal(t, "0120", spans[1].Method)
	assert.EqualValues(t, now, spans[1].End)

	// With only the last chunk in userspace, its offset from the start of the TCP record is unknown.
	large = largebuf.NewLargeBufferFrom(last)
	assert.Empty(t, decodeTestTCP(&event, inline, empty, large, r.trailer()))
}

func TestISO8583InvalidWriteRanges(t *testing.T) {
	now := uint64(timing.MonoTimeNow())
	frame := iso8583TestFrame("02100200000000000000" + timing.KernelTime(now).UTC().Format("0102150405"))
	event := TCPRequestInfo{Flags: EventTypeTCPMultiplex, Len: uint32(len(frame)), LbReqBytes: uint32(len(frame)), StartMonotimeNs: now, EndMonotimeNs: now, Direction: directionSend}
	copy(event.Buf[:], frame)
	buf := largebuf.NewLargeBufferFrom(frame)
	empty := largebuf.NewLargeBuffer()
	for _, mark := range []BpfTcpIoRangeT{
		{Len: uint32(len(frame)), Timestamp: now, InlineOffset: 250, InlineLen: uint16(len(frame))},
		{Len: uint32(len(frame)), Timestamp: now, LargeOffset: 1, LargeLen: uint32(len(frame))},
		{Len: 1, Timestamp: now, InlineLen: uint16(len(frame)), LargeLen: uint32(len(frame))},
	} {
		r := tcpTestRecord{TCPRequestInfo: event, operations: []BpfTcpIoRangeT{mark}}
		assert.Empty(t, decodeTestTCP(&event, buf, empty, buf, r.trailer()))
	}
	mark := BpfTcpIoRangeT{Len: uint32(len(frame)), Timestamp: now, InlineLen: uint16(len(frame))}
	raw := traceRecordBytes(&mark)
	header := BpfTcpMultiplexHeaderT{Count: 2}
	trailer := append(traceRecordBytes(&header), raw...)
	trailer = append(trailer, raw[:len(raw)-1]...)
	assert.Len(t, decodeTestTCP(&event, buf, empty, nil, trailer), 1)
}

func TestISO8583ProtocolDebug(t *testing.T) {
	req := iso8583TestFrame("01002000000000000000000000")
	resp := iso8583TestFrame("0110000000000200000000")
	for _, tc := range []struct {
		name      string
		debug     bool
		req, resp []byte
	}{
		{"disabled", false, req, resp},
		{"exchange", true, req, resp},
		{"request only", true, req, nil},
		{"response only", true, nil, resp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cfg, filter := newTraceDispatcherTestContext()
			defer ctx.Close()
			cfg.ProtocolDebug = tc.debug
			logFile, err := os.CreateTemp(t.TempDir(), "tcp-debug")
			require.NoError(t, err)
			stdout := os.Stdout
			os.Stdout = logFile
			t.Cleanup(func() {
				os.Stdout = stdout
				_ = logFile.Close()
			})

			event := TCPRequestInfo{Flags: EventTypeTCP, Direction: directionSend, StartMonotimeNs: 10, EndMonotimeNs: 25}
			event.Len = uint32(copy(event.Buf[:], tc.req))
			event.ReqLen = event.Len
			event.RespLen = uint32(copy(event.Rbuf[:], tc.resp))
			_, _, err = ReadTCPRequestIntoSpan(ctx, cfg, &ringbuf.Record{RawSample: traceRecordBytes(&event)}, filter)
			require.NoError(t, err)

			output, err := os.ReadFile(logFile.Name())
			require.NoError(t, err)
			if tc.debug {
				assert.Contains(t, string(output), fmt.Sprintf("[>] %v\n[<] %v\n", tc.req, tc.resp))
			} else {
				assert.Empty(t, output)
			}
		})
	}
}

func BenchmarkISO8583PrefixReject(b *testing.B) {
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"short", []byte("PING")},
		{"text", []byte("GET /orders HTTP/1.1\r\nHost: localhost\r\n")},
		{"binary", fetchV13TwoTopics(fetchUUID1, fetchUUID2)},
	} {
		b.Run(tt.name, func(b *testing.B) {
			req := largebuf.NewLargeBufferFrom(tt.data)
			resp := largebuf.NewLargeBufferFrom(tt.data)
			var event TCPRequestInfo
			var mux tcpMultiplex
			cfg := &config.EBPFTracer{}
			x := newTCPExchange(&event, req, resp, nil, nil)
			b.ReportAllocs()
			for b.Loop() {
				if spans := mux.decode(cfg, x); len(spans) != 0 {
					b.Fatal("unexpected ISO 8583 prefix")
				}
			}
		})
	}
}

func TestISO8583RequiresMatchingFramedHeaders(t *testing.T) {
	event := TCPRequestInfo{StartMonotimeNs: 10, EndMonotimeNs: 20}
	req := iso8583TestFrame("01002000000000000000000000")
	resp := iso8583TestFrame("0110000000000200000000")
	for _, tt := range []struct {
		name      string
		req, resp []byte
	}{
		{"bare MTI", []byte("0100"), []byte("0110")},
		{"unframed", req[2:], resp[2:]},
		{"short response", req, resp[:7]},
		{"request only", req, nil},
		{"reversed exchange", resp, req},
		{"mismatched class", req, iso8583TestFrame("0210000000000200000000")},
		{"mismatched origin", req, iso8583TestFrame("0112000000000200000000")},
		{"wrong function", req, iso8583TestFrame("0130000000000200000000")},
		{"nondecimal MTI", iso8583TestFrame("010A2000000000000000000000"), resp},
		{"invalid bitmap", iso8583TestFrame("0100200000000000000Z000000"), resp},
		{"empty bitmap", iso8583TestFrame("01000000000000000000000000"), resp},
		{"short secondary bitmap", iso8583TestFrame("0100800000000000000001"), resp},
		{"fields exceed frame", iso8583TestFrame("01007FFFFFFFFFFFFFFF123"), resp},
		{"coalesced requests", bytes.Repeat(req, 2), resp},
		{"inconsistent length", req[:len(req)-1], resp},
		{"different framing", req, append([]byte("0022"), resp[2:]...)},
		{"different packing", req, iso8583TestFrame("\x01\x10\x00\x00\x00\x00\x02\x00\x00\x00" + "00")},
		{"HTTP", []byte("GET /0100 HTTP/1.1\r\n"), []byte("HTTP/1.1 200 OK\r\n")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			spans := decodeTestTCP(&event, largebuf.NewLargeBufferFrom(tt.req), largebuf.NewLargeBufferFrom(tt.resp), nil, nil)
			assert.Empty(t, spans)
		})
	}
	// A bitmap and MTI can span large-buffer chunks.
	for split := 1; split < len(req); split++ {
		t.Run(strconv.Itoa(split), func(t *testing.T) {
			buf := largebuf.NewLargeBufferFrom(req[:split])
			buf.AppendChunk(req[split:])
			require.True(t, hasISO8583Prefix(buf))
			assert.Len(t, decodeTestTCP(&event, buf, largebuf.NewLargeBufferFrom(resp), nil, nil), 1)
		})
	}
}
