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

func TestISO8583AsynchronousResponse(t *testing.T) {
	var cfg config.EBPFTracer
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
	span, ok := detectISO8583(nil, &cfg, &event, largebuf.NewLargeBufferFrom(call), largebuf.NewLargeBufferFrom(reply))
	require.True(t, ok)
	assert.True(t, span.ISO8583Field7Timing)
	assert.EqualValues(t, event.Tp.TraceId, span.TraceID)
	assert.InDelta(t, 5.5, time.Duration(span.End-span.Start).Seconds(), 0.51)

	// The response follows an unrelated request with the same MTI.
	other := message("0200", f7, "222222")
	span, ok = detectISO8583(nil, &cfg, &event, largebuf.NewLargeBufferFrom(other), largebuf.NewLargeBufferFrom(reply))
	require.True(t, ok)
	assert.False(t, span.ParentSpanID.IsValid())
	assert.False(t, span.TraceID.IsValid())
	assert.True(t, span.ISO8583Field7Timing)

	// A response in the first buffer is timestamped when the write occurred.
	event.ProtocolType = ProtocolTypeISO8583
	event.EndMonotimeNs = now + uint64(time.Minute)
	span, ok = detectISO8583(nil, &cfg, &event, largebuf.NewLargeBufferFrom(reply), empty)
	require.True(t, ok)
	assert.Equal(t, request.EventTypeISO8583Server, span.Type)
	assert.Equal(t, "0200", span.Method)
	assert.EqualValues(t, event.StartMonotimeNs, span.End)
	assert.InDelta(t, 5.5, time.Duration(span.End-span.Start).Seconds(), 0.51)
	assert.Empty(t, span.Statement)

	ctx := NewEBPFParseContext(nil, nil, nil)
	var extras []request.Span
	ctx.emitSpans = func(spans []request.Span) { extras = append(extras, spans...) }
	batch := append(bytes.Clone(reply), message("0430", f7, "222222")...)
	event.Direction = directionRecv
	event.ConnInfo = BpfConnectionInfoT{S_port: 45000, D_port: 8583}
	span, ok = detectISO8583(ctx, &cfg, &event, largebuf.NewLargeBufferFrom(batch), empty)
	require.True(t, ok)
	require.Len(t, extras, 1)
	assert.Equal(t, "0200", span.Method)
	assert.Equal(t, "0420", extras[0].Method)
	assert.Equal(t, request.ISO8583Declined, span.ISO8583Outcome)
	assert.Equal(t, request.ISO8583NotApplicable, extras[0].ISO8583Outcome)
	assert.Equal(t, request.EventTypeISO8583Client, extras[0].Type)
	assert.Equal(t, 45000, extras[0].HostPort)
	assert.Equal(t, 8583, extras[0].PeerPort)
	assert.Equal(t, span.End, extras[0].End)
	assert.False(t, extras[0].ParentSpanID.IsValid())
	_, ok = detectISO8583(ctx, &cfg, &event, largebuf.NewLargeBufferFrom(append(bytes.Clone(batch), 0xff)), empty)
	assert.False(t, ok)
	assert.Len(t, extras, 1)

	stale := message("0210", "0231000099", "111111")
	_, ok = detectISO8583(nil, &cfg, &event, largebuf.NewLargeBufferFrom(stale), empty)
	assert.False(t, ok)
	event.ProtocolType = ProtocolTypeUnknown
	event.EndMonotimeNs = now
	sameCall := message("0200", "0231000099", "111111")
	span, ok = detectISO8583(nil, &cfg, &event, largebuf.NewLargeBufferFrom(sameCall), largebuf.NewLargeBufferFrom(stale))
	require.True(t, ok)
	assert.False(t, span.ISO8583Field7Timing)
	assert.Equal(t, time.Millisecond, time.Duration(span.End-span.Start))
	// An invalid or absent DE7 cannot make a mismatched STAN look like a measured exchange.
	_, ok = detectISO8583(nil, &cfg, &event, largebuf.NewLargeBufferFrom(other), largebuf.NewLargeBufferFrom(stale))
	assert.False(t, ok)
	badCall := message("0200", "0231000099", "??????")
	badReply := message("0210", "0231000099", "??????")
	_, ok = detectISO8583(nil, &cfg, &event, largebuf.NewLargeBufferFrom(badCall), largebuf.NewLargeBufferFrom(badReply))
	assert.False(t, ok)
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
	var cfg config.EBPFTracer
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

	read := func(t *testing.T, protocol BpfProtocolType, req, resp []byte, includeISO8583 bool) (request.Span, bool, error) {
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
		if includeISO8583 {
			return ReadTCPRequestIntoSpan(ctx, cfg, &ringbuf.Record{RawSample: traceRecordBytes(&event)}, filter)
		}
		// Replay the other three detection stages on a fresh context to compare their exact result.
		requestBuf, responseBuf := getBuffers(ctx, &event)
		if s, ignore, matched, err := dispatchKernelAssignedProtocol(ctx, cfg, &event, requestBuf, responseBuf); matched {
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
			// A tentative standalone tag still requires a decodable reply with a valid DE7.
			for _, payload := range [][]byte{tt.req, tt.resp} {
				_, ignore, err := read(t, ProtocolTypeISO8583, payload, nil, true)
				require.NoError(t, err)
				require.True(t, ignore)
			}

			tags := []BpfProtocolType{ProtocolTypeUnknown}
			if tt.tag != ProtocolTypeUnknown {
				tags = append(tags, tt.tag)
			}
			for _, tag := range tags {
				span, ignore, err := read(t, tag, tt.req, tt.resp, true)
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

				// A timed ISO reply in the opposite direction cannot claim a foreign record,
				// including protocols that require both buffers to recognize the exchange.
				for _, iso := range [][]byte{reply, packedReply} {
					for _, pair := range [][2][]byte{{tt.req, iso}, {iso, tt.req}, {tt.resp, iso}, {iso, tt.resp}} {
						want, wantIgnore, wantErr := read(t, tag, pair[0], pair[1], false)
						got, ignore, err := read(t, tag, pair[0], pair[1], true)
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
		_, ignore, err := read(t, ProtocolTypeISO8583, packet, nil, true)
		require.NoError(t, err)
		require.True(t, ignore)
		// A read ending at the ISO length boundary is valid in both decoders.
		overlap := packet[:iso8583BinaryLength+int(binary.BigEndian.Uint16(packet))]
		_, ignore, err = read(t, ProtocolTypeISO8583, overlap, nil, true)
		require.NoError(t, err)
		require.True(t, ignore)
		response := iso8583TestFrame(string(packedBody))
		event := TCPRequestInfo{ReqLen: uint32(len(overlap)), StartMonotimeNs: now, EndMonotimeNs: now}
		_, ok := detectISO8583(nil, &cfg, &event, largebuf.NewLargeBufferFrom(overlap), largebuf.NewLargeBufferFrom(response))
		require.True(t, ok)
		s, ignore, err := read(t, ProtocolTypeUnknown, overlap, response, true)
		require.NoError(t, err)
		require.False(t, ignore)
		assert.Equal(t, request.EventTypeHTTPClient, s.Type)
		assert.Equal(t, "GET", s.Method)
	})

	span, ignore, err := read(t, ProtocolTypeISO8583, reply, nil, true)
	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, request.EventTypeISO8583Server, span.Type)
	// A real 260-byte ISO response has the same leading bytes as FastCGI PARAMS.
	longReply := iso8583TestFrame("02100200000000010000" + stamp + "227" + strings.Repeat("X", 227))
	span, ignore, err = read(t, ProtocolTypeISO8583, longReply, nil, true)
	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, "0200", span.Method)
	// The kernel also retains this write in normal TCP aggregation.
	_, ignore, err = read(t, ProtocolTypeUnknown, reply, nil, true)
	require.NoError(t, err)
	assert.True(t, ignore)
	_, ignore, err = read(t, ProtocolTypeUnknown, reply, iso8583TestFrame("08002000000000000000000000"), true)
	require.NoError(t, err)
	assert.True(t, ignore)
	_, ignore, err = read(t, ProtocolTypeUnknown, reply, iso8583TestFrame(string(packedBody)), true)
	require.NoError(t, err)
	assert.True(t, ignore)
}

func TestISO8583StandaloneMongoHeader(t *testing.T) {
	cfg := &config.EBPFTracer{}
	event := &TCPRequestInfo{ProtocolType: ProtocolTypeISO8583, Direction: directionSend}
	payload := getRequestPayload(nil, 0, sectionTypeBody, nil)
	buf := largebuf.NewLargeBufferFrom(payload)
	empty := largebuf.NewLargeBuffer()
	assert.True(t, matchesOtherStandaloneTCPProtocol(cfg, event, buf, empty))

	// A well-formed header with an unsupported opcode must pass without a MongoDB request cache.
	binary.LittleEndian.PutUint32(payload[12:16], 9999)
	assert.False(t, matchesOtherStandaloneTCPProtocol(cfg, event, buf, empty))
}

func TestISO8583ProtocolDebug(t *testing.T) {
	req := iso8583TestFrame("01002000000000000000000000")
	resp := iso8583TestFrame("0110000000000200000000")
	for _, tc := range []struct {
		name      string
		debug     bool
		tag       BpfProtocolType
		req, resp []byte
	}{
		{"disabled", false, ProtocolTypeUnknown, req, resp},
		{"exchange", true, ProtocolTypeUnknown, req, resp},
		{"request only", true, ProtocolTypeUnknown, req, nil},
		{"response only", true, ProtocolTypeUnknown, nil, resp},
		{"kernel classified", true, ProtocolTypeISO8583, []byte("unrecognized copy"), nil},
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

			event := TCPRequestInfo{Flags: EventTypeTCP, Direction: directionSend, ProtocolType: tc.tag, StartMonotimeNs: 10, EndMonotimeNs: 25}
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
			b.ReportAllocs()
			for b.Loop() {
				if hasISO8583Prefix(req) && hasISO8583Prefix(resp) {
					b.Fatal("unexpected ISO 8583 prefix")
				}
			}
		})
	}
}

func TestISO8583RequiresMatchingFramedHeaders(t *testing.T) {
	var cfg config.EBPFTracer
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
			_, matched := detectISO8583(nil, &cfg, &TCPRequestInfo{StartMonotimeNs: 10, EndMonotimeNs: 20}, largebuf.NewLargeBufferFrom(tt.req), largebuf.NewLargeBufferFrom(tt.resp))
			assert.False(t, matched)
		})
	}
	// A bitmap and MTI can span large-buffer chunks.
	for split := 1; split < len(req); split++ {
		t.Run(strconv.Itoa(split), func(t *testing.T) {
			buf := largebuf.NewLargeBufferFrom(req[:split])
			buf.AppendChunk(req[split:])
			require.True(t, hasISO8583Prefix(buf))
			_, matched := detectISO8583(nil, &cfg, &TCPRequestInfo{StartMonotimeNs: 10, EndMonotimeNs: 20}, buf, largebuf.NewLargeBufferFrom(resp))
			assert.True(t, matched)
		})
	}
}
