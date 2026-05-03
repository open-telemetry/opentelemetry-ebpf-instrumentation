// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestTCPReqSQLParsing(t *testing.T) {
	sql := randomStringWithSub("SELECT * FROM accounts ")
	r := makeTCPReq(sql, 343534)
	op, table, sql := detectSQL([]byte(sql))
	assert.Equal(t, "SELECT", op)
	assert.Equal(t, "accounts", table)
	s := TCPToSQLToSpan(&r, op, table, sql, request.DBGeneric, "", nil)
	assert.NotNil(t, s)
	assert.NotEmpty(t, s.Host)
	assert.NotEmpty(t, s.Peer)
	assert.Equal(t, 8080, s.HostPort)
	assert.Greater(t, s.End, s.Start)
	assert.Contains(t, s.Statement, "SELECT * FROM accounts ")
	assert.Equal(t, "SELECT", s.Method)
	assert.Equal(t, "accounts", s.Path)
	assert.Equal(t, request.EventTypeSQLClient, s.Type)
}

func TestReadTCPRequestIntoSpan_SQLServerTrafficIsServerSpan(t *testing.T) {
	r := makeTCPReq("SELECT * FROM accounts", 3306)
	r.Direction = directionRecv
	r.IsServer = true
	r.ProtocolType = ProtocolTypeMySQL

	cfg := config.EBPFTracer{HeuristicSQLDetect: true}
	ctx := NewEBPFParseContext(&cfg, nil, nil)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, r))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	assert.False(t, ignore, "server-side SQL traffic should produce spans")
	assert.Equal(t, request.EventTypeSQLServer, span.Type)
	assert.Equal(t, "SELECT", span.Method)
	assert.Equal(t, "accounts", span.Path)
}

func TestTCPReqParsing(t *testing.T) {
	sql := "Not a sql or any known protocol"
	r := makeTCPReq(sql, 343534)
	op, table, _ := detectSQL([]byte(sql))
	assert.Empty(t, op)
	assert.Empty(t, table)
	assert.NotNil(t, r)

	// Verify fallback debug logs appear when no protocol matches
	cfg := config.EBPFTracer{HeuristicSQLDetect: false, ProtocolDebug: true}
	ctx := NewEBPFParseContext(&cfg, nil, nil)

	pipeR, pipeW, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = pipeW
	var output bytes.Buffer
	done := make(chan bool)
	go func() {
		_, err := io.Copy(&output, pipeR)
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("io.Copy error: %v", err)
		}
		done <- true
	}()

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, r))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	assert.Equal(t, request.Span{}, span)
	assert.True(t, ignore)

	pipeW.Close()
	os.Stdout = stdout
	<-done
	pipeR.Close()

	assert.Contains(t, output.String(), "![>]")
	assert.Contains(t, output.String(), "![<]")
}

func TestSQLDetection(t *testing.T) {
	for _, s := range [][]byte{
		[]byte("SELECT * from accounts"), []byte("SELECT/*My comment*/ * from accounts"),
		[]byte("--UPDATE accounts SET"), []byte("DELETE++ from accounts "),
		[]byte("INSERT into accounts "), []byte("CREATE table accounts "),
		[]byte("DROP table accounts "), []byte("ALTER table accounts"),
	} {
		surrounded := []byte(randomStringWithSub(string(s)))
		op, table, _ := detectSQL(s)
		assert.NotEmpty(t, op)
		assert.NotEmpty(t, table)
		op, table, _ = detectSQL(surrounded)
		assert.NotEmpty(t, op)
		assert.NotEmpty(t, table)
	}
}

func TestSQLDetectionFails(t *testing.T) {
	for _, s := range [][]byte{
		[]byte("SELECT"), []byte("UPDATES{}"), []byte("DELETE {} "), []byte("INSERT// into accounts "),
	} {
		op, table, _ := detectSQL(s)
		assert.False(t, validSQL(op, table, request.DBGeneric))
		surrounded := []byte(randomStringWithSub(string(s)))
		op, table, _ = detectSQL(surrounded)
		assert.False(t, validSQL(op, table, request.DBGeneric))
	}
}

func TestSQLDetectionDoesntFailForDetectedKind(t *testing.T) {
	for _, s := range [][]byte{[]byte("SELECT"), []byte("DELETE {} ")} {
		op, table, _ := detectSQL(s)
		assert.True(t, validSQL(op, table, request.DBPostgres))
	}
}

// Test making sure that issue https://github.com/grafana/beyla/issues/854 is fixed
func TestReadTCPRequestIntoSpan_Overflow(t *testing.T) {
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

	tri := TCPRequestInfo{
		Len: 340,
		// this byte array contains select * from foo
		// rest of the array is invalid UTF-8 and would cause that strings.ToUpper
		// returns a string longer than 256. That's why we are providing
		// our own asciiToUpper implementation in detectSQL function
		Buf: [256]byte{
			74, 39, 133, 207, 240, 83, 124, 225, 227, 163, 3, 23, 253, 254, 18, 12, 77, 143, 198, 122,
			123, 67, 221, 225, 10, 233, 220, 36, 65, 35, 25, 251, 88, 197, 107, 99, 25, 247, 195, 216,
			245, 107, 26, 144, 75, 78, 24, 70, 136, 173, 198, 79, 148, 232, 19, 253, 185, 169, 213, 97,
			85, 119, 210, 114, 92, 26, 226, 241, 33, 16, 199, 78, 88, 108, 8, 211, 76, 188, 8, 170, 68,
			128, 108, 194, 67, 240, 144, 132, 50, 191, 136, 130, 52, 210, 166, 212, 17, 179, 144, 138,
			101, 98, 119, 16, 125, 99, 161, 176, 9, 25, 218, 236, 219, 22, 144, 91, 158, 146, 14, 243,
			177, 58, 40, 139, 158, 33, 3, 91, 63, 70, 85, 20, 222, 206, 211, 152, 216, 53, 177, 125, 204,
			219, 157, 151, 222, 184, 241, 193, 111, 22, 242, 185, 126, 159, 53, 181,
			's', 'e', 'l', 'e', 'c', 't', ' ', '*', ' ', 'f', 'r', 'o', 'm', ' ', 'f', 'o', 'o',
			0, 17, 111, 111, 133, 13, 221,
			135, 126, 159, 234, 95, 233, 172, 96, 241, 140, 96, 71, 100, 223, 73, 74, 117, 239, 170, 154,
			148, 167, 122, 215, 170, 51, 236, 146, 5, 61, 208, 74, 230, 243, 106, 222, 52, 138, 202, 39,
			122, 180, 232, 43, 217, 86, 220, 38, 106, 141, 188, 27, 133, 156, 96, 107, 180, 178, 20, 62,
			169, 193, 172, 206, 225, 219, 112, 52, 115, 32, 147, 192, 127, 211, 129, 241,
		},
	}

	cfg := config.EBPFTracer{HeuristicSQLDetect: true}
	ctx := NewEBPFParseContext(&cfg, nil, nil)
	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))
	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	require.False(t, ignore)

	assert.Equal(t, request.EventTypeSQLClient, span.Type)
	assert.Equal(t, "SELECT", span.Method)
	assert.Equal(t, "foo", span.Path)
}

func TestRedisDetection(t *testing.T) {
	for _, s := range []string{
		`*2|$3|GET|$5|obi|`,
		`*2|$7|HGETALL|$16|users_sessions`,
		`*8|$4|name|$4|John|`,
		`+OK|`,
		"-ERR ",
		":123|",
		"-WRONGTYPE ",
		"-MOVED ",
	} {
		lines := strings.Split(s, "|")
		test := strings.Join(lines, "\r\n")
		assert.True(t, isRedis(largebuf.NewLargeBufferFrom([]uint8(test))))
		assert.True(t, isRedisOp([]uint8(test)))
	}

	for _, s := range []string{
		"",
		`*2`,
		`*$7`,
		`+OK`,
		"-ERR",
		"-WRONGTYPE",
	} {
		lines := strings.Split(s, "|")
		test := strings.Join(lines, "\r\n")
		assert.False(t, isRedis(largebuf.NewLargeBufferFrom([]uint8(test))))
		assert.False(t, isRedisOp([]uint8(test)))
	}
}

func TestTCPReqKafkaParsing(t *testing.T) {
	// kafka message
	b := []byte{0, 0, 0, 94, 0, 1, 0, 11, 0, 0, 0, 224, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 6, 64, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0}
	r := makeTCPReq(string(b), 343534)
	k, _, err := ProcessKafkaRequest(largebuf.NewLargeBufferFrom(b), nil)
	require.NoError(t, err)
	s := TCPToKafkaToSpan(&r, k)
	assert.NotNil(t, s)
	assert.NotEmpty(t, s.Host)
	assert.NotEmpty(t, s.Peer)
	assert.Equal(t, 8080, s.HostPort)
	assert.Greater(t, s.End, s.Start)
	assert.Equal(t, "process", s.Method)
	assert.Equal(t, "important", s.Path)
	assert.Equal(t, "sarama", s.Statement)
	assert.Equal(t, request.EventTypeKafkaClient, s.Type)
}

func TestTCPReqMQTTParsing(t *testing.T) {
	// MQTT PUBLISH packet with topic "test/topic" and no payload
	b := []byte{
		0x30,       // PUBLISH QoS 0
		0x0c,       // Remaining length: 12
		0x00, 0x0a, // Topic length: 10
		't', 'e', 's', 't', '/', 't', 'o', 'p', 'i', 'c',
	}
	r := makeTCPReq(string(b), 1883)
	m, ignore, err := ProcessMQTTEvent(b)
	require.NoError(t, err)
	assert.False(t, ignore)
	s := TCPToMQTTToSpan(&r, m)
	assert.NotNil(t, s)
	assert.NotEmpty(t, s.Host)
	assert.NotEmpty(t, s.Peer)
	assert.Equal(t, 8080, s.HostPort)
	assert.Greater(t, s.End, s.Start)
	assert.Equal(t, request.MessagingPublish, s.Method)
	assert.Equal(t, "test/topic", s.Path)
	assert.Equal(t, request.EventTypeMQTTClient, s.Type)
}

func TestTCPReqNATSParsing(t *testing.T) {
	b := []byte("PUB updates.orders 5\r\nhello\r\n")
	r := makeTCPReq(string(b), 4222)
	n, ignore, err := ProcessNATSEvent(largebuf.NewLargeBufferFrom(b))
	require.NoError(t, err)
	assert.False(t, ignore)
	s := TCPToNATSToSpan(&r, n)
	assert.NotNil(t, s)
	assert.NotEmpty(t, s.Host)
	assert.NotEmpty(t, s.Peer)
	assert.Equal(t, 8080, s.HostPort)
	assert.Greater(t, s.End, s.Start)
	assert.Equal(t, request.MessagingPublish, s.Method)
	assert.Equal(t, "updates.orders", s.Path)
	assert.Equal(t, request.EventTypeNATSClient, s.Type)
}

func TestReadTCPRequestIntoSpan_NATSResponseTrafficIsServerSpan(t *testing.T) {
	r := makeTCPReq("PING\r\n", 4222)
	r.RespLen = uint32(len("MSG updates.orders sidA 5\r\nhello\r\n"))
	copy(r.Rbuf[:], "MSG updates.orders sidA 5\r\nhello\r\n")

	cfg := config.EBPFTracer{HeuristicSQLDetect: true}
	ctx := NewEBPFParseContext(&cfg, nil, nil)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, r))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	assert.False(t, ignore)
	assert.Equal(t, request.EventTypeNATSServer, span.Type)
	assert.Equal(t, request.MessagingProcess, span.Method)
	assert.Equal(t, "updates.orders", span.Path)
}

func TestReadTCPRequestIntoSpan_NATSReceiveFirstMessageIsServerSpan(t *testing.T) {
	header := "NATS/1.0\r\nX-Test: python\r\n\r\n"
	payload := "python-nats-1"
	frame := fmt.Sprintf("HMSG updates.orders 1 %d %d\r\n%s%s\r\n", len(header), len(header)+len(payload), header, payload)

	r := makeTCPReq(frame, 4222)
	r.Direction = directionRecv

	cfg := config.EBPFTracer{HeuristicSQLDetect: true}
	ctx := NewEBPFParseContext(&cfg, nil, nil)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, r))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	assert.False(t, ignore)
	assert.Equal(t, request.EventTypeNATSServer, span.Type)
	assert.Equal(t, request.MessagingProcess, span.Method)
	assert.Equal(t, "updates.orders", span.Path)
}

func TestReadTCPRequestIntoSpan_NATSCoalescedPublishAndProcessEmitsDistinctServerExtraSpan(t *testing.T) {
	header := "NATS/1.0\r\nX-Test: python\r\n\r\n"
	payload := "python-nats-1"
	hdrLen := len(header)
	totalLen := hdrLen + len(payload)

	requestFrame := fmt.Sprintf("HPUB updates.orders %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)
	responseFrame := fmt.Sprintf("HMSG updates.orders subA %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)

	r := makeTCPReq(requestFrame, 4222)
	r.RespLen = uint32(len(responseFrame))
	copy(r.Rbuf[:], responseFrame)
	r.ConnInfo.S_port = 38436
	r.ConnInfo.D_port = 4222
	r.Tp.TraceId = [16]uint8{1, 2, 3, 4}
	r.Tp.SpanId = [8]uint8{5, 6, 7, 8}
	r.Tp.ParentId = [8]uint8{9, 10, 11, 12}

	cfg := config.EBPFTracer{HeuristicSQLDetect: true}
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	out := queue.Subscribe(msg.SubscriberName("nats"))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	ctx := NewEBPFParseContext(&cfg, queue, &fltr)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, r))

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	require.False(t, ignore)

	assert.Equal(t, request.EventTypeNATSClient, span.Type)
	assert.Equal(t, request.MessagingPublish, span.Method)
	assert.Equal(t, "updates.orders", span.Path)
	assert.Equal(t, 4222, span.HostPort)

	extra := testutil.ReadChannel(t, out, time.Second)
	require.Len(t, extra, 1)
	assert.Equal(t, request.EventTypeNATSServer, extra[0].Type)
	assert.Equal(t, request.MessagingProcess, extra[0].Method)
	assert.Equal(t, "updates.orders", extra[0].Path)
	assert.Equal(t, 4222, extra[0].HostPort)
	assert.Equal(t, span.TraceID, extra[0].TraceID)
	assert.Equal(t, span.ParentSpanID, extra[0].ParentSpanID)
	assert.NotEqual(t, span.SpanID, extra[0].SpanID)
	assert.False(t, extra[0].SpanID.IsValid())
}

func TestReadTCPRequestIntoSpan_NATSReversedCoalescedPublishAndProcessPreservesRoles(t *testing.T) {
	header := "NATS/1.0\r\nX-Test: python\r\n\r\n"
	payload := "python-nats-1"
	hdrLen := len(header)
	totalLen := hdrLen + len(payload)

	requestFrame := fmt.Sprintf("HMSG updates.orders subA %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)
	responseFrame := fmt.Sprintf("HPUB updates.orders %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)

	r := makeTCPReq(requestFrame, 4222)
	r.RespLen = uint32(len(responseFrame))
	copy(r.Rbuf[:], responseFrame)
	r.ConnInfo.S_port = 38436
	r.ConnInfo.D_port = 4222
	r.Tp.TraceId = [16]uint8{1, 2, 3, 4}
	r.Tp.SpanId = [8]uint8{5, 6, 7, 8}
	r.Tp.ParentId = [8]uint8{9, 10, 11, 12}

	cfg := config.EBPFTracer{HeuristicSQLDetect: true}
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	out := queue.Subscribe(msg.SubscriberName("nats-reversed"))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	ctx := NewEBPFParseContext(&cfg, queue, &fltr)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, r))

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	require.False(t, ignore)

	assert.Equal(t, request.EventTypeNATSClient, span.Type)
	assert.Equal(t, request.MessagingPublish, span.Method)
	assert.Equal(t, "updates.orders", span.Path)
	assert.Equal(t, 4222, span.HostPort)

	extra := testutil.ReadChannel(t, out, time.Second)
	require.Len(t, extra, 1)
	assert.Equal(t, request.EventTypeNATSServer, extra[0].Type)
	assert.Equal(t, request.MessagingProcess, extra[0].Method)
	assert.Equal(t, "updates.orders", extra[0].Path)
	assert.Equal(t, 4222, extra[0].HostPort)
}

func TestTCPReqMQTTHeuristicFailure(t *testing.T) {
	// This packet passes isMQTT() heuristic (valid PUBLISH header) but fails full parsing
	// because the topic length (0x00, 0xFF = 255) exceeds the available data.
	// This tests that when MQTT heuristic matches but full parsing fails, the packet is ignored.
	b := []byte{
		0x30,       // PUBLISH QoS 0 - valid MQTT packet type
		0x05,       // Remaining length: 5 bytes
		0x00, 0xFF, // Topic length: 255 (but only 3 bytes remain - will fail parsing)
		0x01, 0x02, 0x03,
	}

	// Verify the heuristic passes but full parsing fails
	assert.True(t, isMQTT(largebuf.NewLargeBufferFrom(b)), "packet should pass isMQTT heuristic")
	_, _, err := ProcessMQTTEvent(b)
	require.Error(t, err, "full MQTT parsing should fail")

	// Now test via ReadTCPRequestIntoSpan - should be ignored
	r := makeTCPReq(string(b), 1883)
	cfg := config.EBPFTracer{HeuristicSQLDetect: false}
	ctx := NewEBPFParseContext(&cfg, nil, nil)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, r))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	assert.True(t, ignore, "packet should be ignored when MQTT heuristic passes but parsing fails")
	assert.Equal(t, request.Span{}, span, "span should be empty")
}

const charset = "\\0\\1\\2abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}

func randomStringWithSub(sub string) string {
	return fmt.Sprintf("%s%s%s", randomString(rand.IntN(10)), sub, randomString(rand.IntN(20)))
}

func TestReadTCPRequestIntoSpan_CouchbaseKeyNotFound(t *testing.T) {
	// Real Couchbase memcached binary protocol packets captured from eBPF
	// Request: GET for key "non_existent_document_xyz_123" (with collection ID prefix byte)
	// Original response used flexible framing (magic 0x18) which isn't fully supported,
	// so we construct an equivalent standard response (magic 0x81) with KEY_NOT_FOUND status
	requestBuffer := []byte{128, 0, 0, 30, 0, 0, 0, 70, 0, 0, 0, 30, 0, 0, 92, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 110, 111, 110, 95, 101, 120, 105, 115, 116, 101, 110, 116, 95, 100, 111, 99, 117, 109, 101, 110, 116, 95, 120, 121, 122, 95, 49, 50, 51}

	// Construct a standard response packet (magic 0x81) with KEY_NOT_FOUND status (0x0001)
	// Header format: magic(1) + opcode(1) + keyLen(2) + extrasLen(1) + dataType(1) + status(2) + bodyLen(4) + opaque(4) + CAS(8) = 24 bytes
	responseBuffer := []byte{
		0x81,       // Magic: MagicClientResponse
		0x00,       // Opcode: GET
		0x00, 0x00, // Key length: 0
		0x00,       // Extras length: 0
		0x00,       // Data type: raw
		0x00, 0x01, // Status: KEY_NOT_FOUND (1)
		0x00, 0x00, 0x00, 0x00, // Body length: 0
		0x00, 0x00, 0x5c, 0xf0, // Opaque: 23792 (same as request)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // CAS: 0
	}

	// Create TCPRequestInfo with the captured buffers
	tri := TCPRequestInfo{
		StartMonotimeNs: 1000000000,
		EndMonotimeNs:   1000500000,
		Len:             uint32(len(requestBuffer)),
		RespLen:         uint32(len(responseBuffer)),
		Direction:       directionSend,
	}

	copy(tri.Buf[:], requestBuffer)
	copy(tri.Rbuf[:], responseBuffer)

	// Set up connection info (client -> Couchbase server on port 11210)
	tri.ConnInfo.S_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	tri.ConnInfo.D_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1}
	tri.ConnInfo.S_port = 54321
	tri.ConnInfo.D_port = 11210

	// Set PID info
	tri.Pid.HostPid = 1234
	tri.Pid.UserPid = 1234
	tri.Pid.Ns = 4026531840

	cfg := config.EBPFTracer{HeuristicSQLDetect: false}
	ctx := NewEBPFParseContext(&cfg, nil, nil)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))

	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	assert.False(t, ignore, "Couchbase event should not be ignored")

	// Verify the span is correctly identified as a Couchbase event
	assert.Equal(t, request.EventTypeCouchbaseClient, span.Type)
	assert.Equal(t, "GET", span.Method)

	assert.Equal(t, 1, span.Status, "Status should be 1 (KeyNotFound)")
	assert.NotEmpty(t, span.DBError.ErrorCode, "DBError.ErrorCode should be set for KeyNotFound")
	assert.Equal(t, "1", span.DBError.ErrorCode, "DBError.ErrorCode should be 1 (KeyNotFound)")
	assert.NotEmpty(t, span.DBError.Description, "DBError.Description should be set for KeyNotFound")
	assert.Equal(t, "KeyNotFound", span.DBError.Description, "DBError.Description should indicate KeyNotFound")
}

func TestReadTCPRequestIntoSpan_CouchbaseFlexibleFraming(t *testing.T) {
	// Real Couchbase memcached binary protocol packets captured from eBPF
	// Request: GET for key with collection ID prefix
	// Response: Uses flexible framing (magic 0x18) with KEY_NOT_FOUND status
	//
	// Original captured buffers:
	// [>] [128 0 0 30 0 0 0 70 0 0 0 30 0 0 92 240 0 0 0 0 0 0 0 0 0 110 111 110 95 101 120 105 115 116 101 110 116 95 100 111 99 117 109 101 110 116 95 120 121 122 95 49 50 51]
	// [<] [24 0 3 0 0 0 0 1 0 0 0 3 0 0 92 240 0 0 0 0 0 0 0 0 2 0 15]
	//
	// The response uses MagicAltClientResponse (0x18) which has a different header layout:
	// - byte 2: framing extras length (not part of key length)
	// - byte 3: key length (single byte)
	// Currently the parser doesn't fully support flexible framing, so the status may not be extracted correctly.
	requestBuffer := []byte{128, 0, 0, 30, 0, 0, 0, 70, 0, 0, 0, 30, 0, 0, 92, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 110, 111, 110, 95, 101, 120, 105, 115, 116, 101, 110, 116, 95, 100, 111, 99, 117, 109, 101, 110, 116, 95, 120, 121, 122, 95, 49, 50, 51}
	responseBuffer := []byte{24, 0, 3, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 92, 240, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 15}

	// Create TCPRequestInfo with the captured buffers
	tri := TCPRequestInfo{
		StartMonotimeNs: 1000000000,
		EndMonotimeNs:   1000500000,
		Len:             uint32(len(requestBuffer)),
		RespLen:         uint32(len(responseBuffer)),
		Direction:       directionSend,
	}

	copy(tri.Buf[:], requestBuffer)
	copy(tri.Rbuf[:], responseBuffer)

	// Set up connection info (client -> Couchbase server on port 11210)
	tri.ConnInfo.S_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}
	tri.ConnInfo.D_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1}
	tri.ConnInfo.S_port = 54321
	tri.ConnInfo.D_port = 11210

	// Set PID info
	tri.Pid.HostPid = 1234
	tri.Pid.UserPid = 1234
	tri.Pid.Ns = 4026531840

	cfg := config.EBPFTracer{HeuristicSQLDetect: false}
	ctx := NewEBPFParseContext(&cfg, nil, nil)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))

	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	assert.False(t, ignore, "Couchbase event should not be ignored")

	// Verify the span is correctly identified as a Couchbase event
	assert.Equal(t, request.EventTypeCouchbaseClient, span.Type)
	assert.Equal(t, "GET", span.Method)

	assert.NotEmpty(t, span.DBError.ErrorCode, "DBError.ErrorCode should be set for KeyNotFound")
	assert.Equal(t, "1", span.DBError.ErrorCode, "DBError.ErrorCode should be 1 (KeyNotFound)")
	assert.NotEmpty(t, span.DBError.Description, "DBError.Description should be set for KeyNotFound")
	assert.Equal(t, "KeyNotFound", span.DBError.Description, "DBError.Description should indicate KeyNotFound")
}

func TestReadTCPRequestIntoSpan_MemcachedCoalescedNoreplySetThenGet(t *testing.T) {
	requestBuffer := "set session-key 0 300 5 noreply\r\nvalue\r\nget session-key\r\n"
	responseBuffer := "VALUE session-key 0 5\r\nvalue\r\nEND\r\n"

	tri := makeTCPReq(requestBuffer, 11211)
	tri.RespLen = uint32(len(responseBuffer))
	copy(tri.Rbuf[:], responseBuffer)

	cfg := config.EBPFTracer{}
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	out := queue.Subscribe(msg.SubscriberName("memcached"))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	ctx := NewEBPFParseContext(&cfg, queue, &fltr)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	require.False(t, ignore)

	assert.Equal(t, request.EventTypeMemcachedClient, span.Type)
	assert.Equal(t, "GET", span.Method)
	assert.Equal(t, "session-key", span.Path)

	extra := testutil.ReadChannel(t, out, time.Second)
	require.Len(t, extra, 1)
	assert.Equal(t, "SET", extra[0].Method)
	assert.Equal(t, "session-key", extra[0].Path)
	assert.Equal(t, extra[0].Start, extra[0].End)
}

func TestReadTCPRequestIntoSpan_MemcachedCoalescedNoreplySetThenIncrError(t *testing.T) {
	requestBuffer := "set error-key 0 300 12 noreply\r\nnot-a-number\r\nincr error-key 1\r\n"
	responseBuffer := "CLIENT_ERROR cannot increment or decrement non-numeric value\r\n"

	tri := makeTCPReq(requestBuffer, 11211)
	tri.RespLen = uint32(len(responseBuffer))
	copy(tri.Rbuf[:], responseBuffer)

	cfg := config.EBPFTracer{}
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	out := queue.Subscribe(msg.SubscriberName("memcached"))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	ctx := NewEBPFParseContext(&cfg, queue, &fltr)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	require.False(t, ignore)

	assert.Equal(t, "INCR", span.Method)
	assert.Equal(t, "error-key", span.Path)
	assert.Equal(t, 1, span.Status)
	assert.Equal(t, request.DBError{
		ErrorCode:   "CLIENT_ERROR",
		Description: "CLIENT_ERROR cannot increment or decrement non-numeric value",
	}, span.DBError)

	extra := testutil.ReadChannel(t, out, time.Second)
	require.Len(t, extra, 1)
	assert.Equal(t, "SET", extra[0].Method)
	assert.Equal(t, "error-key", extra[0].Path)
}

func TestReadTCPRequestIntoSpan_MemcachedRequestOnlyDeleteNoreply(t *testing.T) {
	tri := makeTCPReq("delete session-key noreply\r\n", 11211)

	cfg := config.EBPFTracer{}
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	out := queue.Subscribe(msg.SubscriberName("memcached"))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	ctx := NewEBPFParseContext(&cfg, queue, &fltr)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	assert.Equal(t, request.Span{}, span)
	assert.True(t, ignore)

	extra := testutil.ReadChannel(t, out, time.Second)
	require.Len(t, extra, 1)
	assert.Equal(t, "DELETE", extra[0].Method)
	assert.Equal(t, "session-key", extra[0].Path)
}

func TestReadTCPRequestIntoSpan_MemcachedRequestOnlyTouchNoreply(t *testing.T) {
	tri := makeTCPReq("touch session-key 60 noreply\r\n", 11211)

	cfg := config.EBPFTracer{}
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	out := queue.Subscribe(msg.SubscriberName("memcached"))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	ctx := NewEBPFParseContext(&cfg, queue, &fltr)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	assert.Equal(t, request.Span{}, span)
	assert.True(t, ignore)

	extra := testutil.ReadChannel(t, out, time.Second)
	require.Len(t, extra, 1)
	assert.Equal(t, "TOUCH", extra[0].Method)
	assert.Equal(t, "session-key", extra[0].Path)
}

func TestReadTCPRequestIntoSpan_MemcachedRequestOnlyWithoutNoreplyIgnored(t *testing.T) {
	tri := makeTCPReq("set session-key 0 300 5\r\nvalue\r\n", 11211)

	cfg := config.EBPFTracer{}
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	out := queue.Subscribe(msg.SubscriberName("memcached"))
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}
	ctx := NewEBPFParseContext(&cfg, queue, &fltr)

	binaryRecord := bytes.Buffer{}
	require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))

	span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
	require.NoError(t, err)
	assert.Equal(t, request.Span{}, span)
	assert.True(t, ignore)

	testutil.ChannelEmpty(t, out, 100*time.Millisecond)
}

// TestReadTCPRequestIntoSpan_DNSNotMisclassifiedAsCouchbase guards against a
// regression where TCP payloads containing raw DNS query/response messages were
// being misclassified as Couchbase memcached binary protocol. The Couchbase
// magic bytes (0x80, 0x81, 0x82, 0x83, 0x08, 0x18) can collide with the first
// byte of a raw DNS message (the transaction ID high byte), and the subsequent
// DNS header bytes occasionally satisfied Couchbase's loose header validation.
func TestReadTCPRequestIntoSpan_DNSNotMisclassifiedAsCouchbase(t *testing.T) {
	// Each case is a raw DNS message payload carried over TCP-port traffic,
	// without the 2-byte DNS-over-TCP length prefix. These leading bytes can
	// collide with Couchbase magic and would have been misclassified prior to
	// tightening validation. Hostnames use RFC 2606 reserved names.
	tests := []struct {
		name     string
		request  []byte
		response []byte
	}{
		{
			// Query A "example.com" — classic magic 0x80, KeyLen=256 (DNS flags 0x0100).
			name:     "classic-magic DNS A query",
			request:  []byte{128, 15, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0},
			response: []byte{128, 15, 133, 3, 0, 1, 0, 0, 0, 1, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 6, 0, 1, 0, 0, 0, 3, 0, 55, 2, 110, 115, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 5, 97, 100, 109, 105, 110, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 0, 0, 1, 0, 0, 28, 32, 0, 0, 7, 8, 0, 0, 14, 16, 0, 0, 1, 44},
		},
		{
			// Query AAAA "host.example.com" — alt magic 0x08, header shape passed previous KeyLen+BodyLen check with KeyLen=0.
			name:    "alt-magic DNS AAAA query",
			request: []byte{8, 26, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 4, 104, 111, 115, 116, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 28, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0},
		},
		{
			// Query AAAA "test.example.net" — classic magic 0x80.
			name:    "classic-magic DNS AAAA query",
			request: []byte{128, 4, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 4, 116, 101, 115, 116, 7, 101, 120, 97, 109, 112, 108, 101, 3, 110, 101, 116, 0, 0, 28, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0},
		},
		{
			// Minimal DNS query for single label "host" — alt magic 0x08.
			name:     "alt-magic tiny DNS query",
			request:  []byte{8, 29, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 4, 104, 111, 115, 116, 0, 0, 28, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0},
			response: []byte{8, 29, 133, 133, 0, 1, 0, 0, 0, 0, 0, 1, 4, 104, 111, 115, 116, 0, 0, 28, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tri := TCPRequestInfo{
				StartMonotimeNs: 1000000000,
				EndMonotimeNs:   1000500000,
				Len:             uint32(len(tt.request)),
				RespLen:         uint32(len(tt.response)),
				Direction:       directionSend,
			}
			copy(tri.Buf[:], tt.request)
			copy(tri.Rbuf[:], tt.response)
			tri.ConnInfo.S_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2}
			tri.ConnInfo.D_addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 10}
			tri.ConnInfo.S_port = 54321
			tri.ConnInfo.D_port = 53

			cfg := config.EBPFTracer{HeuristicSQLDetect: false}
			ctx := NewEBPFParseContext(&cfg, nil, nil)

			binaryRecord := bytes.Buffer{}
			require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, tri))

			fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

			span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
			require.NoError(t, err)
			assert.True(t, ignore, "DNS packet must not produce a span")
			assert.NotEqual(t, request.EventTypeCouchbaseClient, span.Type, "DNS packet must not be classified as Couchbase")
		})
	}
}

func makeTCPReq(buf string, peerPort uint32) TCPRequestInfo {
	i := TCPRequestInfo{
		StartMonotimeNs: 2000 * 1000000,
		EndMonotimeNs:   2000 * 2 * 1000000,
		Len:             uint32(len(buf)),
		Direction:       directionSend,
	}

	copy(i.Buf[:], buf)
	i.ConnInfo.S_addr[0] = 1
	i.ConnInfo.S_addr[1] = 0
	i.ConnInfo.S_addr[2] = 0
	i.ConnInfo.S_addr[3] = 127
	i.ConnInfo.S_port = uint16(peerPort)
	i.ConnInfo.D_addr[0] = 1
	i.ConnInfo.D_addr[1] = 0
	i.ConnInfo.D_addr[2] = 0
	i.ConnInfo.D_addr[3] = 127
	i.ConnInfo.D_port = 8080

	return i
}
