// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	maxTraceRecordFuzzSize   = goAutoSpanJSONMaxLen + int(unsafe.Offsetof(GoAutoSpanTrace{}.Buf))
	maxTraceDispatcherAllocs = 64
	castRecordTooShortError  = "byte slice too short"
	testParseCacheSize       = 1
	testGoroutineChecks      = 100
	testGoroutineAllowance   = 2
)

type traceRecordBoundary struct {
	name      string
	eventType byte
	size      int
}

func traceRecordBoundaries() []traceRecordBoundary {
	return []traceRecordBoundary{
		{"http-server", EventTypeHTTPRequest, int(unsafe.Sizeof(HTTPRequestTrace{}))},
		{"grpc-server", EventTypeGRPCRequest, int(unsafe.Sizeof(HTTPRequestTrace{}))},
		{"http-client", EventTypeHTTPClient, int(unsafe.Sizeof(HTTPRequestTrace{}))},
		{"grpc-client", EventTypeGRPCClient, int(unsafe.Sizeof(HTTPRequestTrace{}))},
		{"sql", EventTypeSQL, int(unsafe.Sizeof(SQLRequestTrace{}))},
		{"kernel-http", EventTypeKHTTP, int(unsafe.Sizeof(BPFHTTPInfo{}))},
		{"kernel-http2", EventTypeKHTTP2, int(unsafe.Sizeof(BPFHTTP2Info{}))},
		{"tcp", EventTypeTCP, int(unsafe.Sizeof(TCPRequestInfo{}))},
		{"go-sarama", EventTypeGoSarama, int(unsafe.Sizeof(GoSaramaClientInfo{}))},
		{"go-redis", EventTypeGoRedis, int(unsafe.Sizeof(GoRedisClientInfo{}))},
		{"go-kafka", EventTypeGoKafkaGo, int(unsafe.Sizeof(GoKafkaGoClientInfo{}))},
		{"tcp-large-buffer", EventTypeTCPLargeBuffer, int(unsafe.Sizeof(TCPLargeBufferHeader{}))},
		{"go-otel", EventOTelSDKGo, int(unsafe.Sizeof(GoOTelSpanTrace{}))},
		{"go-mongo", EventTypeGoMongo, int(unsafe.Sizeof(GoMongoClientInfo{}))},
		{"failed-connect", EventTypeFailedConnect, int(unsafe.Sizeof(TCPRequestInfo{}))},
		{"dns", EventTypeDNS, int(unsafe.Sizeof(DNSInfo{}))},
		{"go-channel-link", EventTypeGoChannelLink, int(unsafe.Sizeof(GoChannelLinkTrace{}))},
		{"go-auto-span", EventTypeGoAutoSpan, int(unsafe.Offsetof(GoAutoSpanTrace{}.Buf))},
	}
}

func newTestLRU[K comparable, V any]() *simplelru.LRU[K, V] {
	cache, err := simplelru.NewLRU[K, V](testParseCacheSize, nil)
	if err != nil {
		panic(err)
	}
	return cache
}

func newTraceDispatcherTestContext() (*EBPFParseContext, *config.EBPFTracer, ServiceFilter) {
	h2c, _ := lru.New[uint64, h2Connection](testParseCacheSize)
	parseCtx := &EBPFParseContext{
		h2c:                        h2c,
		redisDBCache:               newTestLRU[BpfConnectionInfoT, int](),
		couchbaseBucketCache:       newTestLRU[BpfConnectionInfoT, CouchbaseBucketInfo](),
		largeBuffers:               expirable.NewLRU[largeBufferKey, *largebuf.LargeBuffer](testParseCacheSize, nil, 0),
		mongoRequestCache:          expirable.NewLRU[MongoRequestKey, *MongoRequestValue](testParseCacheSize, nil, 0),
		mysqlPreparedStatements:    newTestLRU[mysqlPreparedStatementsKey, string](),
		postgresPreparedStatements: newTestLRU[postgresPreparedStatementsKey, string](),
		postgresPortals:            newTestLRU[postgresPortalsKey, string](),
		postgresDBNames:            newTestLRU[BpfConnectionInfoT, string](),
		mssqlPreparedStatements:    newTestLRU[mssqlPreparedStatementsKey, string](),
		kafkaTopicUUIDToName:       newTestLRU[kafkaparser.UUID, string](),
		dnsEvents:                  expirable.NewLRU[dnsparser.DNSId, *request.Span](testParseCacheSize, nil, 0),
		pendingSpanLinks: &pendingSpanLinks{
			cache:          expirable.NewLRU[spanLinkKey, []request.SpanLink](maxPendingSpanLinks, nil, 0),
			linkCountLimit: maxPendingSpanLinks,
		},
	}
	cfg := &config.EBPFTracer{}
	filter := &IdentityPidsFilter{}
	return parseCtx, cfg, filter
}

func dispatchTraceRecord(raw []byte) (request.Span, bool, error) {
	parseCtx, cfg, filter := newTraceDispatcherTestContext()
	defer parseCtx.Close()

	return ReadBPFTraceAsSpan(parseCtx, cfg, &ringbuf.Record{RawSample: bytes.Clone(raw)}, filter)
}

func traceRecordBytes[T any](event *T) []byte {
	return bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(event)), int(unsafe.Sizeof(*event))))
}

func minimalHTTP2TCPRecord() []byte {
	frame := []byte{0, 0, 2, 1, 4, 0, 0, 0, 1, 0x82, 0x86}
	event := TCPRequestInfo{Flags: EventTypeTCP, Len: uint32(len(frame))}
	copy(event.Buf[:], frame)
	return traceRecordBytes(&event)
}

func startMisclassifiedEventReceiver(tb testing.TB) <-chan MisclassifiedEvent {
	stop := make(chan struct{})
	done := make(chan struct{})
	received := make(chan MisclassifiedEvent, 1)
	go func() {
		defer close(done)
		for {
			select {
			case event := <-MisclassifiedEvents:
				select {
				case received <- event:
				default:
				}
			case <-stop:
				return
			}
		}
	}()
	tb.Cleanup(func() {
		close(stop)
		<-done
	})
	return received
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func boundaryGuardError(eventType byte) string {
	if eventType == EventTypeGoAutoSpan {
		return "invalid Go Auto SDK span record: shorter than its header"
	}
	return castRecordTooShortError
}

func TestReadBPFTraceAsSpanRecordSizeBoundaries(t *testing.T) {
	parseCtx, cfg, filter := newTraceDispatcherTestContext()
	defer parseCtx.Close()

	for _, boundary := range traceRecordBoundaries() {
		for _, delta := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("%s/%+d", boundary.name, delta), func(t *testing.T) {
				raw := make([]byte, boundary.size+delta)
				raw[0] = boundary.eventType
				guardError := boundaryGuardError(boundary.eventType)

				span, ignore, err := ReadBPFTraceAsSpan(
					parseCtx, cfg, &ringbuf.Record{RawSample: bytes.Clone(raw)}, filter,
				)
				spanAgain, ignoreAgain, errAgain := ReadBPFTraceAsSpan(
					parseCtx, cfg, &ringbuf.Record{RawSample: bytes.Clone(raw)}, filter,
				)

				assert.Equal(t, span, spanAgain)
				assert.Equal(t, ignore, ignoreAgain)
				assert.Equal(t, errorText(err), errorText(errAgain))

				if err != nil {
					assert.True(t, ignore)
					assert.Equal(t, request.Span{}, span)
				}
				if delta < 0 {
					require.EqualError(t, err, guardError)
				} else {
					assert.NotEqual(t, guardError, errorText(err))
				}
			})
		}
	}
}

func TestReadBPFTraceAsSpanPreservesHTTPEventTypes(t *testing.T) {
	for _, eventType := range []uint8{
		EventTypeHTTPRequest,
		EventTypeGRPCRequest,
		EventTypeHTTPClient,
		EventTypeGRPCClient,
	} {
		t.Run(fmt.Sprintf("event-%d", eventType), func(t *testing.T) {
			event := HTTPRequestTrace{Type: eventType, Method: [7]uint8{'G', 'E', 'T'}}
			span, ignore, err := dispatchTraceRecord(traceRecordBytes(&event))

			require.NoError(t, err)
			assert.False(t, ignore)
			assert.Equal(t, request.EventType(eventType), span.Type)
			assert.Equal(t, "GET", span.Method)
		})
	}
}

func TestReadBPFTraceAsSpanReroutesHTTP2WithoutBlocking(t *testing.T) {
	received := startMisclassifiedEventReceiver(t)

	for range 2 {
		span, ignore, err := dispatchTraceRecord(minimalHTTP2TCPRecord())
		require.NoError(t, err)
		assert.True(t, ignore)
		assert.Equal(t, request.Span{}, span)
		assert.Equal(t, EventTypeKHTTP2, (<-received).EventType)
	}
}

func TestDispatchTraceRecordDoesNotLeakGoroutines(t *testing.T) {
	runtime.GC()
	runtime.Gosched()
	before := runtime.NumGoroutine()

	for range testGoroutineChecks {
		_, _, err := dispatchTraceRecord(nil)
		require.Error(t, err)
	}

	runtime.GC()
	for range testGoroutineChecks {
		runtime.Gosched()
	}
	after := runtime.NumGoroutine()
	assert.LessOrEqual(t, after, before+testGoroutineAllowance)
}

func TestReadBPFTraceAsSpanMalformedRecordDoesNotLeakPriorSpan(t *testing.T) {
	largeBuffer := TCPLargeBufferHeader{Type: EventTypeTCPLargeBuffer, Len: math.MaxUint32}
	http2 := BPFHTTP2Info{Flags: EventTypeKHTTP2, Len: -1}
	goOTel := GoOTelSpanTrace{Type: EventOTelSDKGo}
	goOTel.SpanAttrs.ValidAttrs = uint8(len(goOTel.SpanAttrs.Attrs) + 1)
	tests := []struct {
		name   string
		record *ringbuf.Record
	}{
		{"nil-record", nil},
		{"empty-record", &ringbuf.Record{}},
		{"truncated-record", &ringbuf.Record{RawSample: []byte{EventTypeSQL}}},
		{"oversized-large-buffer", &ringbuf.Record{RawSample: traceRecordBytes(&largeBuffer)}},
		{"negative-http2-length", &ringbuf.Record{RawSample: traceRecordBytes(&http2)}},
		{"oversized-go-otel-attrs", &ringbuf.Record{RawSample: traceRecordBytes(&goOTel)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parseCtx, cfg, filter := newTraceDispatcherTestContext()
			defer parseCtx.Close()

			valid := HTTPRequestTrace{Type: EventTypeHTTPRequest, Method: [7]uint8{'G', 'E', 'T'}}
			prior, ignore, err := ReadBPFTraceAsSpan(
				parseCtx, cfg, &ringbuf.Record{RawSample: traceRecordBytes(&valid)}, filter,
			)
			require.NoError(t, err)
			require.False(t, ignore)
			require.NotEqual(t, request.Span{}, prior)

			span, ignore, err := ReadBPFTraceAsSpan(parseCtx, cfg, tt.record, filter)
			require.Error(t, err)
			assert.True(t, ignore)
			assert.Equal(t, request.Span{}, span)
		})
	}
}

func TestReadBPFTraceAsSpanResourceBounds(t *testing.T) {
	parseCtx, cfg, filter := newTraceDispatcherTestContext()
	defer parseCtx.Close()

	autoSpan := GoAutoSpanTrace{Type: EventTypeGoAutoSpan, Size: goAutoSpanJSONMaxLen}
	payload := bytes.Repeat([]byte{' '}, goAutoSpanJSONMaxLen)
	payload[len(payload)-1] = '{'
	record := &ringbuf.Record{RawSample: append(traceRecordBytes(&autoSpan), payload...)}
	var span request.Span
	var ignore bool
	var err error
	allocs := testing.AllocsPerRun(10, func() {
		span, ignore, err = ReadBPFTraceAsSpan(parseCtx, cfg, record, filter)
	})

	require.Error(t, err)
	assert.True(t, ignore)
	assert.Equal(t, request.Span{}, span)
	assert.LessOrEqual(t, allocs, float64(maxTraceDispatcherAllocs))

	largeBuffer := TCPLargeBufferHeader{Type: EventTypeTCPLargeBuffer, Len: math.MaxUint32}
	for range maxPendingSpanLinks + 1 {
		_, _, err = ReadBPFTraceAsSpan(
			parseCtx, cfg, &ringbuf.Record{RawSample: traceRecordBytes(&largeBuffer)}, filter,
		)
		require.Error(t, err)
	}
	assert.Zero(t, parseCtx.largeBuffers.Len())

	for i := range maxPendingSpanLinks + 1 {
		link := GoChannelLinkTrace{Type: EventTypeGoChannelLink}
		link.ReceiverTp.TraceId[15] = 1
		link.ReceiverTp.SpanId[6] = byte((i + 1) >> 8)
		link.ReceiverTp.SpanId[7] = byte(i + 1)
		link.SenderTp.TraceId[15] = 2
		link.SenderTp.SpanId[7] = 1
		_, ignore, err = ReadBPFTraceAsSpan(
			parseCtx, cfg, &ringbuf.Record{RawSample: traceRecordBytes(&link)}, filter,
		)
		require.NoError(t, err)
		require.True(t, ignore)
	}
	require.NotNil(t, parseCtx.pendingSpanLinks)
	assert.Equal(t, maxPendingSpanLinks, parseCtx.pendingSpanLinks.cache.Len())
}

func FuzzReadBPFTraceAsSpan(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(minimalHTTP2TCPRecord())
	for _, boundary := range traceRecordBoundaries() {
		for _, delta := range []int{-1, 0, 1} {
			raw := make([]byte, boundary.size+delta)
			raw[0] = boundary.eventType
			f.Add(raw)
		}
	}

	largeBuffer := TCPLargeBufferHeader{Type: EventTypeTCPLargeBuffer, Len: math.MaxUint32}
	f.Add(traceRecordBytes(&largeBuffer))
	http2 := BPFHTTP2Info{Flags: EventTypeKHTTP2, Len: -1}
	f.Add(traceRecordBytes(&http2))
	goOTel := GoOTelSpanTrace{Type: EventOTelSDKGo}
	goOTel.SpanAttrs.ValidAttrs = uint8(len(goOTel.SpanAttrs.Attrs) + 1)
	f.Add(traceRecordBytes(&goOTel))
	unknown := make([]byte, unsafe.Sizeof(HTTPRequestTrace{}))
	unknown[0] = math.MaxUint8
	f.Add(unknown)
	f.Fuzz(func(t *testing.T, raw []byte) {
		startMisclassifiedEventReceiver(t)

		if len(raw) > maxTraceRecordFuzzSize {
			raw = raw[:maxTraceRecordFuzzSize]
		}

		span, ignore, err := dispatchTraceRecord(raw)
		_, ignoreAgain, errAgain := dispatchTraceRecord(raw)
		if ignore != ignoreAgain || errorText(err) != errorText(errAgain) {
			t.Fatalf("unstable classification: first (%v, %v), second (%v, %v)",
				ignore, err, ignoreAgain, errAgain)
		}

		if err != nil && (!ignore || !reflect.DeepEqual(span, request.Span{})) {
			t.Fatalf("error result returned span %+v with ignore %v: %v", span, ignore, err)
		}
	})
}
