// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type tcpOperation struct {
	data      *largebuf.LargeBuffer
	observed  uint64
	length    int // wire bytes, including any uncaptured suffix
	direction uint8
	capped    bool // wire length is unknown beyond the inline limit
}

type tcpExchange struct {
	event                    *TCPRequestInfo
	request, response, large *largebuf.LargeBuffer
	header                   *BpfTcpMultiplexHeaderT
	ranges                   []byte
}

func newTCPExchange(event *TCPRequestInfo, req, resp, large *largebuf.LargeBuffer, trailer []byte) tcpExchange {
	x := tcpExchange{event: event, request: req, response: resp}
	if event.Flags != EventTypeTCPMultiplex {
		return x
	}

	header, err := ReinterpretCast[BpfTcpMultiplexHeaderT](trailer)
	if err != nil {
		return x
	}

	x.header = header
	trailer = trailer[unsafe.Sizeof(*header):]
	x.ranges = trailer[:min(len(trailer), int(header.Count)*int(unsafe.Sizeof(BpfTcpIoRangeT{})))]

	if large != nil {
		captured := event.LbReqBytes
		if event.Direction != directionByPacketType(packetTypeRequest, !event.IsServer) {
			captured = event.LbResBytes
		}

		// A missing chunk would shift the offsets of every operation following it.
		if uint32(large.Len()) == captured {
			x.large = large
		}
	}

	return x
}

func (x tcpExchange) operation(r *BpfTcpIoRangeT) tcpOperation {
	var data []byte
	start, n := int(r.InlineOffset), int(r.InlineLen)
	if n <= int(r.Len) && start+n <= min(int(x.event.Len), len(x.event.Buf)) {
		data = x.event.Buf[start : start+n]
	}

	if x.large != nil && r.LargeLen > uint32(len(data)) && r.LargeLen <= r.Len {
		if b, err := x.large.UnsafeViewAt(int(r.LargeOffset), int(r.LargeLen)); err == nil {
			data = b
		}
	}

	return tcpOperation{data: largebuf.NewLargeBufferFrom(data), length: int(r.Len), observed: r.Timestamp, direction: x.event.Direction}
}

func (x tcpExchange) initialWireLen() int {
	return max(int(x.event.ReqLen), int(x.event.Len), x.request.Len())
}

func (x tcpExchange) firstOperation() (tcpOperation, bool) {
	r, err := ReinterpretCast[BpfTcpIoRangeT](x.ranges)
	if err == nil && r.Timestamp == x.event.StartMonotimeNs && r.InlineOffset == 0 && r.LargeOffset == 0 {
		return x.operation(r), true
	}

	return tcpOperation{
		data: x.request, observed: x.event.StartMonotimeNs, direction: x.event.Direction,
		length: x.initialWireLen(),
	}, false
}

// initialOperations yields individually observed reads or writes in the direction
// that opened the record. Each view is valid until the next operation is read.
func (x tcpExchange) initialOperations(yield func(tcpOperation) bool) {
	for ranges := x.ranges; len(ranges) >= int(unsafe.Sizeof(BpfTcpIoRangeT{})); ranges = ranges[unsafe.Sizeof(BpfTcpIoRangeT{}):] {
		r, _ := ReinterpretCast[BpfTcpIoRangeT](ranges)
		if !yield(x.operation(r)) {
			return
		}
	}
}

func (x tcpExchange) oppositeOperation() tcpOperation {
	length := max(int(x.event.RespLen), x.response.Len())
	if x.header != nil && x.header.ResponseLen != 0 {
		length = int(x.header.ResponseLen)
	}

	return tcpOperation{
		data: x.response, length: length, observed: x.event.EndMonotimeNs,
		direction: reverseDirection(x.event.Direction),
		capped:    x.header == nil && int(x.event.RespLen) == len(x.event.Rbuf),
	}
}

// A decoder confirms ownership by validating an exchange. Only its session
// receives subsequent socket operations for that record.
type tcpMultiplexDecoder interface {
	exchange(tcpExchange) (spans []request.Span, confirmed bool)
	observe(*TCPRequestInfo, tcpOperation) []request.Span
}

type tcpMultiplexProtocol struct {
	match      func(tcpExchange) bool
	newDecoder func(*config.EBPFTracer) tcpMultiplexDecoder
}

type tcpMultiplexKey struct {
	pid  BpfPidInfoT
	conn BpfConnectionInfoT
}

func multiplexKey(pid BpfPidInfoT, conn BpfConnectionInfoT) tcpMultiplexKey {
	sortConnectionInfo(&conn)
	return tcpMultiplexKey{pid: pid, conn: conn}
}

type tcpMultiplexSession struct {
	start     uint64
	protocol  int
	direction uint8
	decoder   tcpMultiplexDecoder
}

type tcpMultiplex struct {
	protocols []tcpMultiplexProtocol
	sessions  *simplelru.LRU[tcpMultiplexKey, tcpMultiplexSession]
}

var tcpMultiplexProtocols = [...]tcpMultiplexProtocol{iso8583Protocol}

func (m *tcpMultiplex) decode(cfg *config.EBPFTracer, x tcpExchange) []request.Span {
	protocols := m.protocols
	if protocols == nil {
		protocols = tcpMultiplexProtocols[:]
	}

	var standalone []request.Span
	prior := -1
	if x.header != nil && x.header.PreviousRecord != 0 && m.sessions != nil {
		key := multiplexKey(x.event.Pid, x.event.ConnInfo)
		// Tuple reuse, lost records and intervening claims break the record chain.
		if session, ok := m.sessions.Get(key); ok && session.start == x.header.PreviousRecord {
			prior = session.protocol
			spans, confirmed := m.try(x, session.decoder, prior)
			if confirmed {
				return spans
			}
			standalone = spans
		}
	}

	for i, protocol := range protocols {
		if i == prior || !protocol.match(x) {
			continue
		}
		spans, confirmed := m.try(x, protocol.newDecoder(cfg), i)
		if confirmed {
			return spans
		}
		// A write inside another protocol can be a valid standalone message.
		// Give every decoder a chance to claim the exchange before emitting it.
		if len(standalone) == 0 {
			standalone = spans
		}
	}

	return standalone
}

func (m *tcpMultiplex) try(x tcpExchange, decoder tcpMultiplexDecoder, protocol int) ([]request.Span, bool) {
	spans, confirmed := decoder.exchange(x)
	if confirmed && x.header != nil {
		if m.sessions == nil {
			const maxConnections = 1024
			m.sessions, _ = simplelru.NewLRU[tcpMultiplexKey, tcpMultiplexSession](maxConnections, nil)
		}

		key := multiplexKey(x.event.Pid, x.event.ConnInfo)
		m.sessions.Add(key, tcpMultiplexSession{start: x.event.StartMonotimeNs, protocol: protocol, direction: x.event.Direction, decoder: decoder})
	}

	return spans, confirmed
}

func readTCPMultiplexCont(ctx *EBPFParseContext, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	r, err := ReinterpretCast[BpfTcpMultiplexContT](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if r.EventSource == GenericEventSourceTypeKProbes && !filter.ValidPID(app.PID(r.Pid.UserPid), r.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	if ctx.tcpMultiplex.sessions == nil {
		return request.Span{}, true, nil
	}

	key := multiplexKey(r.Pid, r.ConnInfo)
	session, ok := ctx.tcpMultiplex.sessions.Get(key)
	if !ok || session.start != r.RecordStart || r.Observed < r.RecordStart {
		return request.Span{}, true, nil
	}

	buf := largebuf.NewLargeBufferFrom(r.Buf[:min(r.Len, uint32(len(r.Buf)))])
	if r.LargeLen != 0 {
		packet := uint8(packetTypeResponse)
		if r.Direction == directionByPacketType(packetTypeRequest, !r.IsServer) {
			packet = packetTypeRequest
		}
		if large, found := extractTCPLargeBuffer(ctx, r.Tp.TraceId, r.Tp.SpanId, packet, r.Direction, key.conn, ProtocolTypeUnknown); found && large.Len() == int(r.LargeLen) && large.Len() > buf.Len() {
			buf = large
		}
	}

	event := TCPRequestInfo{
		Flags: EventTypeTCPMultiplexCont, EventSource: r.EventSource, Direction: session.direction,
		IsServer: r.IsServer, ConnInfo: r.ConnInfo, Pid: r.Pid, Tp: r.Tp,
		StartMonotimeNs: r.RecordStart, EndMonotimeNs: r.Observed,
	}

	spans := session.decoder.observe(&event, tcpOperation{data: buf, length: int(r.Len), observed: r.Observed, direction: r.Direction})
	if len(spans) == 0 {
		return request.Span{}, true, nil
	}

	ctx.emitExtraSpans(spans[1:]...)

	return spans[0], false, nil
}
