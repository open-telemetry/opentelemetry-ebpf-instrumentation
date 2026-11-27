// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

// This test protocol uses a verb byte and a one-byte correlation ID.
type testIDProtocol map[byte]uint64

func (p testIDProtocol) exchange(x tcpExchange) ([]request.Span, bool) {
	reply := x.oppositeOperation()
	response := reply.data.UnsafeView()
	if len(response) != 2 || response[0] != 'R' {
		return nil, false
	}
	for op := range x.initialOperations {
		data := op.data.UnsafeView()
		if len(data) == 2 && data[0] == 'Q' {
			p[data[1]] = op.observed
		}
	}
	return p.observe(x.event, reply), true
}

func (p testIDProtocol) observe(_ *TCPRequestInfo, op tcpOperation) []request.Span {
	data := op.data.UnsafeView()
	if len(data) == 2 && data[0] == 'R' {
		if start, ok := p[data[1]]; ok {
			delete(p, data[1])
			return []request.Span{{Start: int64(start), End: int64(op.observed)}}
		}
	}
	return nil
}

func TestMultiplexedTCPSecondDecoder(t *testing.T) {
	ctx, cfg, filter := newTraceDispatcherTestContext()
	t.Cleanup(ctx.Close)
	ctx.tcpMultiplex.protocols = []tcpMultiplexProtocol{iso8583Protocol, {
		match:      func(x tcpExchange) bool { return x.request.Len() >= 2 && x.request.UnsafeView()[0] == 'Q' },
		newDecoder: func(*config.EBPFTracer) tcpMultiplexDecoder { return testIDProtocol{} },
	}}
	dispatch := func(raw []byte, start, end int64) {
		t.Helper()
		span, ignored, err := ReadBPFTraceAsSpan(ctx, cfg, &ringbuf.Record{RawSample: raw}, filter)
		require.NoError(t, err)
		require.False(t, ignored)
		require.Equal(t, start, span.Start)
		require.Equal(t, end, span.End)
	}
	start := uint64(timing.MonoTimeNow())
	event := newTCPTestRecord(directionSend, start, start+300, []byte("Qa"), []byte("Rb"))
	// One write also parses as an independent ISO reply. The decoder that
	// recognizes the full exchange owns the record and its continuations.
	stamp := timing.KernelTime(start).UTC().Add(-time.Second).Format("0102150405")
	event.appendOperation(start+100, iso8583TestFrame("05100200000000000000"+stamp))
	event.appendOperation(start+200, []byte("Qb"))
	dispatch(event.raw(), int64(start+200), int64(start+300))
	dispatch(event.continuation(start+400, []byte("Ra")), int64(start), int64(start+400))
}

type tcpTestRecord struct {
	TCPRequestInfo
	header     BpfTcpMultiplexHeaderT
	operations []BpfTcpIoRangeT
}

func newTCPTestRecord(direction uint8, start, end uint64, initial, opposite []byte) tcpTestRecord {
	r := tcpTestRecord{
		TCPRequestInfo: TCPRequestInfo{
			Flags: EventTypeTCPMultiplex, Direction: direction, IsServer: direction == directionRecv,
			ConnInfo: BpfConnectionInfoT{S_port: 42000, D_port: 8583}, StartMonotimeNs: start, EndMonotimeNs: end,
		},
		header: BpfTcpMultiplexHeaderT{ResponseLen: uint32(len(opposite))},
	}
	r.Len = uint32(copy(r.Buf[:], initial))
	r.ReqLen = uint32(len(initial))
	r.RespLen = uint32(copy(r.Rbuf[:], opposite))
	r.operations = []BpfTcpIoRangeT{{Timestamp: start, Len: r.ReqLen, InlineLen: uint16(r.Len)}}
	return r
}

func (r *tcpTestRecord) appendOperation(at uint64, data []byte) {
	op := BpfTcpIoRangeT{Timestamp: at, Len: uint32(len(data)), InlineOffset: uint16(r.Len)}
	op.InlineLen = uint16(copy(r.Buf[r.Len:], data))
	r.operations = append(r.operations, op)
	r.Len += op.Len
	r.ReqLen = r.Len
}

func (r tcpTestRecord) trailer() []byte {
	r.header.Count = uint8(len(r.operations))
	raw := traceRecordBytes(&r.header)
	for i := range r.operations {
		raw = append(raw, traceRecordBytes(&r.operations[i])...)
	}
	return raw
}

func (r tcpTestRecord) raw() []byte {
	return append(traceRecordBytes(&r.TCPRequestInfo), r.trailer()...)
}

func (r tcpTestRecord) continuation(at uint64, data []byte) []byte {
	cont := BpfTcpMultiplexContT{
		Flags: EventTypeTCPMultiplexCont, Direction: reverseDirection(r.Direction), IsServer: r.IsServer,
		ConnInfo: r.ConnInfo, Pid: r.Pid, RecordStart: r.StartMonotimeNs, Observed: at, Len: uint32(len(data)),
	}
	copy(cont.Buf[:], data)
	return traceRecordBytes(&cont)
}
