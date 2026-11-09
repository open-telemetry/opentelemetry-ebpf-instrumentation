// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

type wireParent int

const (
	wireParentNone wireParent = iota
	wireParentServer
	wireParentThread
)

const wireParentH2ConnID = 77

// Exercise the real plaintext HTTP parser and central resolver through the
// existing ioctl test entry, with the network's native client identity intact.
func TestWireParentResolution(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, test := range []struct {
			name                                         string
			indexed, ambiguous, ended, future, forwarded bool
			sameTrace, hasWire, invalidTrace             bool
			parent                                       wireParent
		}{
			{name: "unindexed_rejects_other_thread_trace", hasWire: true, parent: wireParentNone},
			{name: "unindexed_falls_back_to_thread", sameTrace: true, hasWire: true, parent: wireParentThread},
			{name: "index_before_thread", indexed: true, sameTrace: true, hasWire: true, parent: wireParentServer},
			{name: "ambiguous_falls_back_to_thread", indexed: true, ambiguous: true, sameTrace: true, hasWire: true, parent: wireParentThread},
			{name: "ambiguous_rejects_other_thread_trace", indexed: true, ambiguous: true, hasWire: true, parent: wireParentNone},
			{name: "ended_falls_back_to_thread", indexed: true, ended: true, sameTrace: true, hasWire: true, parent: wireParentThread},
			{name: "index_outside_transaction_falls_back_to_thread", indexed: true, future: true, sameTrace: true, hasWire: true, parent: wireParentThread},
			{name: "forwarded_header_gets_new_span", indexed: true, forwarded: true, hasWire: true, parent: wireParentServer},
			{name: "no_wire_keeps_thread_lookup", indexed: true, parent: wireParentThread},
			{name: "invalid_wire_clears_inferred_parent", indexed: true, sameTrace: true, hasWire: true, invalidTrace: true, parent: wireParentNone},
		} {
			t.Run(fmt.Sprintf("h2=%t/%s", h2, test.name), func(t *testing.T) {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				objects := loadJavaHTTP1Reservations(t, true)
				var now unix.Timespec
				require.NoError(t, unix.ClockGettime(unix.CLOCK_MONOTONIC, &now))
				nsLink, err := os.Readlink("/proc/self/ns/pid")
				require.NoError(t, err)
				var ns uint32
				_, err = fmt.Sscanf(nsLink, "pid:[%d]", &ns)
				require.NoError(t, err)
				pid := uint32(os.Getpid())
				tp := BpfTpInfoT{Ts: uint64(now.Nano()), Flags: 1}
				copy(tp.TraceId[:], bytes.Repeat([]byte{0x11}, 16))
				copy(tp.SpanId[:], bytes.Repeat([]byte{0x33}, 8))
				wireSpan := [8]byte{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}
				serverTp := tp
				if test.forwarded {
					serverTp.ParentId = wireSpan
				}
				if test.future {
					// a parent that starts after its child is outside the transaction
					serverTp.Ts += uint64(time.Hour)
				}
				conn := BpfPidConnectionInfoT{Pid: pid}
				conn.Conn.S_port, conn.Conn.D_port = 39000, 8080
				stream := BpfHttp2ConnStreamT{PidConn: conn}
				if h2 {
					stream.StreamId = 3
					server := BpfHttp2GrpcRequestT{
						Type: ebpfcommon.EventTypeHTTPRequest, Tp: serverTp, StartMonotimeNs: tp.Ts, NewConnId: wireParentH2ConnID,
					}
					if test.ended {
						server.EndMonotimeNs = tp.Ts + 1
					}
					require.NoError(t, objects.HTTP2.Update(stream, server, ebpf.UpdateAny))
					require.NoError(t, objects.HTTP2Conns.Update(conn, BpfHttp2ConnInfoDataT{Id: wireParentH2ConnID}, ebpf.UpdateAny))
				} else {
					server := BpfHttpInfoT{Type: ebpfcommon.EventTypeHTTPRequest, Tp: serverTp, StartMonotimeNs: tp.Ts}
					if test.ended {
						server.Status = 200
					}
					require.NoError(t, objects.HTTP.Update(conn, server, ebpf.UpdateAny))
				}
				if test.indexed {
					ref := BpfHttpServerTraceRefT{Stream: stream, SpanId: tp.SpanId}
					if test.ambiguous {
						ref.Ambiguous = 1
					}
					require.NoError(t, objects.ServerIndex.Update(BpfHttpServerTraceKeyT{Pid: pid, TraceId: tp.TraceId}, ref, ebpf.UpdateAny))
				}
				thread := BpfTpInfoPidT{Tp: tp, Pid: pid, Valid: 1, ReqType: ebpfcommon.EventTypeHTTPRequest}
				copy(thread.Tp.SpanId[:], bytes.Repeat([]byte{0x44}, 8))
				if !test.sameTrace {
					copy(thread.Tp.TraceId[:], bytes.Repeat([]byte{0x22}, 16))
				}
				key := BpfTraceKeyT{P_key: BpfPidKeyT{Pid: pid, Tid: uint32(unix.Gettid()), Ns: ns}}
				require.NoError(t, objects.Servers.Update(key, thread, ebpf.UpdateAny))
				headers := "GET / HTTP/1.1\r\nHost: localhost\r\n"
				wireTrace := tp.TraceId
				if test.invalidTrace {
					wireTrace = [16]byte{}
				}
				if test.hasWire {
					headers += "traceparent: 00-" + hex.EncodeToString(wireTrace[:]) + "-" + hex.EncodeToString(wireSpan[:]) + "-01\r\n"
				}
				javaHTTP1Data(javaHTTP1Packet(40000), javaHTTP1SendOp, []byte(headers+"\r\n"))
				var requestKey BpfPidConnectionInfoT
				var span BpfHttpInfoT
				var client BpfHttpInfoT
				found := false
				iter := objects.HTTP.Iterate()
				for iter.Next(&requestKey, &span) {
					if span.Type == ebpfcommon.EventTypeHTTPClient {
						client, found = span, true
					}
				}
				require.NoError(t, iter.Err())
				require.True(t, found, "HTTP client span must be recorded")

				wantParent := map[wireParent][8]byte{
					wireParentServer: tp.SpanId,
					wireParentThread: thread.Tp.SpanId,
				}[test.parent]
				require.Equal(t, wantParent, client.Tp.ParentId)

				if !test.hasWire {
					require.Equal(t, thread.Tp.TraceId, client.Tp.TraceId)
					return
				}
				require.Equal(t, wireTrace, client.Tp.TraceId)
				require.Equal(t, uint8(1), client.Tp.Flags)
				if test.forwarded {
					require.NotEqual(t, wireSpan, client.Tp.SpanId)
					require.NotZero(t, client.Tp.SpanId)
				} else {
					require.Equal(t, wireSpan, client.Tp.SpanId)
				}
			})
		}
	}
}
