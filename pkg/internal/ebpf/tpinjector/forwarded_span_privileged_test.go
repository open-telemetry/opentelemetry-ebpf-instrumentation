// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

// The client forwards the traceparent of the request it serves unchanged, which
// tpinjector answers by giving the client call a span ID of its own. A process
// exporting its own traces never has that span exported, so its header must pass
// unchanged, while its context is still recorded for the client call.
func TestOTelTraceExportKeepsForwardedSpanID(t *testing.T) {
	traceID := bytes.Repeat([]byte{0x11}, 16)
	serverSpanID := bytes.Repeat([]byte{0x22}, 8)
	forwardedSpanID := bytes.Repeat([]byte{0x33}, 8)
	traceparent := "00-" + hex.EncodeToString(traceID) + "-" + hex.EncodeToString(forwardedSpanID) + "-01"

	h1Request := []byte("GET /forward HTTP/1.1\r\nHost: localhost\r\nTraceparent: " + traceparent + "\r\n\r\n")
	h2Setup := bytes.Join([][]byte{h2Preface, h2EmptySettings}, nil)
	h2Request := h2HeadersWithTraceparent(1, traceparent)

	for _, tc := range []struct {
		name     string
		setup    []byte
		request  []byte
		streamID uint32
		excluded bool
	}{
		{name: "HTTP1 rewritten", request: h1Request},
		{name: "HTTP1 excluded", request: h1Request, excluded: true},
		{name: "HTTP2 rewritten", setup: h2Setup, request: h2Request, streamID: 1},
		{name: "HTTP2 excluded", setup: h2Setup, request: h2Request, streamID: 1, excluded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// tpinjector finds the request a client call belongs to by the sending thread
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			constants := ebpfcommon.PIDFilterConstants()
			constants["max_transaction_time"] = uint64(time.Minute)
			objs := loadSocketGuardHarnessWith(t, constants)
			if tc.excluded {
				var marked ebpfcommon.PIDBitmap
				require.NoError(t, marked.Set(objs.OtelTracesPids, app.PID(os.Getpid()), true))
			}
			serveRequestOnThisThread(t, objs, traceID, serverSpanID, forwardedSpanID)

			conn := newGuardConn(t, objs)
			if len(tc.setup) != 0 {
				conn.send(tc.setup)
			}
			conn.send(tc.request)
			got := conn.received()

			var stored BpfTpInfoPidT
			require.NoError(t, objs.OutgoingTraceMap.Lookup(conn.egressKey(tc.streamID), &stored))
			require.Equal(t, traceID, stored.Tp.TraceId[:])
			require.Equal(t, serverSpanID, stored.Tp.ParentId[:], "the client call stays a child of the request it serves")

			if tc.streamID == 0 {
				var scheduled BpfTpInfoPidT
				require.NoError(t, objs.SkTpInfoPidMap.Lookup(uint32(conn.fd), &scheduled))
				require.Equal(t, stored.Tp.SpanId, scheduled.Tp.SpanId, "the TCP option carries the header's context")
			}

			if !tc.excluded {
				require.NotEqual(t, forwardedSpanID, stored.Tp.SpanId[:])
				sent := hex.EncodeToString(traceID) + "-" + hex.EncodeToString(stored.Tp.SpanId[:])
				require.Contains(t, string(got), sent, "the header carries the client call's span ID")
				return
			}
			require.Equal(t, forwardedSpanID, stored.Tp.SpanId[:])
			require.Equal(t, conn.sent, got, "the forwarded traceparent must reach the peer unchanged")
		})
	}
}

// Records a request served by the calling thread the way the server probes do.
// The caller keeps the thread locked, so that its writes run on the same thread.
func serveRequestOnThisThread(t *testing.T, objs *BpfObjects, traceID, spanID, parentID []byte) {
	t.Helper()

	var now unix.Timespec
	require.NoError(t, unix.ClockGettime(unix.CLOCK_MONOTONIC, &now))

	server := BpfTpInfoPidT{Pid: uint32(os.Getpid()), Valid: 1, ReqType: ebpfcommon.EventTypeHTTPRequest}
	server.Tp.Ts = uint64(now.Nano())
	server.Tp.Flags = 1
	copy(server.Tp.TraceId[:], traceID)
	copy(server.Tp.SpanId[:], spanID)
	copy(server.Tp.ParentId[:], parentID)

	key := BpfTraceKeyT{P_key: BpfPidKeyT{Tid: uint32(unix.Gettid()), Pid: uint32(os.Getpid()), Ns: selfPidNamespace(t)}}
	require.NoError(t, objs.ServerTraces.Put(key, server))
}

// A request HEADERS frame whose traceparent is a literal without indexing, the
// encoding tpinjector writes and adopts
func h2HeadersWithTraceparent(streamID uint32, traceparent string) []byte {
	const name = "traceparent"
	const literalWithoutIndexing = 0x00
	// :method GET, :scheme http, :path /
	block := []byte{0x82, 0x86, 0x84, literalWithoutIndexing, byte(len(name))}
	block = append(block, name...)
	block = append(block, byte(len(traceparent)))
	block = append(block, traceparent...)

	frame := make([]byte, h2ProbeFrameHeaderLen, h2ProbeFrameHeaderLen+len(block))
	frame[2] = byte(len(block))
	frame[3] = 1 // HEADERS
	frame[4] = 4 // END_HEADERS
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	return append(frame, block...)
}
