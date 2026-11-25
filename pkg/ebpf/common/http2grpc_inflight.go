// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"strings"
	"time"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// GRPCInflightStatus marks an in-flight span. It is not a gRPC status code, so exporters
// that only know gRPC codes (0-16) leave the status attribute out.
const GRPCInflightStatus = 408

// GRPCInflightSpan builds the in-flight span of a gRPC server stream that is still open in the
// kernel map. It reports false when the stream cannot be told apart from a healthy one: not a
// server stream, not a gRPC connection, no cached request headers (stream cache cleared or
// evicted), response headers already seen, or the stream already completed. Labels come from the
// cached request (exported as span name pkg.Service/Method and rpc.system.name=grpc by the regular gRPC path), never from info.Data, because decoding the header block again desyncs the
// connection's stateful HPACK decoder. now is a CLOCK_MONOTONIC reading, the clock of info.
func GRPCInflightSpan(parseCtx *EBPFParseContext, info *BPFHTTP2Info, now time.Duration) (request.Span, bool) {
	if request.EventType(info.Type) != request.EventTypeHTTP || info.StreamId == 0 {
		return request.Span{}, false
	}

	parseCtx.h2mu.Lock()
	defer parseCtx.h2mu.Unlock()

	// Peek keeps the connection's place in the LRU: the scan must not keep idle connections alive.
	h2c, ok := parseCtx.h2c.Peek(info.NewConnId)
	if !ok || h2c.protocol != GRPC {
		return request.Span{}, false
	}
	if _, completed := h2c.completed[info.StreamId]; completed {
		return request.Span{}, false
	}
	stream := h2c.streams[info.StreamId]
	if stream == nil || !stream.requestSeen || !stream.requestOK || stream.responseSeen {
		return request.Span{}, false
	}

	cached := stream.request
	peer, host, hostPort := "", cached.host, cached.hostPort
	if info.ConnInfo.S_port != 0 || info.ConnInfo.D_port != 0 {
		peer, host = (*BPFConnInfo)(unsafe.Pointer(&info.ConnInfo)).reqHostInfo()
		hostPort = int(info.ConnInfo.D_port)
	}
	span := http2InfoToSpan(
		info, cached.method, cached.path, cached.fullPath, peer, host, hostPort, GRPCInflightStatus, GRPC, cached.authority,
	)
	// A path that is not /pkg.Service/Method exports as span name "grpc" and rpc.method _OTHER; the
	// in-flight span is only useful with a real method, so it is skipped.
	if method, _ := request.GRPCMethod(&span); !strings.Contains(method, "/") {
		return request.Span{}, false
	}
	span.End = int64(now)
	return span, true
}
