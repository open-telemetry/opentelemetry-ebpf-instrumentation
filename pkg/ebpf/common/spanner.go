// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"log/slog"
	"strings"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

func HTTPRequestTraceToSpan(trace *HTTPRequestTrace) request.Span {
	// From C, assuming 0-ended strings
	method := cstr(trace.Method[:])
	path := cstr(trace.Path[:])
	pattern := cstr(trace.Pattern[:])
	scheme := cstr(trace.Scheme[:])
	origHost := cstr(trace.Host[:])

	if pattern != "" {
		pattern = stripPattern(pattern)
		if pattern == "/" {
			pattern = ""
		}
	}

	peer := ""
	hostname := ""
	hostPort := 0

	if trace.Conn.S_port != 0 || trace.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.Conn)).reqHostInfo()

		hostPort = int(trace.Conn.D_port)
	}

	schemeHost := ""
	if scheme != "" || origHost != "" {
		schemeHost = strings.Join([]string{scheme, origHost}, request.SchemeHostSeparator)
	}

	span := request.Span{
		Type:           request.EventType(trace.Type),
		Method:         method,
		Path:           path,
		FullPath:       path,
		Route:          pattern,
		Peer:           peer,
		PeerPort:       int(trace.Conn.S_port),
		Host:           hostname,
		HostPort:       hostPort,
		ContentLength:  trace.ContentLength,
		ResponseLength: trace.ResponseLength,
		RequestStart:   int64(trace.GoStartMonotimeNs),
		Start:          int64(trace.StartMonotimeNs),
		End:            int64(trace.EndMonotimeNs),
		Status:         int(trace.Status),
		TraceID:        trace.Tp.TraceId,
		SpanID:         trace.Tp.SpanId,
		ParentSpanID:   trace.Tp.ParentId,
		TraceFlags:     trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		Statement: schemeHost,
	}

	// The Go net/http uprobe (bpf/gotracer/go_nethttp.c) overwrites the captured
	// HTTP method with the JSON-RPC procedure name when the handler resolves to
	// net/rpc/jsonrpc. The uprobe truncates to k_method_max_len (7 bytes), so
	// every standard HTTP verb fits intact and any captured value outside that
	// closed set marks a JSON-RPC procedure. Promote those traces to the
	// HTTPSubtypeJSONRPC subtype so RPC routing in the exporters takes over
	// (see issue #1821).
	if isJSONRPCMethod(method) {
		span.SubType = request.HTTPSubtypeJSONRPC
		span.JSONRPC = &request.JSONRPC{
			Method:  method,
			Version: "2.0",
		}
		span.Method = "POST"
	}

	return span
}

// isJSONRPCMethod reports whether the captured method looks like a Go
// net/rpc/jsonrpc procedure name rather than a real HTTP method. The Go
// uprobe overwrites the HTTP method field with the procedure name when
// net/rpc/jsonrpc handles the request.
//
// We use a positive pattern instead of a negative HTTP-verb allowlist
// because the BPF buffer truncates to k_method_max_len (7 bytes), which
// turns longer extension verbs (WebDAV PROPFIND -> "PROPFIN", MKCALENDAR
// -> "MKCALEN", etc.) into opaque tokens that cannot be enumerated.
//
// Go's net/rpc enforces "Type.Method" naming (always contains "."), and
// JSON-RPC namespaces commonly use "/" separators (e.g. MCP "tools/call",
// "resources/read"). Standard HTTP and WebDAV verbs contain neither
// character, so requiring "." or "/" rules them out cleanly.
func isJSONRPCMethod(method string) bool {
	return strings.ContainsAny(method, "./")
}

func stripPattern(p string) string {
	if p != "" && p[0] == '/' {
		return p
	}

	for _, s := range []string{"GET ", "PUT ", "POST ", "PATCH ", "DELETE ", "OPTIONS ", "HEAD "} {
		if strings.HasPrefix(p, s) {
			return p[len(s):]
		}
	}

	return ""
}

func SQLRequestTraceToSpan(trace *SQLRequestTrace) request.Span {
	if request.EventType(trace.Type) != request.EventTypeSQLClient {
		slog.With("component", "goexec.spanner").Warn("unknown trace type", "type", trace.Type)
		return request.Span{}
	}

	// From C, assuming 0-ended strings
	sql := cstr(trace.Sql[:])

	method, path := sqlprune.SQLParseOperationAndTable(sql)

	peer := ""
	peerPort := 0
	host := ""
	hostPort := 0

	if trace.Conn.S_port != 0 || trace.Conn.D_port != 0 {
		peer, host = (*BPFConnInfo)(unsafe.Pointer(&trace.Conn)).reqHostInfo()
		peerPort = int(trace.Conn.S_port)
		hostPort = int(trace.Conn.D_port)
	}

	hostname := cstr(trace.Hostname[:])
	if idx := strings.LastIndex(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}

	return request.Span{
		Type:          request.EventType(trace.Type),
		Method:        method,
		Path:          path,
		Peer:          peer,
		PeerPort:      peerPort,
		Host:          host,
		HostName:      hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        int(trace.Status),
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		Statement: sql,
	}
}
