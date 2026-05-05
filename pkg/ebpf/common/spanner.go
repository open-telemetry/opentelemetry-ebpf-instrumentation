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

// isJSONRPCMethod reports whether the captured method is something other than
// a standard HTTP verb. It's used to detect the Go net/rpc/jsonrpc case where
// the uprobe overwrites the HTTP method field with the procedure name.
func isJSONRPCMethod(method string) bool {
	switch method {
	case "",
		"GET", "HEAD", "POST", "PUT", "DELETE",
		"CONNECT", "OPTIONS", "TRACE", "PATCH":
		return false
	}
	return true
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
