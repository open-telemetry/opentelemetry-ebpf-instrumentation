// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bufio"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfhttp "go.opentelemetry.io/obi/pkg/ebpf/common/http"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

func HTTPRequestTraceToSpan(parseCtx *EBPFParseContext, trace *HTTPRequestTrace) request.Span {
	// From C, assuming 0-ended strings
	method := cstr(trace.Method[:])
	path := cstr(trace.Path[:])
	pattern := cstr(trace.Pattern[:])
	scheme := cstr(trace.Scheme[:])
	origHost := cstr(trace.Host[:])

	var jsonRPC *request.JSONRPC
	var subType int
	if trace.IsJsonrpc {
		jsonRPC = &request.JSONRPC{
			Method:  pattern,
			Version: ebpfhttp.JSONRPCVersionV1,
		}
		pattern = path
		subType = request.HTTPSubtypeJSONRPC
	}

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
		JSONRPC:   jsonRPC,
		SubType:   subType,
	}

	if parseCtx != nil && parseCtx.payloadExtraction.Enabled() && (!span.IsClientSpan() || !parseCtx.defersGoHTTPClientRequests()) {
		span = enrichedGoHTTPSpan(parseCtx, trace.Conn, &span)
	}

	return span
}

func enrichedGoHTTPSpan(parseCtx *EBPFParseContext, conn BpfConnectionInfoT, span *request.Span) request.Span {
	if req, requestBuffer, ok := parseGoRequestLargeBuffer(parseCtx, conn, span.IsClientSpan()); ok {
		resp := &http.Response{Header: http.Header{}}

		hasResponse := false
		emptyTraceID := [16]uint8{}
		b, ok := extractTCPLargeBuffer(parseCtx, emptyTraceID, packetTypeResponse, directionByPacketType(packetTypeResponse, span.IsClientSpan()), conn, ProtocolTypeHTTP)
		if ok {
			var err error
			resp, err = httpSafeParseResponse(b, req)
			if err != nil {
				slog.Debug("error while parsing http request or response, falling back to manual HTTP info parsing", "respErr", err)
			} else {
				hasResponse = true
			}

		}

		if !hasResponse || req == nil || resp == nil {
			return *span
		}

		defer req.Body.Close()
		defer resp.Body.Close()

		if req.ContentLength > 0 {
			recoverRequestBody(req, requestBuffer)
		}

		return postProcessHTTPSpan(parseCtx, span, req, resp)
	}

	return *span
}

func deferredGoHTTPClientRequestHandler(parseCtx *EBPFParseContext) func(BpfConnectionInfoT, *pendingGoHTTPClientRequest) {
	return func(_ BpfConnectionInfoT, pending *pendingGoHTTPClientRequest) {
		if pending == nil || !pending.emitted.CompareAndSwap(false, true) ||
			parseCtx.discardPendingGoHTTPClients.Load() {
			return
		}

		span := HTTPRequestTraceToSpan(parseCtx, &pending.trace)
		span = enrichedGoHTTPSpan(parseCtx, pending.trace.Conn, &span)
		parseCtx.emitExtraSpans(span)
	}
}

func parseGoRequestLargeBuffer(
	parseCtx *EBPFParseContext,
	conn BpfConnectionInfoT,
	isClient bool,
) (*http.Request, *largebuf.LargeBuffer, bool) {
	sortConnectionInfo(&conn)

	emptyTraceID := [16]uint8{}
	buffer, ok := extractTCPLargeBuffer(parseCtx, emptyTraceID, packetTypeRequest,
		directionByPacketType(packetTypeRequest, isClient), conn, ProtocolTypeHTTP)
	if !ok {
		return nil, nil, false
	}

	reqReader := buffer.NewReader()
	req, err := http.ReadRequest(bufio.NewReader(&reqReader))
	if err != nil {
		slog.Debug("error parsing HTTP request from large buffer for enrichment", "error", err)
		return nil, buffer, false
	}
	return req, buffer, true
}

func goHTTPClientConnectionKey(conn BpfConnectionInfoT) BpfConnectionInfoT {
	sortConnectionInfo(&conn)
	return conn
}

func (ctx *EBPFParseContext) goClientPayloadExtractionEnabled(cfg *config.EBPFTracer) bool {
	return cfg != nil && ctx.emitSpans != nil &&
		cfg.BufferSizes.HTTP > 0 &&
		cfg.GoHTTPClientBufferTimeout > 0 &&
		cfg.MaxTransactionTime > 0 &&
		cfg.PayloadExtraction.HTTP.ClientEnabled()
}

func (ctx *EBPFParseContext) defersGoHTTPClientRequests() bool {
	// this value is set in NewEBPFParseContext if goClientPayloadExtractionEnabled was
	// successfully called on the config. We use this as a check where the config is not
	// present.
	return ctx.goHTTPClientMaxPendingTime > 0
}

func (ctx *EBPFParseContext) deferGoHTTPClientRequest(trace *HTTPRequestTrace) bool {
	if trace == nil || ctx.pendingGoHTTPClientRequests == nil ||
		ctx.discardPendingGoHTTPClients.Load() {
		return false
	}

	key := goHTTPClientConnectionKey(trace.Conn)

	// If a request is already pending for this connection, the arrival of a new
	// request means the connection is being reused, which implies the previous
	// request/response exchange has completed. Flush the previous one (the LRU
	// eviction callback emits it) and handle the new request immediately rather
	// than deferring it again.
	if ctx.pendingGoHTTPClientRequests.Contains(key) {
		ctx.pendingGoHTTPClientRequests.Remove(key)
		return false
	}

	// Only defer if we captured the request payload. Without it there is nothing
	// to wait for, so the span can be emitted immediately.
	if !containsTCPLargeBuffer(ctx, [16]uint8{}, packetTypeRequest,
		directionByPacketType(packetTypeRequest, true), key, ProtocolTypeHTTP) {
		return false
	}

	ctx.pendingGoHTTPClientRequests.Add(key, &pendingGoHTTPClientRequest{
		trace:     *trace,
		createdAt: time.Now(),
	})
	return true
}

func (ctx *EBPFParseContext) refreshPendingGoHTTPClientRequest(conn BpfConnectionInfoT) {
	if ctx.pendingGoHTTPClientRequests == nil || ctx.discardPendingGoHTTPClients.Load() {
		return
	}

	key := goHTTPClientConnectionKey(conn)
	pending, ok := ctx.pendingGoHTTPClientRequests.Get(key)
	if !ok || pending == nil || pending.emitted.Load() {
		return
	}

	if time.Since(pending.createdAt) >= ctx.goHTTPClientMaxPendingTime {
		ctx.pendingGoHTTPClientRequests.Remove(key)
		return
	}

	ctx.pendingGoHTTPClientRequests.Add(key, pending)
	if pending.emitted.Load() {
		ctx.pendingGoHTTPClientRequests.Remove(key)
	}
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

	method, tables := sqlprune.SQLParseOperationAndTables(sql)
	path := sqlprune.SQLTargetCollection(method, tables)

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

	subType := trace.SubType

	// if we didn't detect the type in Go, try heuristic detect
	if subType == uint8(request.DBGeneric) {
		switch hostPort {
		case 5432:
			subType = uint8(request.DBPostgres)
		case 3306:
			subType = uint8(request.DBMySQL)
		case 1434:
			subType = uint8(request.DBMSSQL)
		}
	}

	return request.Span{
		Type:          request.EventType(trace.Type),
		SubType:       int(subType),
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
		Statement:      sql,
		DBQuerySummary: sqlprune.SQLQuerySummary(method, tables),
	}
}
