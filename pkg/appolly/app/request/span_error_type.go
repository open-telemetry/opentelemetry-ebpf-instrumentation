// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"strconv"

	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
)

const ErrorTypeOther = "_OTHER"

// SpanErrorType returns error.type for a failed span, or "" when the span did
// not fail. It is the single source for both the trace and the metric pipeline,
// so the attribute and the metric label cannot disagree.
//
// A failed span always yields a value: semconv requires error.type on failure,
// and _OTHER is its fallback for a failure that cannot be classified further.
func SpanErrorType(span *Span) string {
	// A parsed protocol error is the most specific answer available, wherever
	// the parser happened to put it. It is checked before the status gate
	// because some protocols report a failure inside a 2xx response: SQL++
	// classifies from the JSON body and never touches span.Status.
	if errType := parsedErrorType(span); errType != "" {
		return errType
	}

	if SpanStatusCode(span) != StatusCodeError {
		return ""
	}

	switch span.Type {
	case EventTypeHTTP, EventTypeHTTPClient:
		if span.Status >= 400 {
			return strconv.Itoa(span.Status)
		}
	case EventTypeGRPC, EventTypeGRPCClient:
		if code := GRPCStatusCodeString(span.Status); code != "" {
			return code
		}
	case EventTypeDNS:
		return dnsparser.RCode(span.Status).String()
	}

	return ErrorTypeOther
}

// parsedErrorType reports the error a protocol parser extracted from the
// payload, across every field the parsers write it to.
func parsedErrorType(span *Span) string {
	if span.DBError.ErrorCode != "" {
		return span.DBError.ErrorCode
	}
	if span.SQLError != nil && span.SQLError.SQLState != "" {
		return span.SQLError.SQLState
	}
	if errType := span.GenAIErrorType(); errType != "" {
		return errType
	}
	if span.SubType == HTTPSubtypeJSONRPC && span.JSONRPC != nil && span.JSONRPC.ErrorCode != 0 {
		return strconv.Itoa(span.JSONRPC.ErrorCode)
	}
	if span.SubType == HTTPSubtypeMCP && span.GenAI != nil && span.GenAI.MCP != nil &&
		span.GenAI.MCP.ErrorCode != 0 {
		return strconv.Itoa(span.GenAI.MCP.ErrorCode)
	}

	return ""
}
