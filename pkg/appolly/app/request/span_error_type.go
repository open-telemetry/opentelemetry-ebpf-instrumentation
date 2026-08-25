// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"strconv"

	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
)

const ErrorTypeOther = "_OTHER"

// SpanErrorType returns the status-derived error.type for a failed span, or ""
// when the span did not fail. Callers that already derived a more specific
// value from protocol detail keep theirs.
func SpanErrorType(span *Span) string {
	if SpanStatusCode(span) != StatusCodeError {
		return ""
	}

	if span.DBError.ErrorCode != "" {
		return span.DBError.ErrorCode
	}

	switch span.Type {
	case EventTypeHTTP, EventTypeHTTPClient:
		// A subtype is a different protocol carried over HTTP, so the HTTP
		// status is not its error.
		if span.SubType != HTTPSubtypeNone {
			return ""
		}
		if span.Status >= 400 {
			return strconv.Itoa(span.Status)
		}
		return ErrorTypeOther
	case EventTypeGRPC, EventTypeGRPCClient:
		if code := GRPCStatusCodeString(span.Status); code != "" {
			return code
		}
		return ErrorTypeOther
	case EventTypeRedisClient, EventTypeRedisServer,
		EventTypeMongoClient, EventTypeCouchbaseClient,
		EventTypeMemcachedClient, EventTypeMemcachedServer,
		EventTypeAerospikeClient:
		return ErrorTypeOther
	case EventTypeDNS:
		return dnsparser.RCode(span.Status).String()
	case EventTypeSQLClient, EventTypeSQLServer:
		// Only reached when no SQLSTATE was captured; otherwise the SQL branch
		// reports it.
		return ErrorTypeOther
	}

	return ""
}
