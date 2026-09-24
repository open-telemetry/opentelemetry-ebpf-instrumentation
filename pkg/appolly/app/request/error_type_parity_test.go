// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// The metric label and the span attribute must agree.
func TestErrorTypeMetricMatchesSpan(t *testing.T) {
	getter, ok := spanOTELGetters(attr.ErrorType)
	require.True(t, ok)

	for _, tc := range []struct {
		name     string
		span     *Span
		expected string
	}{
		{
			name:     "http status code",
			span:     &Span{Type: EventTypeHTTP, Status: 503},
			expected: "503",
		},
		{
			name:     "grpc status name",
			span:     &Span{Type: EventTypeGRPC, Path: "/pkg.Svc/M", Status: 14},
			expected: "UNAVAILABLE",
		},
		{
			name:     "db server error code",
			span:     &Span{Type: EventTypeRedisClient, Method: "GET", Status: 1, DBError: DBError{ErrorCode: "WRONGTYPE"}},
			expected: "WRONGTYPE",
		},
		{
			name:     "dns rcode",
			span:     &Span{Type: EventTypeDNS, Method: "A", Path: "nope.test", Status: 3},
			expected: "NXDomain",
		},
		{
			name:     "genai provider error",
			span:     &Span{Type: EventTypeHTTPClient, SubType: HTTPSubtypeOpenAI, Status: 429, GenAI: &GenAI{OpenAI: &VendorOpenAI{Error: OpenAIError{Type: "rate_limit_error"}}}},
			expected: "rate_limit_error",
		},
		{
			name:     "sql sqlstate",
			span:     &Span{Type: EventTypeSQLClient, Method: "SELECT", Status: 1, SQLError: &SQLError{Code: 1064, SQLState: "42000"}},
			expected: "42000",
		},
		{
			// MySQL reports the numeric code unconditionally, SQLSTATE only
			// under CLIENT_PROTOCOL_41.
			name:     "sql numeric code when sqlstate is absent",
			span:     &Span{Type: EventTypeSQLClient, Method: "SELECT", Status: 1, SQLError: &SQLError{Code: 1064}},
			expected: "1064",
		},
		{
			name:     "sunrpc denied",
			span:     &Span{Type: EventTypeSunRPCClient, Path: "portmapper", Route: "0", Status: 1},
			expected: "denied",
		},
		{
			name:     "sunrpc accept_stat",
			span:     &Span{Type: EventTypeSunRPCServer, Path: "nfs", Route: "1", Status: 3},
			expected: "2",
		},
		{
			name:     "failed with nothing to classify by",
			span:     &Span{Type: EventTypeRedisClient, Method: "GET", Status: 1},
			expected: ErrorTypeOther,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, SpanErrorType(tc.span), "span value")

			kv := getter(tc.span)
			require.True(t, kv.Valid(), "metric label must be present")
			assert.Equal(t, tc.expected, kv.Value.AsString(), "metric label")
		})
	}

	t.Run("omitted on success", func(t *testing.T) {
		span := &Span{Type: EventTypeHTTP, Status: 200}
		assert.Empty(t, SpanErrorType(span))
		assert.False(t, getter(span).Valid(), "successful requests must not carry error.type")
	})
}
