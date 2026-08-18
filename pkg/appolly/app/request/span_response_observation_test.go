// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A client span with no observed response used to report an error twice over: through
// the fabricated 499, and through HTTPSpanStatusCode's zero-status branch. OBI saw
// nothing, so the status is Unset.
func TestSpanStatusCode_UnknownOutcomeIsUnset(t *testing.T) {
	for _, eventType := range []EventType{EventTypeHTTPClient, EventTypeHTTP} {
		span := &Span{Type: eventType, ResponseObservation: ResponseReceived}

		assert.Equal(t, StatusCodeUnset, SpanStatusCode(span), eventType)
	}
}

// The guard fires on the marker, not on the zero status, so a request that genuinely
// failed without a response keeps reporting an error.
func TestSpanStatusCode_UnsetStatusWithoutMarkerStaysError(t *testing.T) {
	for _, eventType := range []EventType{EventTypeHTTPClient, EventTypeHTTP} {
		span := &Span{Type: eventType}

		assert.Equal(t, StatusCodeError, SpanStatusCode(span), eventType)
	}
}

// The control: ordinary outcomes are unchanged.
func TestSpanStatusCode_ObservedResponsesAreUnchanged(t *testing.T) {
	tests := []struct {
		name      string
		eventType EventType
		status    int
		expected  string
	}{
		{"client 200", EventTypeHTTPClient, 200, StatusCodeUnset},
		{"client 404", EventTypeHTTPClient, 404, StatusCodeError},
		{"client 500", EventTypeHTTPClient, 500, StatusCodeError},
		{"server 200", EventTypeHTTP, 200, StatusCodeUnset},
		{"server 404", EventTypeHTTP, 404, StatusCodeUnset},
		{"server 500", EventTypeHTTP, 500, StatusCodeError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := &Span{Type: tt.eventType, Status: tt.status}

			assert.Equal(t, tt.expected, SpanStatusCode(span))
		})
	}
}
