// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func hasAttributeKey(attrs []attribute.KeyValue, key attribute.Key) bool {
	for _, kv := range attrs {
		if kv.Key == key {
			return true
		}
	}

	return false
}

// A response that was never observed was never received, so semconv forbids the
// attribute.
func TestTraceAttributesSelector_UnparsedResponseOmitsStatusCode(t *testing.T) {
	statusCode := attribute.Key(attr.HTTPResponseStatusCode)
	observed := attribute.Key(attr.OBIHTTPResponseObserved)

	for _, eventType := range []request.EventType{request.EventTypeHTTPClient, request.EventTypeHTTP} {
		span := &request.Span{
			Type:                eventType,
			Method:              "GET",
			Path:                "/r",
			Host:                "relay",
			HostPort:            9100,
			ResponseObservation: request.ResponseReceived,
		}

		attrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})

		assert.False(t, hasAttributeKey(attrs, statusCode),
			"%s: no status code is reported when none was observed", eventType)
		assert.Contains(t, attrs, attribute.Bool(string(observed), false),
			"%s: the span says the response was not observed", eventType)
	}
}

// No span on this path names an error type.
func TestTraceAttributesSelector_UnknownOutcomeNamesNoError(t *testing.T) {
	errorType := attribute.Key(attr.ErrorType)

	for _, eventType := range []request.EventType{request.EventTypeHTTPClient, request.EventTypeHTTP} {
		span := &request.Span{
			Type:                eventType,
			Method:              "GET",
			Path:                "/r",
			Host:                "relay",
			HostPort:            9100,
			ResponseObservation: request.ResponseReceived,
		}

		attrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})

		assert.False(t, hasAttributeKey(attrs, errorType),
			"%s: a span nobody judged names no error", eventType)
	}
}

// The control. An ordinary request reports its status and says nothing about
// observation.
func TestTraceAttributesSelector_ObservedResponseKeepsStatusCode(t *testing.T) {
	observed := attribute.Key(attr.OBIHTTPResponseObserved)

	for _, eventType := range []request.EventType{request.EventTypeHTTPClient, request.EventTypeHTTP} {
		span := &request.Span{
			Type:     eventType,
			Method:   "GET",
			Path:     "/r",
			Host:     "relay",
			HostPort: 9100,
			Status:   200,
		}

		attrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})

		assert.Contains(t, attrs, request.HTTPResponseStatusCode(200), eventType)
		assert.False(t, hasAttributeKey(attrs, observed),
			"%s: the observation marker is additive and absent on a normal span", eventType)
	}
}
