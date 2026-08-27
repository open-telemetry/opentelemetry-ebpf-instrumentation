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

// A status nobody parsed cannot be reported, and the span says which observation
// left it absent. The values are the ones declared in
// schemas/obi/groups/traces.yaml; anything else fails the semconv live check.
func TestTraceAttributesSelector_UnparsedResponseReportsObservation(t *testing.T) {
	statusCode := attribute.Key(attr.HTTPResponseStatusCode)
	observation := attribute.Key(attr.OBIHTTPResponseObservation)

	for _, tc := range []struct {
		observed request.ResponseObservation
		value    string
	}{
		{request.ResponseReceived, "not_captured"},
		{request.ResponseSilent, "not_received"},
		{request.ResponseUnread, "not_parsed"},
	} {
		for _, eventType := range []request.EventType{request.EventTypeHTTPClient, request.EventTypeHTTP} {
			span := &request.Span{
				Type:                eventType,
				Method:              "GET",
				Path:                "/r",
				Host:                "relay",
				HostPort:            9100,
				ResponseObservation: tc.observed,
			}

			attrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})

			assert.False(t, hasAttributeKey(attrs, statusCode),
				"%s/%s: no status code is reported when none was parsed", eventType, tc.value)
			assert.Contains(t, attrs, attribute.String(string(observation), tc.value),
				"%s: the span says how much of the response was observed", eventType)
		}
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
	observation := attribute.Key(attr.OBIHTTPResponseObservation)

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
		assert.False(t, hasAttributeKey(attrs, observation),
			"%s: the observation marker is additive and absent on a normal span", eventType)
	}
}

// The two response fields stand or fall together. A status and a length are both read
// off the response, so a span that never had one reports neither, and a span that did
// reports both. Seeded nonzero so a suppressed field is told apart from an absent value.
func TestTraceAttributesSelector_ResponseFieldsFollowTheResponse(t *testing.T) {
	const (
		seededStatus = 200
		seededLength = 1024
	)

	statusCode := attribute.Key(attr.HTTPResponseStatusCode)
	bodySize := attribute.Key(attr.HTTPResponseBodySize)
	observation := attribute.Key(attr.OBIHTTPResponseObservation)

	for _, tc := range []struct {
		name     string
		observed request.ResponseObservation
		known    bool
	}{
		{"parsed", request.ResponseParsed, true},
		{"not_captured", request.ResponseReceived, false},
		{"not_received", request.ResponseSilent, false},
		{"not_parsed", request.ResponseUnread, false},
	} {
		for _, eventType := range []request.EventType{request.EventTypeHTTPClient, request.EventTypeHTTP} {
			t.Run(eventType.String()+"/"+tc.name, func(t *testing.T) {
				span := &request.Span{
					Type:                eventType,
					Method:              "GET",
					Path:                "/r",
					Host:                "relay",
					HostPort:            9100,
					Status:              seededStatus,
					ResponseLength:      seededLength,
					ResponseObservation: tc.observed,
				}

				attrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})

				if tc.known {
					assert.Contains(t, attrs, request.HTTPResponseStatusCode(seededStatus),
						"a parsed response reports the status it carried")
					assert.Contains(t, attrs, request.HTTPResponseBodySize(seededLength),
						"a parsed response reports the length it carried")
					assert.False(t, hasAttributeKey(attrs, observation),
						"the observation marker is absent on a parsed response")

					return
				}

				assert.False(t, hasAttributeKey(attrs, statusCode),
					"no status is reported when none was parsed")
				assert.False(t, hasAttributeKey(attrs, bodySize),
					"no response length is reported when none was parsed")
				assert.Contains(t, attrs, attribute.String(string(observation), tc.name),
					"the span says how much of the response was observed")
			})
		}
	}
}
