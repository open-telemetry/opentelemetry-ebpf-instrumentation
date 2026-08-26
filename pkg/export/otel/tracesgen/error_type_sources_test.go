// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// manualStringAttrs encodes key/value pairs the way the manual-span path expects
// to find them in Statement.
func manualStringAttrs(t *testing.T, kv ...string) string {
	t.Helper()
	require.Zero(t, len(kv)%2, "want key/value pairs")

	encoded := make([]SpanAttr, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		a := SpanAttr{Vtype: uint8(attribute.STRING)}
		copy(a.Key[:], kv[i])
		copy(a.Value[:], kv[i+1])
		encoded = append(encoded, a)
	}

	payload, err := json.Marshal(encoded)
	require.NoError(t, err)

	return string(payload)
}

// A manual span may already carry a caller-supplied error.type. Duplicate keys
// are invalid OTLP, and the caller's classification is the specific one.
func TestTraceAttributesSelector_ManualSpanKeepsItsOwnErrorType(t *testing.T) {
	span := &request.Span{
		Type:      request.EventTypeManualSpan,
		Status:    int(codes.Error),
		Statement: manualStringAttrs(t, "error.type", "MyCustomError", "foo", "bar"),
	}

	attrs := TraceAttributesSelector(span, defaultTraceAttrs(t))

	require.Equal(t, 1, countAttr(attrs, "error.type"), "duplicate keys are invalid OTLP")
	v, ok := errorTypeValue(attrs)
	require.True(t, ok)
	assert.Equal(t, "MyCustomError", v.AsString(), "the caller's value must win over _OTHER")
}

// Some protocols report a failure inside a 2xx response, so the parsed error
// cannot be gated on the HTTP status.
func TestTraceAttributesSelector_ParsedErrorInsideSuccessResponse(t *testing.T) {
	t.Run("sql++ classifies from the response body", func(t *testing.T) {
		span := &request.Span{
			Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeSQLPP,
			Method: "POST", Path: "/query/service", Host: "cb", HostPort: 8093,
			Status:   200,
			DBSystem: "couchbase",
			DBError:  request.DBError{ErrorCode: "5000", Description: "fatal"},
		}

		v, ok := errorTypeValue(TraceAttributesSelector(span, defaultTraceAttrs(t)))
		require.True(t, ok, "a body-parsed failure still needs error.type")
		assert.Equal(t, "5000", v.AsString())
	})

	t.Run("openai-compatible reports the provider error", func(t *testing.T) {
		span := &request.Span{
			Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeOpenAICompatible,
			Method: "POST", Path: "/v1/chat", Status: 200,
			GenAI: &request.GenAI{OpenAICompatible: &request.VendorOpenAI{
				Error: request.OpenAIError{Type: "invalid_request_error"},
			}},
		}

		v, ok := errorTypeValue(TraceAttributesSelector(span, defaultTraceAttrs(t)))
		require.True(t, ok, "OpenAI-compatible providers report errors inside a 2xx")
		assert.Equal(t, "invalid_request_error", v.AsString())
	})
}
