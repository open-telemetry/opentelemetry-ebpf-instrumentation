// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jaeger

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestQueryV3URL(t *testing.T) {
	now := time.Date(2026, time.September, 21, 12, 0, 0, 0, time.UTC)
	got, err := queryV3URL(
		"http://localhost:16686/api/traces?service=checkout&operation=GET+%2Fcart&limit=50&lookback=5m&tags=%7B%22http.request.method%22%3A%22GET%22%7D",
		now,
	)
	require.NoError(t, err)

	u, err := url.Parse(got)
	require.NoError(t, err)
	assert.Equal(t, "/api/v3/traces", u.Path)
	assert.Equal(t, "checkout", u.Query().Get("query.serviceName"))
	assert.Equal(t, "GET /cart", u.Query().Get("query.operationName"))
	assert.Equal(t, "50", u.Query().Get("query.searchDepth"))
	assert.JSONEq(t, `{"http.request.method":"GET"}`, u.Query().Get("query.attributes"))
	assert.Equal(t, now.Add(-5*time.Minute).Format(time.RFC3339Nano), u.Query().Get("query.startTimeMin"))
	assert.Equal(t, now.Format(time.RFC3339Nano), u.Query().Get("query.startTimeMax"))
}

func TestQueryV3URLByTraceID(t *testing.T) {
	got, err := queryV3URL(
		"http://localhost:16686/api/traces?service=checkout&traceID=0123456789abcdef",
		time.Now(),
	)
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:16686/api/v3/traces/0123456789abcdef", got)

	got, err = queryV3URL(
		"http://localhost:16686/api/traces/0123456789abcdef",
		time.Now(),
	)
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:16686/api/v3/traces/0123456789abcdef", got)
}

func TestConvertV3Body(t *testing.T) {
	traces := ptrace.NewTraces()
	resourceSpans := traces.ResourceSpans().AppendEmpty()
	resourceSpans.Resource().Attributes().PutStr("service.name", "checkout")
	resourceSpans.Resource().Attributes().PutStr("service.namespace", "shop")
	scopeSpans := resourceSpans.ScopeSpans().AppendEmpty()
	scopeSpans.Scope().SetName("go.opentelemetry.io/obi")
	span := scopeSpans.Spans().AppendEmpty()
	span.SetTraceID(pcommon.TraceID{1})
	span.SetSpanID(pcommon.SpanID{2})
	span.SetParentSpanID(pcommon.SpanID{3})
	span.SetName("GET /cart")
	span.SetKind(ptrace.SpanKindServer)
	span.SetStartTimestamp(10_000)
	span.SetEndTimestamp(25_000)
	span.Attributes().PutInt("http.response.status_code", 500)
	span.Status().SetCode(ptrace.StatusCodeError)
	span.Status().SetMessage("request failed")
	event := span.Events().AppendEmpty()
	event.SetName("exception")
	event.SetTimestamp(20_000)
	event.Attributes().PutStr("exception.type", "boom")

	result, err := new(ptrace.JSONMarshaler).MarshalTraces(traces)
	require.NoError(t, err)
	body, err := json.Marshal(v3Response{Result: result})
	require.NoError(t, err)
	legacyBody, err := convertV3Body(body)
	require.NoError(t, err)

	var query TracesQuery
	require.NoError(t, json.Unmarshal(legacyBody, &query))
	require.Len(t, query.Data, 1)
	trace := query.Data[0]
	assert.Equal(t, span.TraceID().String(), trace.TraceID)
	require.Len(t, trace.Spans, 1)
	legacySpan := trace.Spans[0]
	assert.Equal(t, "GET /cart", legacySpan.OperationName)
	assert.Equal(t, int64(10), legacySpan.StartTime)
	assert.Equal(t, int64(15), legacySpan.Duration)
	assert.Empty(t, legacySpan.Diff(
		Tag{Key: "http.response.status_code", Type: "int64", Value: float64(500)},
		Tag{Key: "otel.scope.name", Type: "string", Value: "go.opentelemetry.io/obi"},
		Tag{Key: "span.kind", Type: "string", Value: "server"},
		Tag{Key: "otel.status_code", Type: "string", Value: "ERROR"},
		Tag{Key: "error", Type: "bool", Value: true},
	))
	assert.Equal(t, "checkout", trace.Processes[legacySpan.ProcessID].ServiceName)
	require.Len(t, legacySpan.Logs, 1)
	assert.Equal(t, Tag{Key: "event", Type: "string", Value: "exception"}, legacySpan.Logs[0].Fields[0])
}

func TestGetMapsMissingTracesToEmptyLegacyResponse(t *testing.T) {
	originalTransport := http.DefaultClient.Transport
	http.DefaultClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, "/api/v3/traces", r.URL.Path)
		assert.Equal(t, "checkout", r.URL.Query().Get("query.serviceName"))
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Status:     "404 Not Found",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("No traces found")),
			Request:    r,
		}, nil
	})
	t.Cleanup(func() { http.DefaultClient.Transport = originalTransport })

	resp, err := Get("http://localhost:16686/api/traces?service=checkout")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, resp.Body.Close()) })
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var query TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&query))
	assert.Empty(t, query.Data)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
