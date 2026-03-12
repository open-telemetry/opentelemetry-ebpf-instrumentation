// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

// doHTTPGetWithHeaders sends a GET request with custom request headers.
func doHTTPGetWithHeaders(t *testing.T, url string, status int, headers map[string]string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	defer r.Body.Close()
	require.Equal(t, status, r.StatusCode)
}

// doHTTPGetWithRawHeaders sends a GET request allowing multiple values per header key.
func doHTTPGetWithRawHeaders(t *testing.T, url string, status int, headers http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header = headers
	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	defer r.Body.Close()
	require.Equal(t, status, r.StatusCode)
}

// testGenericHeaderExtraction verifies that the generic HTTP header parsing
// configuration correctly extracts, obfuscates, and excludes headers on spans.
func testGenericHeaderExtraction(t *testing.T) {
	// Send requests to /rolldice/42 with custom request headers.
	// The test server sets response headers: Content-Type and X-Dice-Roll.
	for i := 0; i < 4; i++ {
		doHTTPGetWithHeaders(t, instrumentedServiceStdURL+"/rolldice/42", 200, map[string]string{
			"X-Custom-Foo":  "custom-value",
			"Authorization": "Bearer secret-token",
			"Accept":        "text/plain", // not in the include list -> excluded
		})
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Frolldice%2F%3Aid")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/42"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	// Find the server span
	res := trace.FindByOperationName("GET /rolldice/:id", "server")
	require.NotEmpty(t, res)
	parent := res[0]

	// Verify included request headers appear on the span.
	// Headers are exported as http.request.header.<lowercase-name> with string slice values.
	tag, ok := jaeger.FindIn(parent.Tags, "http.request.header.x-custom-foo")
	require.True(t, ok, "expected X-Custom-Foo request header on span")
	val, valOk := jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Equal(t, "custom-value", val)

	// Verify Authorization header is obfuscated (rule 1: obfuscate).
	tag, ok = jaeger.FindIn(parent.Tags, "http.request.header.authorization")
	require.True(t, ok, "expected Authorization request header on span (obfuscated)")
	val, valOk = jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Equal(t, "***", val, "Authorization should be obfuscated")

	// Verify excluded headers are NOT present (Accept is not in include rules).
	_, ok = jaeger.FindIn(parent.Tags, "http.request.header.accept")
	assert.False(t, ok, "Accept header should be excluded")

	// Verify included response headers appear on the span.
	// The test server sets X-Dice-Roll and Content-Type response headers.
	tag, ok = jaeger.FindIn(parent.Tags, "http.response.header.x-dice-roll")
	require.True(t, ok, "expected X-Dice-Roll response header on span")
	val, valOk = jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.NotEmpty(t, val)

	tag, ok = jaeger.FindIn(parent.Tags, "http.response.header.content-type")
	require.True(t, ok, "expected Content-Type response header on span")
	vals := jaeger.TagStringValues(tag)
	require.NotEmpty(t, vals)
	assert.Contains(t, vals[0], "text/plain")
}

// testGenericHeaderRuleOrder verifies that rule ordering is preserved:
// the obfuscate rule for Authorization fires before the include-all rule.
func testGenericHeaderRuleOrder(t *testing.T) {
	// Send a request with both Authorization and a custom header.
	for i := 0; i < 4; i++ {
		doHTTPGetWithHeaders(t, instrumentedServiceStdURL+"/rolldice/99", 200, map[string]string{
			"Authorization":   "Bearer another-secret",
			"X-Custom-Header": "should-be-included",
		})
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Frolldice%2F%3Aid")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/99"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	res := trace.FindByOperationName("GET /rolldice/:id", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// Authorization should be obfuscated because rule 1 (obfuscate) fires before rule 2 (include).
	tag, ok := jaeger.FindIn(span.Tags, "http.request.header.authorization")
	require.True(t, ok, "expected Authorization request header on span")
	val, valOk := jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Equal(t, "***", val, "Authorization should be obfuscated by rule 1, not included by rule 2")

	// X-Custom-Header should be included by rule 2.
	tag, ok = jaeger.FindIn(span.Tags, "http.request.header.x-custom-header")
	require.True(t, ok, "expected X-Custom-Header request header on span")
	val, valOk = jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Equal(t, "should-be-included", val)
}

// testGenericHeaderMultipleValues verifies that headers with multiple values
// (added via Header.Add, i.e. duplicate header names) are all captured in the span.
func testGenericHeaderMultipleValues(t *testing.T) {
	headers := http.Header{}
	// A header appearing twice (two Add calls = two values under one key)
	headers.Add("X-Custom-Multi", "value-one")
	headers.Add("X-Custom-Multi", "value-two")
	// A header with three separate values
	headers.Add("X-Custom-Triple", "alpha")
	headers.Add("X-Custom-Triple", "beta")
	headers.Add("X-Custom-Triple", "gamma")

	for i := 0; i < 4; i++ {
		doHTTPGetWithRawHeaders(t, instrumentedServiceStdURL+"/rolldice/77", 200, headers.Clone())
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Frolldice%2F%3Aid")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/77"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	res := trace.FindByOperationName("GET /rolldice/:id", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// X-Custom-Multi was added twice → both values should be present.
	tag, ok := jaeger.FindIn(span.Tags, "http.request.header.x-custom-multi")
	require.True(t, ok, "expected X-Custom-Multi request header on span")
	vals := jaeger.TagStringValues(tag)
	assert.Contains(t, vals, "value-one", "first value of duplicate header should be present")
	assert.Contains(t, vals, "value-two", "second value of duplicate header should be present")

	// X-Custom-Triple was added three times → all three values should be present.
	tag, ok = jaeger.FindIn(span.Tags, "http.request.header.x-custom-triple")
	require.True(t, ok, "expected X-Custom-Triple request header on span")
	tripleVals := jaeger.TagStringValues(tag)
	assert.Contains(t, tripleVals, "alpha")
	assert.Contains(t, tripleVals, "beta")
	assert.Contains(t, tripleVals, "gamma")
}

func TestSuiteGenericHeaders(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-generic-headers.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-http-enrichment-headers")
	compose.Env = append(compose.Env, "OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=true")
	require.NoError(t, compose.Up())

	t.Run("Enrichment header extraction", func(t *testing.T) {
		waitForTestComponents(t, instrumentedServiceStdURL)
		testGenericHeaderExtraction(t)
	})
	t.Run("Enrichment header rule order", func(t *testing.T) {
		testGenericHeaderRuleOrder(t)
	})
	t.Run("Enrichment header multiple values", func(t *testing.T) {
		testGenericHeaderMultipleValues(t)
	})

	require.NoError(t, compose.Close())
}
