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

// testBodyExtractionObfuscate verifies that the body extraction rules correctly
// capture the request body with sensitive fields obfuscated.
func testBodyExtractionObfuscate(t *testing.T) {
	// Send POST requests with a JSON body containing sensitive fields.
	// The config obfuscates $.password and $.secret on POST requests.
	for i := 0; i < 4; i++ {
		doHTTPPost(t, instrumentedServiceStdURL+"/rolldice/50", 200,
			[]byte(`{"username":"alice","password":"secret123","secret":"my-api-key","email":"alice@test.com"}`))
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=POST%20%2Frolldice%2F%3Aid")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/50"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	res := trace.FindByOperationName("POST /rolldice/:id", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// Verify the request body content attribute is present.
	tag, ok := jaeger.FindIn(span.Tags, "http.request.body.content")
	require.True(t, ok, "expected http.request.body.content on span")
	val, valOk := jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)

	// Verify sensitive fields are obfuscated.
	assert.NotContains(t, val, "secret123", "password should be obfuscated")
	assert.NotContains(t, val, "my-api-key", "secret should be obfuscated")
	assert.Contains(t, val, "***", "obfuscation string should be present")

	// Verify non-sensitive fields are preserved.
	assert.Contains(t, val, "alice", "username should be present")
	assert.Contains(t, val, "alice@test.com", "email should be present")
}

// testBodyExtractionInclude verifies that body include rules capture the raw body
// without obfuscation when only an include rule matches.
func testBodyExtractionInclude(t *testing.T) {
	// The config has an include rule for POST /rolldice/* which also matches,
	// but the obfuscate rule also matches POST requests.
	// Since body rules merge, both rules apply: obfuscate paths are applied
	// to the included body.

	// Send a POST without the sensitive fields to test pure include behavior.
	for i := 0; i < 4; i++ {
		doHTTPPost(t, instrumentedServiceStdURL+"/rolldice/51", 200,
			[]byte(`{"action":"roll","sides":6}`))
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=POST%20%2Frolldice%2F%3Aid")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/51"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	res := trace.FindByOperationName("POST /rolldice/:id", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// Verify the request body content is present with original values.
	tag, ok := jaeger.FindIn(span.Tags, "http.request.body.content")
	require.True(t, ok, "expected http.request.body.content on span")
	val, valOk := jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Contains(t, val, "roll", "action field should be present")
	assert.Contains(t, val, "6", "sides field should be present")
}

// testBodyExtractionExcludedByDefault verifies that GET requests (which don't match
// any body rules) have no body content on the span.
func testBodyExtractionExcludedByDefault(t *testing.T) {
	for i := 0; i < 4; i++ {
		doHTTPGetWithHeaders(t, instrumentedServiceStdURL+"/rolldice/52", 200, nil)
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
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/52"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	res := trace.FindByOperationName("GET /rolldice/:id", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// Verify no body content is present (default_action for body is exclude).
	_, ok := jaeger.FindIn(span.Tags, "http.request.body.content")
	assert.False(t, ok, "GET request should not have body content")
	_, ok = jaeger.FindIn(span.Tags, "http.response.body.content")
	assert.False(t, ok, "response body should not be present")
}

// testBodyExtractionContentTypeHeader verifies that the Content-Type header
// is also included on the span (configured via a header include rule).
func testBodyExtractionContentTypeHeader(t *testing.T) {
	for i := 0; i < 4; i++ {
		doHTTPPost(t, instrumentedServiceStdURL+"/rolldice/53", 200,
			[]byte(`{"test":"header-check"}`))
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=POST%20%2Frolldice%2F%3Aid")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/53"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	res := trace.FindByOperationName("POST /rolldice/:id", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// Verify Content-Type header is included alongside body content.
	tag, ok := jaeger.FindIn(span.Tags, "http.request.header.content-type")
	require.True(t, ok, "expected Content-Type header on span")
	val, valOk := jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Contains(t, val, "application/json")

	// Body should also be present.
	_, ok = jaeger.FindIn(span.Tags, "http.request.body.content")
	assert.True(t, ok, "expected body content alongside headers")
}

func TestSuiteBodyExtraction(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-body-extraction.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-http-enrichment-body")
	compose.Env = append(compose.Env, "OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=true")
	require.NoError(t, compose.Up())

	t.Run("Body extraction obfuscate", func(t *testing.T) {
		waitForTestComponents(t, instrumentedServiceStdURL)
		testBodyExtractionObfuscate(t)
	})
	t.Run("Body extraction include", func(t *testing.T) {
		testBodyExtractionInclude(t)
	})
	t.Run("Body excluded by default", func(t *testing.T) {
		testBodyExtractionExcludedByDefault(t)
	})
	t.Run("Body with Content-Type header", func(t *testing.T) {
		testBodyExtractionContentTypeHeader(t)
	})

	require.NoError(t, compose.Close())
}
