// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testJavaNestedTraces(t *testing.T, slug string) {
	// give enough time for the Java injector to finish and to
	// harvest the routes
	t.Log("checking proper server to client nesting for [/api/" + slug + "]")
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:8081/api/"+slug+"?url=https://httpbin.org/get", 200)

		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fapi%2F" + slug)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/api/" + slug})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
		res := trace.FindByOperationName("GET /get", "client")
		require.Len(ct, res, 1)
		child := res[0]
		require.NotEmpty(ct, child.TraceID)
	}, 2*time.Minute, 5*time.Second)
}

func TestJavaNestedTraces(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-dist.yml", path.Join(pathOutput, "test-suite-java-dist.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	waitForTestComponentsRoute(t, "http://localhost:8081", "/api/health")

	for _, slug := range []string{"request", "async-request", "async-request-c", "async-request-fj"} {
		t.Run("Nested traces for "+slug, func(t *testing.T) {
			testJavaNestedTraces(t, slug)
		})
	}

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func TestJavaMalformedIoctlFailsClosed(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-dist-malicious-ioctl.yml", path.Join(pathOutput, "test-suite-java-dist-malicious-ioctl.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	waitForTestComponentsRoute(t, "http://localhost:8081", "/api/health")

	obiLogsBefore, err := compose.LogsOutput("obi")
	require.NoError(t, err)
	unknownCmdCountBefore := strings.Count(obiLogsBefore, "unknown cmd=0 [____obi_kprobe_sys_ioctl]")

	resp, err := http.Post("http://localhost:8081/api/malicious-ioctl", "application/json", nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var ioctlResponse map[string]any
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &ioctlResponse))
	require.GreaterOrEqual(t, ioctlResponse["saved_stdin_fd"], float64(0))
	require.EqualValues(t, 0, ioctlResponse["dup_rc"])
	require.EqualValues(t, -1, ioctlResponse["ioctl_rc"])
	require.EqualValues(t, 25, ioctlResponse["ioctl_errno"])
	require.EqualValues(t, 0, ioctlResponse["restore_rc"])
	require.EqualValues(t, 0, ioctlResponse["close_rc"])
	require.EqualValues(t, 0, ioctlResponse["close_saved_rc"])

	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`http_server_request_duration_seconds_count{http_route="/api/malicious-ioctl"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		trace, err := latestTraceMatching("testserver", func(trace jaeger.Trace) bool {
			return traceHasSpanTags(trace,
				jaeger.Tag{Key: "http.route", Type: "string", Value: "/api/malicious-ioctl"},
				jaeger.Tag{Key: "http.request.method", Type: "string", Value: "POST"},
			)
		})
		require.NoError(ct, err)
		require.NotEmpty(ct, trace.TraceID)
		require.Empty(ct, clientSpans(trace))
	}, 2*time.Minute, 5*time.Second)

	assert.Never(t, func() bool {
		obiLogs, err := compose.LogsOutput("obi")
		assert.NoError(t, err)
		if err != nil {
			return false
		}

		return strings.Count(obiLogs, "unknown cmd=0 [____obi_kprobe_sys_ioctl]") > unknownCmdCountBefore
	}, 10*time.Second, 500*time.Millisecond)

	testJavaNestedTraces(t, "request")
}

func latestTraceMatching(service string, predicate func(jaeger.Trace) bool) (jaeger.Trace, error) {
	params := url.Values{}
	params.Set("service", service)
	params.Set("limit", "50")

	resp, err := http.Get(jaegerQueryURL + "?" + params.Encode())
	if err != nil {
		return jaeger.Trace{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return jaeger.Trace{}, fmt.Errorf("jaeger query returned status %d", resp.StatusCode)
	}

	var tq jaeger.TracesQuery
	if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
		return jaeger.Trace{}, err
	}

	if len(tq.Data) == 0 {
		return jaeger.Trace{}, nil
	}

	var matches []jaeger.Trace
	for _, trace := range tq.Data {
		if predicate(trace) {
			matches = append(matches, trace)
		}
	}

	if len(matches) == 0 {
		return jaeger.Trace{}, nil
	}

	slices.SortFunc(matches, func(a, b jaeger.Trace) int {
		return cmp.Compare(latestSpanStartTime(b), latestSpanStartTime(a))
	})

	return matches[0], nil
}

func latestSpanStartTime(trace jaeger.Trace) int64 {
	var latest int64
	for _, span := range trace.Spans {
		if span.StartTime > latest {
			latest = span.StartTime
		}
	}

	return latest
}

func clientSpans(trace jaeger.Trace) []jaeger.Span {
	var clientSpans []jaeger.Span
	for _, span := range trace.Spans {
		tag, ok := jaeger.FindIn(span.Tags, "span.kind")
		if ok && tag.Value == "client" {
			clientSpans = append(clientSpans, span)
		}
	}

	return clientSpans
}

func traceHasSpanTags(trace jaeger.Trace, tags ...jaeger.Tag) bool {
	for _, span := range trace.Spans {
		if len(span.Diff(tags...)) == 0 {
			return true
		}
	}

	return false
}
