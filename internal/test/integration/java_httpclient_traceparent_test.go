// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

const javaApplicationTraceparent = "00-33333333333333333333333333333333-4444444444444444-01"

func TestJavaHTTPClientTraceparent(t *testing.T) {
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-java-httpclient-traceparent.yml",
				path.Join(pathOutput, "test-suite-java-httpclient-traceparent-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "JAVA_HTTPCLIENT_PROPAGATION="+mode)
			t.Cleanup(func() { assert.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())
			var javaFeature int

			// Wait for dynamic agent attachment as well as HTTP readiness.
			for _, port := range []int{18080, 18086} {
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", port))
					require.NoError(ct, err)
					defer resp.Body.Close()
					body, err := io.ReadAll(resp.Body)
					require.NoError(ct, err)
					require.Equal(ct, http.StatusOK, resp.StatusCode)
					require.NotEmpty(ct, body, "Java agent has not attached")
					if port == 18080 {
						javaFeature, err = strconv.Atoi(resp.Header.Get("X-Java-Feature"))
						require.NoError(ct, err)
					}
				}, 2*time.Minute, time.Second)
			}

			run := fmt.Sprintf("%s-%d", mode, time.Now().UnixNano())
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				resp, err := http.Get("http://localhost:18080/call/" + run + "-warmup-" + strconv.FormatInt(time.Now().UnixNano(), 10))
				require.NoError(ct, err)
				require.NoError(ct, resp.Body.Close())
				require.Equal(ct, http.StatusOK, resp.StatusCode)
				trace, err := latestTraceMatching("java-httpclient", func(trace jaeger.Trace) bool {
					return len(clientSpans(trace)) > 0
				})
				require.NoError(ct, err)
				require.NotEmpty(ct, trace.TraceID, "Java TLS instrumentation is not ready")
			}, 2*time.Minute, time.Second)
			t.Run("generated", func(t *testing.T) {
				testJavaHTTPClientTraceparent(t, run+"-generated", "11111111111111111111111111111111", "", mode)
			})
			t.Run("application-owned", func(t *testing.T) {
				testJavaHTTPClientTraceparent(t, run+"-owned", "22222222222222222222222222222222", javaApplicationTraceparent, mode)
			})
			t.Run("application-owned-invalid", func(t *testing.T) {
				testJavaHTTPClientTraceparent(t, run+"-invalid", "55555555555555555555555555555555", "application-owned-invalid", mode)
			})
			t.Run("pooled-distinct-parents", func(t *testing.T) {
				first, second := run+"-pool-first", run+"-pool-second"
				testJavaHTTPClientTraceparent(t, first, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", mode)
				testJavaHTTPClientTraceparent(t, second, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "", mode)
				require.Equal(t, javaProxyObservations(t, first)[0].Connection, javaProxyObservations(t, second)[0].Connection,
					"distinct incoming parents must be tested on the same pooled TLS connection")
			})
			for i, testMode := range []string{"async", "http2", "http2-fallback", "oversized", "reentrant-async", "reuse", "retry", "redirect", "auth", "post", "expect-continue"} {
				t.Run(testMode, func(t *testing.T) {
					testJavaHTTPClientTraceparent(t, run+"-"+testMode, fmt.Sprintf("%032x", 0x200+i), "", mode, testMode)
				})
			}
			t.Run("application-owned-expect-continue", func(t *testing.T) {
				testJavaHTTPClientTraceparent(t, run+"-expect-owned", "dddddddddddddddddddddddddddddddd", javaApplicationTraceparent, mode, "expect-continue")
			})
			t.Run("expect-reject", func(t *testing.T) {
				id := run + "-expect-reject"
				req, err := http.NewRequest(http.MethodGet, "http://localhost:18080/call/"+id, nil)
				require.NoError(t, err)
				req.Header.Set("X-Test-Mode", "expect-reject")
				response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
				require.NoError(t, err)
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.Equal(t, http.StatusExpectationFailed, response.StatusCode)
				require.Equal(t, "expectation rejected", string(body))
				records := javaProxyObservations(t, id)
				require.Len(t, records, 1)
				require.Empty(t, records[0].Headers, "Expect-Continue requests must remain uninjected")
				require.Empty(t, records[0].Body)
			})
			t.Run("application-owned-duplicates", func(t *testing.T) {
				testJavaHTTPClientTraceparent(t, run+"-duplicates", "77777777777777777777777777777777", javaApplicationTraceparent, mode, "duplicate-owned")
			})
			if javaFeature >= 21 {
				t.Run("virtual-thread", func(t *testing.T) {
					testJavaHTTPClientTraceparent(t, run+"-virtual-thread", "99999999999999999999999999999999", "", mode, "virtual-thread")
				})
			}
			for _, testMode := range []string{"timeout", "interrupt", "tls-failure", "connect-failure"} {
				t.Run(testMode, func(t *testing.T) {
					req, err := http.NewRequest(http.MethodGet, "http://localhost:18080/call/"+run+"-"+testMode, nil)
					require.NoError(t, err)
					req.Header.Set("X-Test-Mode", testMode)
					response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
					require.NoError(t, err)
					defer response.Body.Close()
					body, err := io.ReadAll(response.Body)
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, response.StatusCode, string(body))
					require.Equal(t, "expected failure", string(body))
					testJavaHTTPClientTraceparent(t, run+"-after-"+testMode+"-ok", "88888888888888888888888888888888", "", mode)
				})
			}

			t.Run("concurrent", func(t *testing.T) {
				for i := range 4 {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						t.Parallel()
						testJavaHTTPClientTraceparent(t, fmt.Sprintf("%s-concurrent-%d", run, i),
							fmt.Sprintf("%032x", 0x100+i), "", mode)
					})
				}
			})
			t.Run("concurrent-same-trace", func(t *testing.T) {
				for i := range 4 {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						t.Parallel()
						testJavaHTTPClientTraceparent(t, fmt.Sprintf("%s-concurrent-same-trace-%d", run, i),
							"cccccccccccccccccccccccccccccccc", "", mode, "", fmt.Sprintf("%016x", 0x300+i))
					})
				}
			})
			t.Run("after-concurrent", func(t *testing.T) {
				testJavaHTTPClientTraceparent(t, run+"-after", "66666666666666666666666666666666", "", mode)
			})
			t.Run("cleanup", func(t *testing.T) {
				response, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://localhost:18080/propagation-state")
				require.NoError(t, err)
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, response.StatusCode, string(body))
				require.Equal(t, "0:0", string(body), "request tracking and native reservations must be released")
			})
		})
	}
}

func testJavaHTTPClientTraceparent(t *testing.T, id, traceID, owned, mode string, testModes ...string) {
	t.Helper()
	testMode := ""
	if len(testModes) > 0 {
		testMode = testModes[0]
	}
	injected := mode == "headers" && testMode != "http2" && testMode != "oversized" && testMode != "expect-continue"
	method := http.MethodGet
	if testMode == "post" || testMode == "expect-continue" {
		method = http.MethodPost
	}

	incomingParent := traceID[16:]
	if len(testModes) > 1 {
		incomingParent = testModes[1]
	}
	port := 18080
	if testMode == "virtual-thread" {
		port = 18081
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d/call/%s", port, id), nil)
	require.NoError(t, err)
	req.Header.Set("X-Test-Mode", testMode)
	req.Header.Set("traceparent", "00-"+traceID+"-"+incomingParent+"-01")
	if owned != "" {
		req.Header.Set("X-Application-Traceparent", owned)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	records := javaProxyObservations(t, id)
	downstreamID := id
	if testMode == "redirect" {
		downstreamID += "-target"
		records = append(records, javaProxyObservations(t, downstreamID)...)
	}
	wantRequests := 1
	if testMode == "reuse" || testMode == "retry" || testMode == "redirect" || testMode == "auth" {
		wantRequests = 2
	}
	require.Len(t, records, wantRequests)
	var headers []string
	for _, record := range records {
		protocol := 1
		if testMode == "http2" {
			protocol = 2
		}
		require.Equal(t, protocol, record.Protocol)
		if testMode == "post" || testMode == "expect-continue" {
			require.Equal(t, "body-preserved-by-injection", record.Body)
		}
		switch {
		case owned != "":
			expected := []string{owned}
			if testMode == "duplicate-owned" {
				expected = append(expected, owned)
			}
			require.Equal(t, expected, record.Headers, "application owns all supplied values")
		case !injected:
			require.Empty(t, record.Headers)
		default:
			require.Len(t, record.Headers, 1, "TLS proxy must receive exactly one traceparent per request")
			headers = append(headers, record.Headers[0])
			require.Regexp(t, `^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`, record.Headers[0])
			parts := strings.Split(record.Headers[0], "-")
			require.Equal(t, traceID, parts[1])
			require.NotEqual(t, "0000000000000000", parts[2])
		}
	}
	if testMode == "reentrant-async" {
		nested := javaProxyObservations(t, id+"-nested")
		require.Len(t, nested, 1)
		if mode == "headers" {
			require.Len(t, nested[0].Headers, 1)
			require.Regexp(t, `^00-`+traceID+`-[0-9a-f]{16}-01$`, nested[0].Headers[0])
		} else {
			require.Empty(t, nested[0].Headers)
		}
	}
	var downstream jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		downstream, err = javaDownstreamTrace(downstreamID, method)
		require.NoError(ct, err)
		require.NotEmpty(ct, downstream.TraceID)
	}, time.Minute, time.Second)
	for _, span := range downstream.FindByOperationNameServiceAndKind(method+" /"+downstreamID, "java-downstream", "server") {
		t.Logf("downstream server: trace_id=%s span_id=%s references=%+v", span.TraceID, span.SpanID, span.References)
	}

	var outboundSpanID string
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		trace, err := latestTraceMatching("java-httpclient", func(trace jaeger.Trace) bool {
			return len(trace.FindByOperationNameServiceAndKind("GET /call/"+id, "java-httpclient", "server")) > 0
		})
		require.NoError(ct, err)
		require.Equal(ct, traceID, trace.TraceID)
		servers := trace.FindByOperationNameServiceAndKind("GET /call/"+id, "java-httpclient", "server")
		require.Len(ct, servers, 1)
		require.Contains(ct, servers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: incomingParent})
		if owned != "" {
			if owned == javaApplicationTraceparent {
				parts := strings.Split(owned, "-")
				if testMode != "duplicate-owned" {
					assertJavaDownstreamParent(ct, id, method, parts[1], parts[2])
				}
			}
			return
		}
		if testMode == "virtual-thread" && !injected {
			// The existing TLS path can export this client in a separate trace.
			existing, err := latestTraceMatching("java-httpclient", func(trace jaeger.Trace) bool {
				return len(trace.FindByOperationNameServiceAndKind(method+" /"+id, "java-httpclient", "client")) > 0
			})
			require.NoError(ct, err)
			require.NotEmpty(ct, existing.TraceID)
			require.NotEqual(ct, traceID, downstream.TraceID)
			return
		}
		clients := trace.FindByOperationNameServiceAndKind(method+" /"+id, "java-httpclient", "client")
		if testMode == "redirect" {
			clients = append(clients, trace.FindByOperationNameServiceAndKind("GET /"+downstreamID, "java-httpclient", "client")...)
		}
		require.GreaterOrEqual(ct, len(clients), 1)
		outboundSpanID = clients[0].SpanID
		require.Equal(ct, traceID, clients[0].TraceID)
		if !injected {
			downstream, err := javaDownstreamTrace(downstreamID, method)
			require.NoError(ct, err)
			require.NotEmpty(ct, downstream.TraceID)
			require.NotEqual(ct, traceID, downstream.TraceID)
			return
		}
		spanIDs := make([]string, 0, len(clients))
		for _, span := range clients {
			spanIDs = append(spanIDs, span.SpanID)
			require.True(ct, javaSpanDescendsFrom(trace, span, servers[0].SpanID),
				"each client attempt must descend from its incoming server, including OBI processing spans")
		}
		for _, header := range headers {
			parts := strings.Split(header, "-")
			require.Contains(ct, spanIDs, parts[2], "injected parent must be an emitted client span")
		}
		if testMode == "reuse" || testMode == "retry" || testMode == "redirect" || testMode == "auth" {
			require.NotEqual(ct, headers[0], headers[1], "each attempt must use its own client span")
		}
		downstream, err := javaDownstreamTrace(downstreamID, method)
		require.NoError(ct, err)
		require.Equal(ct, traceID, downstream.TraceID)
		downstreamServers := downstream.FindByOperationNameServiceAndKind(method+" /"+downstreamID, "java-downstream", "server")
		require.NotEmpty(ct, downstreamServers)
		for _, server := range downstreamServers {
			matched := false
			for _, header := range headers {
				parts := strings.Split(header, "-")
				for _, reference := range server.References {
					matched = matched || reference == (jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: parts[2]})
				}
			}
			require.True(ct, matched, "downstream server must be a child of the injected client span")
		}
	}, time.Minute, time.Second)
	if outboundSpanID != "" {
		t.Logf("outbound client: trace_id=%s span_id=%s", traceID, outboundSpanID)
	}
}

type javaProxyObservation struct {
	Headers     []string `json:"headers"`
	Protocol    int      `json:"protocol"`
	Connection  string   `json:"connection"`
	Body        string   `json:"body"`
	Application string   `json:"application"`
	Tracestate  string   `json:"tracestate"`
}

func javaSpanDescendsFrom(trace jaeger.Trace, span jaeger.Span, ancestor string) bool {
	for range len(trace.Spans) {
		var parent string
		for _, reference := range span.References {
			if reference.RefType == "CHILD_OF" && reference.TraceID == trace.TraceID {
				parent = reference.SpanID
				break
			}
		}
		if parent == ancestor {
			return true
		}
		found := false
		for _, candidate := range trace.Spans {
			if candidate.SpanID == parent {
				span = candidate
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return false
}

func javaProxyObservations(t *testing.T, id string) []javaProxyObservation {
	t.Helper()
	response, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://localhost:18082/records/" + id)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	var observations []javaProxyObservation
	require.NoError(t, json.NewDecoder(response.Body).Decode(&observations))
	t.Logf("proxy observation: path=/%s records=%+v", id, observations)
	return observations
}

func javaDownstreamTrace(id string, methods ...string) (jaeger.Trace, error) {
	method := http.MethodGet
	if len(methods) > 0 {
		method = methods[0]
	}
	return latestTraceMatching("java-downstream", func(trace jaeger.Trace) bool {
		return len(trace.FindByOperationNameServiceAndKind(method+" /"+id, "java-downstream", "server")) > 0
	})
}

func assertJavaDownstreamParent(t require.TestingT, id, method, traceID, parentID string) {
	downstream, err := javaDownstreamTrace(id, method)
	require.NoError(t, err)
	require.Equal(t, traceID, downstream.TraceID)
	spans := downstream.FindByOperationNameServiceAndKind(method+" /"+id, "java-downstream", "server")
	require.Len(t, spans, 1)
	require.Contains(t, spans[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: parentID})
}
