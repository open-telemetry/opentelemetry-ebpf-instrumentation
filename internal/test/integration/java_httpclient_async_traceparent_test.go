// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

func TestJavaHTTPClientAsyncTraceparent(t *testing.T) {
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-java-httpclient-traceparent.yml",
				path.Join(pathOutput, "test-suite-java-httpclient-async-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "COMPOSE_PROJECT_NAME=obi-java-httpclient-async", "JAVA_HTTPCLIENT_PROPAGATION="+mode,
				"JAVA_HTTPCLIENT_PORTS=8080", "JAVA_HTTPCLIENT_DOWNSTREAM_OPTIONS=-javaagent:/fixture/opentelemetry-javaagent.jar")
			t.Cleanup(func() { assert.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())
			var javaFeature int
			for _, port := range []int{18080, 18086} {
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					response, err := http.Get(fmt.Sprintf("http://localhost:%d/health", port))
					require.NoError(ct, err)
					defer response.Body.Close()
					body, err := io.ReadAll(response.Body)
					require.NoError(ct, err)
					require.Equal(ct, http.StatusOK, response.StatusCode)
					if port == 18080 {
						require.NotEmpty(ct, body, "OBI agent must attach to source")
						javaFeature, err = strconv.Atoi(response.Header.Get("X-Java-Feature"))
						require.NoError(ct, err)
					} else {
						require.Empty(ct, body, "downstream must not have an OBI agent")
					}
				}, 2*time.Minute, time.Second)
			}
			run := fmt.Sprintf("async-%s-%d", mode, time.Now().UnixNano())
			waitForJavaHTTPClientTrace(t, run, mode)
			t.Run("shared-immutable", func(t *testing.T) {
				testJavaHTTPClientSharedAsync(t, run, mode)
			})
			for _, testMode := range []string{"generated", "push-overload", "reuse", "owned", "owned-empty", "owned-invalid", "duplicate-owned", "owned-ancestor", "owned-unsampled", "incoming-unsampled", "post", "cancel", "detached", "retry", "redirect", "auth", "http2", "http2-fallback", "oversized", "expect-continue", "reentrant-async", "virtual-thread"} {
				t.Run(testMode, func(t *testing.T) {
					if testMode == "virtual-thread" && javaFeature < 21 {
						t.Skip("virtual threads require JDK 21+")
					}
					testJavaHTTPClientAsync(t, run+"-"+testMode, mode, testMode)
				})
			}
			for _, testMode := range []string{"timeout", "connect-failure", "tls-failure", "synchronous-throw", "write-failure", "cancel-transport"} {
				t.Run(testMode, func(t *testing.T) {
					req, err := http.NewRequest(http.MethodGet, "http://localhost:18080/call/"+run+"-"+testMode, nil)
					require.NoError(t, err)
					req.Header.Set("X-Async", "true")
					req.Header.Set("X-Test-Mode", testMode)
					response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
					require.NoError(t, err)
					body, err := io.ReadAll(response.Body)
					require.NoError(t, response.Body.Close())
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, response.StatusCode, string(body))
					require.Equal(t, "expected failure", string(body))
					if testMode == "cancel-transport" {
						require.Contains(t, []string{"java.util.concurrent.CancellationException", "java.util.concurrent.CompletionException"}, response.Header.Get("X-Cancel-Exception"))
						t.Logf("JDK active cancellation: result=%s exception=%s", response.Header.Get("X-Cancel-Result"), response.Header.Get("X-Cancel-Exception"))
					}
					testJavaHTTPClientAsync(t, run+"-after-"+testMode+"-ok", mode, "generated")
				})
			}
			t.Run("pooled-distinct-parents", func(t *testing.T) {
				testJavaHTTPClientAsync(t, run+"-pool-first", mode, "generated")
				testJavaHTTPClientAsync(t, run+"-pool-second", mode, "generated")
				require.Equal(t, javaProxyObservations(t, run+"-pool-first")[0].Connection,
					javaProxyObservations(t, run+"-pool-second")[0].Connection, "exercise connection reuse with distinct incoming contexts")
			})
			t.Run("concurrent", func(t *testing.T) {
				for i := range 4 {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						t.Parallel()
						testJavaHTTPClientAsync(t, fmt.Sprintf("%s-concurrent-%d", run, i), mode, "generated")
					})
				}
			})
			t.Run("concurrent-same-trace", func(t *testing.T) {
				for i := range 4 {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						t.Parallel()
						testJavaHTTPClientAsync(t, fmt.Sprintf("%s-concurrent-same-trace-%d", run, i), mode, "generated",
							"cccccccccccccccccccccccccccccccc", fmt.Sprintf("%016x", 0x300+i))
					})
				}
			})
			t.Run("after-concurrent", func(t *testing.T) {
				testJavaHTTPClientAsync(t, run+"-after", mode, "generated")
			})
			t.Run("tracking-capacity", func(t *testing.T) {
				testJavaHTTPClientAsync(t, run+"-capacity", mode, "tracking-capacity")
				testJavaHTTPClientAsync(t, run+"-after-capacity", mode, "generated")
			})
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				response, err := http.Get("http://localhost:18080/propagation-state")
				require.NoError(ct, err)
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				require.NoError(ct, err)
				require.Equal(ct, "0:0", string(body), "requests and reservations must be released")
			}, 10*time.Second, time.Second)
		})
	}
}

func testJavaHTTPClientAsync(t *testing.T, id, mode, testMode string, incomingContext ...string) {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		response, err := getJaeger(jaegerQueryURL + "?service=java-httpclient&limit=100")
		if err != nil {
			t.Logf("source trace diagnostic: %v", err)
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err == nil {
			err = os.WriteFile(path.Join(pathOutput, id+"-java-httpclient-traces.json"), body, 0o644)
		}
		if err != nil {
			t.Logf("source trace diagnostic: %v", err)
		}
	})
	traceID := fmt.Sprintf("%032x", []byte(id[len(id)-16:]))
	incomingParent := traceID[16:]
	if len(incomingContext) == 2 {
		traceID, incomingParent = incomingContext[0], incomingContext[1]
	}
	applicationOwned := strings.HasPrefix(testMode, "owned") || testMode == "duplicate-owned"
	owned := javaApplicationTraceparent
	switch testMode {
	case "owned-empty":
		owned = ""
	case "owned-invalid":
		owned = "invalid"
	case "owned-ancestor":
		owned = "00-" + traceID + "-" + incomingParent + "-01"
	case "owned-unsampled":
		owned = strings.TrimSuffix(owned, "01") + "00"
	}
	validOwned := applicationOwned && (testMode == "owned" || testMode == "owned-ancestor" || testMode == "owned-unsampled")
	injected := mode == "headers" && testMode != "http2" && testMode != "oversized" && testMode != "expect-continue" && testMode != "tracking-capacity"
	method := http.MethodGet
	if testMode == "post" || testMode == "expect-continue" {
		method = http.MethodPost
	}
	port := 18080
	if testMode == "virtual-thread" {
		port = 18081
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d/call/%s", port, id), nil)
	require.NoError(t, err)
	flags := "01"
	if testMode == "incoming-unsampled" {
		flags = "00"
	}
	req.Header.Set("traceparent", "00-"+traceID+"-"+incomingParent+"-"+flags)
	req.Header.Set("X-Async", "true")
	req.Header.Set("X-Test-Mode", testMode)
	if applicationOwned {
		req.Header.Set("X-Application-Traceparent", owned)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, response.Body.Close())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode, string(body))
	if testMode == "cancel" {
		require.Equal(t, "cancelled", string(body))
	}
	if testMode == "detached" {
		require.Equal(t, "detached", string(body))
	}
	count := 1
	if testMode == "reuse" || testMode == "retry" || testMode == "auth" {
		count = 2
	}
	var records []javaProxyObservation
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		response, err := http.Get("http://localhost:18082/records/" + id)
		require.NoError(ct, err)
		defer response.Body.Close()
		require.Equal(ct, http.StatusOK, response.StatusCode)
		require.NoError(ct, json.NewDecoder(response.Body).Decode(&records))
		require.Len(ct, records, count)
	}, 30*time.Second, 100*time.Millisecond)
	downstreamID := id
	if testMode == "redirect" {
		downstreamID += "-target"
		records = append(records, javaProxyObservations(t, downstreamID)...)
		count = 2
	}
	t.Logf("proxy observation: path=/%s records=%+v", id, records)
	require.Len(t, records, count)
	for _, record := range records {
		protocol := 1
		if testMode == "http2" {
			protocol = 2
		}
		require.Equal(t, protocol, record.Protocol)
		require.Equal(t, "preserved", record.Application)
		require.Equal(t, "fixture=preserved", record.Tracestate)
		if method == http.MethodPost {
			require.Equal(t, "body-preserved-by-injection", record.Body)
		}
		switch {
		case applicationOwned:
			expected := []string{owned}
			if testMode == "duplicate-owned" {
				expected = append(expected, owned)
			}
			require.Equal(t, expected, record.Headers)
		case !injected:
			require.Empty(t, record.Headers)
		default:
			require.Len(t, record.Headers, 1, "exactly one transmitted traceparent")
			require.Regexp(t, `^00-`+traceID+`-[0-9a-f]{16}-01$`, record.Headers[0])
		}
	}
	if testMode == "reuse" {
		require.Equal(t, records[0].Connection, records[1].Connection)
	}
	if count == 2 && injected && !applicationOwned {
		require.NotEqual(t, records[0].Headers, records[1].Headers, "attempts need distinct client identities")
	}
	if testMode == "owned-unsampled" {
		require.Never(t, func() bool {
			downstream, err := latestTraceMatching("java-downstream", func(candidate jaeger.Trace) bool {
				for _, span := range candidate.Spans {
					if len(span.Diff(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + id})) == 0 {
						return true
					}
				}
				return false
			})
			return err != nil || downstream.TraceID != ""
		}, time.Second, 100*time.Millisecond, "the downstream's parent-based sampler must honor supplied 00 flags")
	}
	expectedTrace := traceID
	if validOwned {
		expectedTrace = strings.Split(owned, "-")[1]
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		source, err := fetchTrace(traceID)
		require.NoError(ct, err)
		require.Len(ct, source.Data, 1)
		trace := source.Data[0]
		servers := trace.FindByOperationNameServiceAndKind("GET /call/"+id, "java-httpclient", "server")
		require.Len(ct, servers, 1)
		require.Contains(ct, servers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: incomingParent})
		var downstream jaeger.Trace
		if injected && !applicationOwned || validOwned {
			query, err := fetchTrace(expectedTrace)
			require.NoError(ct, err)
			require.Len(ct, query.Data, 1)
			downstream = query.Data[0]
		} else {
			downstream, err = latestTraceMatching("java-downstream", func(trace jaeger.Trace) bool {
				for _, span := range trace.Spans {
					if len(span.Diff(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + downstreamID})) == 0 {
						return true
					}
				}
				return false
			})
			require.NoError(ct, err)
			require.NotEmpty(ct, downstream.TraceID)
		}
		clients := trace.FindByOperationNameServiceAndKind(method+" /"+id, "java-httpclient", "client")
		if mode == "disabled" && (testMode == "cancel" || testMode == "detached" || testMode == "virtual-thread") {
			// The merged baseline can export these clients in a new trace after the source replies.
			existing, err := latestTraceMatching("java-httpclient", func(candidate jaeger.Trace) bool {
				return len(candidate.FindByOperationNameServiceAndKind(method+" /"+id, "java-httpclient", "client")) > 0
			})
			require.NoError(ct, err)
			require.NotEmpty(ct, existing.TraceID)
			clients = existing.FindByOperationNameServiceAndKind(method+" /"+id, "java-httpclient", "client")
		}
		if testMode == "redirect" {
			clients = append(clients, trace.FindByOperationNameServiceAndKind("GET /"+downstreamID, "java-httpclient", "client")...)
		}
		if !applicationOwned {
			require.Len(ct, clients, count)
		}
		if applicationOwned {
			if validOwned && expectedTrace != traceID {
				clients = append(clients, downstream.FindByOperationNameServiceAndKind(method+" /"+id, "java-httpclient", "client")...)
			}
			if validOwned {
				require.Len(ct, clients, 1)
			}
			if testMode == "owned-ancestor" {
				require.Len(ct, clients, 1)
				require.True(ct, javaSpanDescendsFrom(trace, clients[0], servers[0].SpanID))
			}
			for _, client := range clients {
				require.NotEqual(ct, incomingParent, client.SpanID)
				if validOwned {
					require.NotEqual(ct, strings.Split(owned, "-")[2], client.SpanID, "application context is not a local span reservation")
				}
				for _, reference := range client.References {
					require.NotEqual(ct, client.SpanID, reference.SpanID, "client must not parent itself")
				}
			}
		}
		if !injected && !applicationOwned || applicationOwned && !validOwned {
			require.NotEqual(ct, traceID, downstream.TraceID)
			return
		}
		require.Equal(ct, expectedTrace, downstream.TraceID)
		for _, record := range records {
			if applicationOwned {
				continue
			}
			parent := strings.Split(record.Headers[0], "-")[2]
			found := false
			for _, client := range clients {
				if client.SpanID == parent {
					found = true
					require.True(ct, javaSpanDescendsFrom(trace, client, servers[0].SpanID), "ancestry includes OBI processing spans")
				}
			}
			require.True(ct, found, "transmitted parent must match exported source client")
		}
		found := false
		for _, span := range downstream.Spans {
			if downstream.Processes[span.ProcessID].ServiceName != "java-downstream" || len(span.Diff(
				jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
				jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + downstreamID})) != 0 {
				continue
			}
			matched := false
			for _, record := range records {
				parent := strings.Split(record.Headers[0], "-")[2]
				for _, ref := range span.References {
					matched = matched || ref == (jaeger.Reference{RefType: "CHILD_OF", TraceID: expectedTrace, SpanID: parent})
				}
			}
			require.True(ct, matched, "OTel downstream server must be a child of a transmitted client span")
			found = true
		}
		if testMode == "owned-unsampled" {
			require.False(ct, found, "unsampled downstream requests are not exported")
		} else {
			require.True(ct, found, "downstream server export must be present")
		}
	}, time.Minute, time.Second)
}

func waitForJavaHTTPClientTrace(t *testing.T, run, mode string) {
	t.Helper()
	id := run + "-warmup"
	traceID := fmt.Sprintf("%032x", []byte(id[len(id)-16:]))
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost:18080/call/"+id, nil)
		require.NoError(ct, err)
		req.Header.Set("traceparent", "00-"+traceID+"-"+traceID[16:]+"-01")
		response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		require.NoError(ct, err)
		_, err = io.ReadAll(response.Body)
		require.NoError(ct, err)
		require.NoError(ct, response.Body.Close())
		require.Equal(ct, http.StatusOK, response.StatusCode)
		query, err := fetchTrace(traceID)
		require.NoError(ct, err)
		require.Len(ct, query.Data, 1)
		trace := query.Data[0]
		servers := trace.FindByOperationNameServiceAndKind("GET /call/"+id, "java-httpclient", "server")
		require.NotEmpty(ct, servers)
		if mode == "headers" {
			clients := trace.FindByOperationNameServiceAndKind("GET /"+id, "java-httpclient", "client")
			linked := false
			for _, client := range clients {
				for _, server := range servers {
					linked = linked || javaSpanDescendsFrom(trace, client, server.SpanID)
				}
			}
			require.True(ct, linked)
		} else {
			clientTrace, err := latestTraceMatching("java-httpclient", func(trace jaeger.Trace) bool {
				return len(trace.FindByOperationNameServiceAndKind("GET /"+id, "java-httpclient", "client")) > 0
			})
			require.NoError(ct, err)
			require.NotEmpty(ct, clientTrace.TraceID)
		}
	}, 2*time.Minute, time.Second)
}

func testJavaHTTPClientSharedAsync(t *testing.T, run, mode string) {
	t.Helper()
	t.Run("calls", func(t *testing.T) {
		for i := range 4 {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				t.Parallel()
				id := fmt.Sprintf("%s-shared-concurrent-%d", run, i)
				req, err := http.NewRequest(http.MethodGet, "http://localhost:18080/call/"+id, nil)
				require.NoError(t, err)
				req.Header.Set("traceparent", fmt.Sprintf("00-%032x-%016x-01", 0x700+i, 0x800+i))
				req.Header.Set("X-Async", "true")
				req.Header.Set("X-Test-Mode", "shared-immutable")
				response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				require.NoError(t, response.Body.Close())
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, response.StatusCode, string(body))
			})
		}
	})
	records := javaProxyObservations(t, "shared-immutable")
	require.Len(t, records, 4)
	for _, record := range records {
		require.Equal(t, 1, record.Protocol)
		require.Equal(t, "preserved", record.Application)
		require.Equal(t, "fixture=preserved", record.Tracestate)
		if mode == "disabled" {
			require.Empty(t, record.Headers)
		} else {
			require.Len(t, record.Headers, 1)
		}
	}
	for i := range 4 {
		traceID := fmt.Sprintf("%032x", 0x700+i)
		id := fmt.Sprintf("%s-shared-concurrent-%d", run, i)
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			query, err := fetchTrace(traceID)
			require.NoError(ct, err)
			require.Len(ct, query.Data, 1)
			trace := query.Data[0]
			servers := trace.FindByOperationNameServiceAndKind("GET /call/"+id, "java-httpclient", "server")
			require.Len(ct, servers, 1)
			require.Contains(ct, servers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: fmt.Sprintf("%016x", 0x800+i)})
			clients := trace.FindByOperationNameServiceAndKind("GET /shared-immutable", "java-httpclient", "client")
			require.Len(ct, clients, 1)
			if mode == "disabled" {
				return
			}
			require.True(ct, javaSpanDescendsFrom(trace, clients[0], servers[0].SpanID))
			expected := "00-" + traceID + "-" + clients[0].SpanID + "-01"
			matches := 0
			for _, record := range records {
				if record.Headers[0] == expected {
					matches++
				}
			}
			require.Equal(ct, 1, matches, "shared immutable requests must retain independent owners")
			downstream := false
			for _, span := range trace.Spans {
				if trace.Processes[span.ProcessID].ServiceName == "java-downstream" && len(span.Diff(
					jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
					jaeger.Tag{Key: "url.path", Type: "string", Value: "/shared-immutable"})) == 0 {
					require.Contains(ct, span.References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: clients[0].SpanID})
					downstream = true
				}
			}
			require.True(ct, downstream)
		}, time.Minute, time.Second)
	}
}
