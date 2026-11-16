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
					} else {
						require.Empty(ct, body, "downstream must not have an OBI agent")
					}
				}, 2*time.Minute, time.Second)
			}
			run := fmt.Sprintf("async-%s-%d", mode, time.Now().UnixNano())
			waitForJavaHTTPClientTrace(t, run, mode)
			for _, testMode := range []string{"generated", "push-overload", "owned", "owned-invalid", "cancel"} {
				t.Run(testMode, func(t *testing.T) {
					testJavaHTTPClientAsync(t, run+"-"+testMode, mode, testMode)
				})
			}
			t.Run("shared-immutable", func(t *testing.T) {
				for i := range 4 {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						t.Parallel()
						testJavaHTTPClientAsync(t, fmt.Sprintf("%s-shared-concurrent-%d", run, i), mode, "shared-immutable")
					})
				}
			})
			for _, testMode := range []string{"timeout", "connect-failure", "tls-failure"} {
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
					testJavaHTTPClientAsync(t, run+"-after-"+testMode+"-ok", mode, "generated")
				})
			}
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

func testJavaHTTPClientAsync(t *testing.T, id, mode, testMode string) {
	t.Helper()
	traceID := fmt.Sprintf("%032x", []byte(id[len(id)-16:]))
	incomingParent := traceID[16:]
	req, err := http.NewRequest(http.MethodGet, "http://localhost:18080/call/"+id, nil)
	require.NoError(t, err)
	req.Header.Set("traceparent", "00-"+traceID+"-"+incomingParent+"-01")
	req.Header.Set("X-Async", "true")
	req.Header.Set("X-Test-Mode", testMode)
	owned := ""
	switch testMode {
	case "owned":
		owned = javaApplicationTraceparent
	case "owned-invalid":
		owned = "invalid"
	}
	if owned != "" {
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
	outbound := id
	count := 1
	if testMode == "shared-immutable" {
		outbound, count = "shared-immutable", 4
	}
	var records []javaProxyObservation
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		response, err := http.Get("http://localhost:18082/records/" + outbound)
		require.NoError(ct, err)
		defer response.Body.Close()
		require.Equal(ct, http.StatusOK, response.StatusCode)
		require.NoError(ct, json.NewDecoder(response.Body).Decode(&records))
		require.Len(ct, records, count)
	}, 30*time.Second, 100*time.Millisecond)
	for _, record := range records {
		require.Equal(t, 1, record.Protocol)
		require.Equal(t, "preserved", record.Application)
		require.Equal(t, "fixture=preserved", record.Tracestate)
		switch {
		case owned != "":
			require.Equal(t, []string{owned}, record.Headers)
		case mode == "disabled":
			require.Empty(t, record.Headers)
		default:
			require.Len(t, record.Headers, 1)
		}
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		source, err := fetchTrace(traceID)
		require.NoError(ct, err)
		require.Len(ct, source.Data, 1)
		trace := source.Data[0]
		servers := trace.FindByOperationNameServiceAndKind("GET /call/"+id, "java-httpclient", "server")
		require.Len(ct, servers, 1)
		require.Contains(ct, servers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: incomingParent})
		if testMode == "owned-invalid" || mode == "disabled" && owned == "" {
			return
		}
		var parentID string
		if owned != "" {
			parts := strings.Split(owned, "-")
			query, err := fetchTrace(parts[1])
			require.NoError(ct, err)
			require.Len(ct, query.Data, 1)
			trace, parentID = query.Data[0], parts[2]
		} else {
			clients := trace.FindByOperationNameServiceAndKind("GET /"+outbound, "java-httpclient", "client")
			require.Len(ct, clients, 1)
			require.True(ct, javaSpanDescendsFrom(trace, clients[0], servers[0].SpanID))
			parentID = clients[0].SpanID
			header := "00-" + traceID + "-" + parentID + "-01"
			matches := 0
			for _, record := range records {
				if record.Headers[0] == header {
					matches++
				}
			}
			require.Equal(ct, 1, matches, "each call must transmit its own exported client identity")
		}
		downstream := false
		for _, span := range trace.Spans {
			if trace.Processes[span.ProcessID].ServiceName == "java-downstream" && len(span.Diff(
				jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
				jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + outbound})) == 0 {
				require.Contains(ct, span.References, jaeger.Reference{RefType: "CHILD_OF", TraceID: trace.TraceID, SpanID: parentID})
				downstream = true
			}
		}
		require.True(ct, downstream, "OTel downstream must parent to the transmitted client")
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
