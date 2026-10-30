// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

const apacheConcurrentRequests = 4

func TestJavaApacheHTTPClientTraceparent(t *testing.T) {
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-java-apache-httpclient.yml",
				path.Join(pathOutput, "test-suite-java-apache-httpclient-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "JAVA_HTTPCLIENT_PROPAGATION="+mode, "COMPOSE_PROJECT_NAME=obi-apache-httpclient", "OTEL_EBPF_EXECUTABLE_PATH=", "OTEL_EBPF_OPEN_PORT=")
			t.Cleanup(func() { assert.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				response, err := http.Get("http://localhost:24180/health")
				require.NoError(ct, err)
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				require.NoError(ct, err)
				require.NotEmpty(ct, body, "OBI Java agent has not attached")
			}, 2*time.Minute, time.Second)

			run := fmt.Sprintf("apache-%s-%d", mode, time.Now().UnixNano())
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				response, err := http.Post("http://localhost:24180/call/"+run+"-warmup-"+strconv.FormatInt(time.Now().UnixNano(), 10), "text/plain", strings.NewReader("warmup"))
				require.NoError(ct, err)
				require.NoError(ct, response.Body.Close())
				require.Equal(ct, http.StatusOK, response.StatusCode)
				trace, err := apacheHTTPClientTrace("java-apache-httpclient", "")
				require.NoError(ct, err)
				require.NotEmpty(ct, trace.TraceID, "Java TLS instrumentation is not ready")
			}, 2*time.Minute, time.Second)

			t.Run("generated", func(t *testing.T) {
				testJavaApacheTraceparent(t, run+"-generated", "11111111111111111111111111111111", "", mode)
			})
			t.Run("pooled-distinct-parents", func(t *testing.T) {
				first := testJavaApacheTraceparent(t, run+"-pool-first", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", mode)
				second := testJavaApacheTraceparent(t, run+"-pool-second", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "", mode)
				require.Equal(t, first.Connection, second.Connection, "requests must reuse the same TLS connection")
			})
			t.Run("application-owned", func(t *testing.T) {
				testJavaApacheTraceparent(t, run+"-owned", "22222222222222222222222222222222", javaApplicationTraceparent, mode)
			})
			for i, scenario := range []string{"overload-0", "overload-1", "overload-2", "overload-3", "overload-4", "overload-5", "overload-6", "overload-7", "retry", "redirect", "auth", "reuse", "reentrant", "handler-reentrant", "body-like", "split", "oversized", "capacity", "expect-continue", "expect-reject", "unsampled", "empty-owned", "invalid-owned", "duplicate-owned", "ancestor-owned", "unsampled-owned"} {
				t.Run(scenario, func(t *testing.T) {
					testJavaApacheScenario(t, run+"-"+scenario, fmt.Sprintf("%032x", 0x400+i), scenario, mode)
					if scenario == "capacity" {
						testJavaApacheTraceparent(t, run+"-after-capacity-ok", "dddddddddddddddddddddddddddddddd", "", mode)
					}
				})
			}
			for _, scenario := range []string{"timeout", "abort", "connect-failure", "tls-failure", "write-failure"} {
				t.Run(scenario, func(t *testing.T) {
					require.NoError(t, sendJavaApacheRequest(run+"-"+scenario, "88888888888888888888888888888888", "", scenario))
					testJavaApacheTraceparent(t, run+"-after-"+scenario+"-ok", "99999999999999999999999999999999", "", mode)
				})
			}
			t.Run("cleanup", func(t *testing.T) {
				response, err := http.Get("http://localhost:24180/propagation-state")
				require.NoError(t, err)
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.Equal(t, "0:0", string(body))
				activeResponse, err := http.Get("http://localhost:24180/active-executions")
				require.NoError(t, err)
				defer activeResponse.Body.Close()
				active, err := io.ReadAll(activeResponse.Body)
				require.NoError(t, err)
				require.Equal(t, "0", string(active), "Apache execution scopes must drain")
			})
			t.Run("concurrent", func(t *testing.T) {
				testJavaApacheConcurrentContexts(t, run, mode)
			})
			t.Run("concurrent-same-trace", func(t *testing.T) {
				results := make(chan error, apacheConcurrentRequests)
				for i := range apacheConcurrentRequests {
					go func() {
						results <- sendJavaApacheRequest(fmt.Sprintf("%s-concurrent-same-%d", run, i), "cccccccccccccccccccccccccccccccc", "", "", fmt.Sprintf("%016x", 0x900+i))
					}()
				}
				for range apacheConcurrentRequests {
					require.NoError(t, <-results)
				}
				for i := range apacheConcurrentRequests {
					assertJavaApacheTraceparent(t, fmt.Sprintf("%s-concurrent-same-%d", run, i), "cccccccccccccccccccccccccccccccc", "", mode, fmt.Sprintf("%016x", 0x900+i))
				}
			})
		})
	}
}

type apacheProxyObservation struct {
	javaProxyObservation
	Unrelated  string `json:"unrelated"`
	Tracestate string `json:"tracestate"`
}

func testJavaApacheTraceparent(t *testing.T, id, traceID, owned, mode string) apacheProxyObservation {
	t.Helper()
	require.NoError(t, sendJavaApacheRequest(id, traceID, owned))
	return assertJavaApacheTraceparent(t, id, traceID, owned, mode)
}

func testJavaApacheConcurrentContexts(t *testing.T, run, mode string) {
	t.Helper()
	results := make(chan error, apacheConcurrentRequests)
	for i := range apacheConcurrentRequests {
		go func() {
			results <- sendJavaApacheRequest(fmt.Sprintf("%s-concurrent-%d", run, i), fmt.Sprintf("%032x", 0x100+i), "")
		}()
	}
	for range apacheConcurrentRequests {
		require.NoError(t, <-results)
	}
	for i := range apacheConcurrentRequests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			assertJavaApacheTraceparent(t, fmt.Sprintf("%s-concurrent-%d", run, i), fmt.Sprintf("%032x", 0x100+i), "", mode)
		})
	}
}

func apacheRequestBody(id string) string {
	if strings.Contains(id, "-body-like") {
		return "GET /__body_probe__ HTTP/1.1\r\nX-Body: preserved\r\n\r\npayload"
	}
	return "body-preserved-" + id + "\r\ntraceparent: body-content\r\n\r\n"
}

func sendJavaApacheRequest(id, traceID, owned string, scenarios ...string) error {
	body := apacheRequestBody(id)
	request, err := http.NewRequest(http.MethodPost, "http://localhost:24180/call/"+id, strings.NewReader(body))
	if err != nil {
		return err
	}
	scenario := ""
	if len(scenarios) > 0 {
		scenario = scenarios[0]
	}
	request.Header.Set("X-Test-Mode", scenario)
	flags := "01"
	if scenario == "unsampled" {
		flags = "00"
	}
	parent := traceID[16:]
	if len(scenarios) > 1 {
		parent = scenarios[1]
	}
	request.Header.Set("traceparent", "00-"+traceID+"-"+parent+"-"+flags)
	if owned != "" || scenario == "empty-owned" {
		request.Header.Set("X-Application-Traceparent", owned)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK && scenario != "expect-reject" {
		return fmt.Errorf("apache source returned %d: %s", response.StatusCode, responseBody)
	}
	switch scenario {
	case "timeout", "abort", "tls-failure", "connect-failure", "write-failure":
		body = "expected failure"
	case "retry", "redirect", "auth", "handler-reentrant":
		body = ""
	}
	if scenario == "expect-reject" {
		if response.StatusCode != http.StatusExpectationFailed || string(responseBody) != "expectation rejected" {
			return fmt.Errorf("unexpected Expect rejection: %d %q", response.StatusCode, responseBody)
		}
		return nil
	}
	if string(responseBody) != body {
		return fmt.Errorf("request body was not preserved for %s: %q", id, responseBody)
	}
	return nil
}

func assertJavaApacheTraceparent(t *testing.T, id, traceID, owned, mode string, parentIDs ...string) apacheProxyObservation {
	t.Helper()
	parentID := traceID[16:]
	if len(parentIDs) > 0 {
		parentID = parentIDs[0]
	}
	response, err := http.Get("http://localhost:24182/records/" + id)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	var records []apacheProxyObservation
	require.NoError(t, json.NewDecoder(response.Body).Decode(&records))
	require.Len(t, records, 1, "exactly one request must reach the TLS proxy")
	record := records[0]
	t.Logf("TLS proxy: path=/%s observation=%+v", id, record)
	require.Equal(t, 1, record.Protocol)
	require.Equal(t, apacheRequestBody(id), record.Body)
	require.Equal(t, "preserved", record.Unrelated)
	require.Equal(t, "vendor=value", record.Tracestate)
	switch {
	case owned != "":
		require.Equal(t, []string{owned}, record.Headers)
	case mode == "disabled":
		require.Empty(t, record.Headers)
	default:
		require.Len(t, record.Headers, 1, "exactly one traceparent must be transmitted")
		require.Regexp(t, `^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`, record.Headers[0])
		require.Equal(t, traceID, strings.Split(record.Headers[0], "-")[1])
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		source, err := apacheHTTPClientTrace("java-apache-httpclient", "POST /call/"+id)
		require.NoError(ct, err)
		require.Equal(ct, traceID, source.TraceID)
		servers := source.FindByOperationNameServiceAndKind("POST /call/"+id, "java-apache-httpclient", "server")
		require.Len(ct, servers, 1)
		require.Contains(ct, servers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: parentID})
		downstream, err := apacheHTTPClientTrace("apache-downstream", "POST /"+id)
		require.NoError(ct, err)
		downstreamServers := downstream.FindByOperationNameServiceAndKind("POST /"+id, "apache-downstream", "server")
		require.Len(ct, downstreamServers, 1)
		if owned != "" {
			parts := strings.Split(owned, "-")
			require.Equal(ct, parts[1], downstream.TraceID)
			require.Contains(ct, downstreamServers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: parts[1], SpanID: parts[2]})
			return
		}
		clients := source.FindByOperationNameServiceAndKind("POST /"+id, "java-apache-httpclient", "client")
		require.Len(ct, clients, 1)
		parent, ok := source.ParentOf(&clients[0])
		require.True(ct, ok, "source client must have an exported parent")
		if parent.SpanID != servers[0].SpanID {
			require.Equal(ct, "processing", parent.OperationName)
			require.Equal(ct, servers[0].ProcessID, parent.ProcessID)
			kind, ok := jaeger.FindIn(parent.Tags, "span.kind")
			require.True(ct, ok)
			require.Equal(ct, "internal", kind.Value)
			require.Contains(ct, parent.References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: servers[0].SpanID})
		}
		require.Contains(ct, clients[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: parent.SpanID})
		if mode == "disabled" {
			require.NotEqual(ct, traceID, downstream.TraceID)
			return
		}
		parts := strings.Split(record.Headers[0], "-")
		require.Equal(ct, clients[0].SpanID, parts[2])
		require.Equal(ct, traceID, downstream.TraceID)
		require.Contains(ct, downstreamServers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: clients[0].SpanID})
		t.Logf("span chain: trace=%s server=%s client_parent=%s client=%s downstream=%s", traceID, servers[0].SpanID, parent.SpanID, clients[0].SpanID, downstreamServers[0].SpanID)
	}, time.Minute, time.Second)
	return record
}

func apacheHTTPClientTrace(service, operation string) (jaeger.Trace, error) {
	query := url.Values{"service": {service}, "limit": {"50"}}
	if operation != "" {
		query.Set("operation", operation)
	}
	response, err := getJaeger("http://localhost:24186/api/traces?" + query.Encode())
	if err != nil {
		return jaeger.Trace{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return jaeger.Trace{}, fmt.Errorf("jaeger query returned %d", response.StatusCode)
	}
	var traces jaeger.TracesQuery
	if err := json.NewDecoder(response.Body).Decode(&traces); err != nil {
		return jaeger.Trace{}, err
	}
	for _, trace := range traces.Data {
		if operation != "" || len(clientSpans(trace)) > 0 {
			return trace, nil
		}
	}
	return jaeger.Trace{}, nil
}

func apacheObservations(t *testing.T, id string) []apacheProxyObservation {
	t.Helper()
	response, err := http.Get("http://localhost:24182/records/" + id)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	var records []apacheProxyObservation
	require.NoError(t, json.NewDecoder(response.Body).Decode(&records))
	return records
}

func testJavaApacheScenario(t *testing.T, id, traceID, scenario, mode string) {
	t.Helper()
	owned := ""
	switch scenario {
	case "invalid-owned":
		owned = "invalid"
	case "duplicate-owned":
		owned = javaApplicationTraceparent
	case "ancestor-owned":
		owned = "00-" + traceID + "-" + traceID[16:] + "-01"
	case "unsampled-owned":
		owned = strings.TrimSuffix(javaApplicationTraceparent, "01") + "00"
	}
	require.NoError(t, sendJavaApacheRequest(id, traceID, owned, scenario))
	records := apacheObservations(t, id)
	want := 1
	if scenario == "retry" || scenario == "reuse" || scenario == "auth" {
		want = 2
	}
	require.Len(t, records, want)
	paths := make([]string, len(records))
	for i := range paths {
		paths[i] = id
	}
	if scenario == "redirect" {
		records = append(records, apacheObservations(t, id+"-target")...)
		paths = append(paths, id+"-target")
		require.Len(t, records, 2)
	}
	if scenario == "reentrant" || scenario == "handler-reentrant" {
		nested := apacheObservations(t, id+"-nested")
		require.Len(t, nested, 1)
		records = append(records, nested...)
		paths = append(paths, id+"-nested")
	}
	injected := mode == "headers" && owned == "" && scenario != "empty-owned" && scenario != "oversized" && scenario != "split" && scenario != "capacity" && !strings.HasPrefix(scenario, "expect-")
	ids := map[string]bool{}
	for _, record := range records {
		require.Equal(t, 1, record.Protocol)
		switch {
		case owned != "" || scenario == "empty-owned":
			wantHeaders := []string{owned}
			if scenario == "duplicate-owned" {
				wantHeaders = append(wantHeaders, owned)
			}
			require.Equal(t, wantHeaders, record.Headers)
		case injected:
			require.Len(t, record.Headers, 1)
			require.Regexp(t, `^00-`+traceID+`-[0-9a-f]{16}-01$`, record.Headers[0])
			spanID := strings.Split(record.Headers[0], "-")[2]
			require.False(t, ids[spanID], "every execution/attempt needs a fresh client identity")
			ids[spanID] = true
		default:
			require.Empty(t, record.Headers)
		}
	}
	if strings.HasPrefix(scenario, "expect-") || scenario == "oversized" || scenario == "split" {
		return
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		source, err := apacheHTTPClientTrace("java-apache-httpclient", "POST /call/"+id)
		require.NoError(ct, err)
		servers := source.FindByOperationNameServiceAndKind("POST /call/"+id, "java-apache-httpclient", "server")
		require.Len(ct, servers, 1)
		require.Equal(ct, traceID, source.TraceID)
		require.Contains(ct, servers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: traceID[16:]})
		for i, record := range records {
			method := "POST"
			if scenario == "retry" || scenario == "auth" || scenario == "redirect" || strings.HasSuffix(paths[i], "-nested") {
				method = "GET"
			}
			if owned != "" || scenario == "empty-owned" {
				clientTrace, err := apacheHTTPClientTrace("java-apache-httpclient", method+" /"+paths[i])
				require.NoError(ct, err)
				clients := clientTrace.FindByOperationNameServiceAndKind(method+" /"+paths[i], "java-apache-httpclient", "client")
				require.NotEmpty(ct, clients)
				for _, span := range clients {
					if owned != "" && scenario != "invalid-owned" {
						require.NotEqual(ct, strings.Split(owned, "-")[2], span.SpanID)
					}
					for _, parent := range span.References {
						require.NotEqual(ct, span.SpanID, parent.SpanID, "client cannot parent itself")
					}
				}
				continue
			}
			clients := source.FindByOperationNameServiceAndKind(method+" /"+paths[i], "java-apache-httpclient", "client")
			require.NotEmpty(ct, clients)
			if !injected {
				continue
			}
			clientID := strings.Split(record.Headers[0], "-")[2]
			matched := false
			for _, span := range clients {
				if span.SpanID == clientID {
					require.False(ct, matched, "duplicate client export")
					matched = true
					require.True(ct, javaSpanDescendsFrom(source, span, servers[0].SpanID), "client ancestry must reach its source server")
				}
			}
			require.True(ct, matched, "header client identity must be exported")
			if (scenario == "retry" || scenario == "auth") && i == 0 || scenario == "redirect" && i == 0 {
				continue
			}
			downstream, err := apacheHTTPClientTrace("apache-downstream", method+" /"+paths[i])
			require.NoError(ct, err)
			require.Equal(ct, traceID, downstream.TraceID)
			children := downstream.FindByOperationNameServiceAndKind(method+" /"+paths[i], "apache-downstream", "server")
			found := false
			for _, child := range children {
				for _, parent := range child.References {
					found = found || parent == (jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: clientID})
				}
			}
			require.True(ct, found, "downstream server must parent to the transmitted client identity")
		}
	}, time.Minute, time.Second)
	if scenario == "body-like" && injected {
		unexpected, err := apacheHTTPClientTrace("java-apache-httpclient", "GET /__body_probe__")
		require.NoError(t, err)
		require.Empty(t, unexpected.TraceID, "a later body write must not be exported as another request")
	}
}
