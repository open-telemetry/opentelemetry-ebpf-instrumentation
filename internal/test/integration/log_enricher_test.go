// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

type testServerConstants struct {
	url            string
	smokeEndpoint  string
	logEndpoint    string
	containerImage string
	message        string
}

var (
	logEnricherHTTPConstants = testServerConstants{
		url:            "http://localhost:8381",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/json_logger",
		containerImage: "hatest-testserver-logenricher-http",
		message:        "this is a json log",
	}
	logEnricherGoGRPCConstants = testServerConstants{
		url:            "http://localhost:8382",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/log",
		containerImage: "hatest-testserver-logenricher-grpc-go",
		message:        "hello!",
	}
	logEnricherNodeJSConstants = testServerConstants{
		url:            "http://localhost:8383",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/json_logger",
		containerImage: "hatest-testserver-node",
		message:        "this is a json log from node",
	}
	logEnricherJavaConstants = testServerConstants{
		url:            "http://localhost:8384",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/json_logger",
		containerImage: "hatest-testserver-logenricher-java",
		message:        "this is a json log from java",
	}
	logEnricherRubyWritevConstants = testServerConstants{
		url:            "http://localhost:8385",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/json_logger",
		containerImage: "hatest-testserver-logenricher-ruby",
		message:        "this is a json log from ruby",
	}
	logEnricherRubyWriteConstants = testServerConstants{
		url:            "http://localhost:8385",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/json_logger_write",
		containerImage: "hatest-testserver-logenricher-ruby",
		message:        "this is a json log from ruby via write",
	}
)

// logEnricherTestTraceparents are fixed W3C traceparents used by log enricher tests.
// Fixed IDs allow exact equality assertions on trace_id and ordering assertions
// on the enriched container logs.
var logEnricherTestTraceparents = [5]struct{ traceID, parentID string }{
	{"4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"},
	{"7b5c1e7d8f2a4b6c9e0d3f1a2b4c5d6e", "1a2b3c4d5e6f7a8b"},
	{"a1b2c3d4e5f60718293a4b5c6d7e8f90", "fedcba9876543210"},
	{"0102030405060708090a0b0c0d0e0f10", "0102030405060708"},
	{"deadbeefcafebabe0123456789abcdef", "cafebabe01234567"},
}

func containerLogs(t require.TestingT, cl *client.Client, containerID string) []string {
	reader, err := cl.ContainerLogs(context.TODO(), containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	require.NoError(t, err)
	defer reader.Close()

	var stdout, stderr strings.Builder
	_, err = stdcopy.StdCopy(&stdout, &stderr, reader)
	require.NoError(t, err)

	combined := stdout.String() + stderr.String()

	scanner := bufio.NewScanner(strings.NewReader(combined))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	require.NoError(t, scanner.Err())

	return lines
}

func testContainerID(t require.TestingT, cl *client.Client, image string) string {
	containers, err := cl.ContainerList(context.TODO(), container.ListOptions{All: true})
	require.NoError(t, err)

	for _, c := range containers {
		if c.Image == image {
			return c.ID
		}
	}

	return ""
}

// testLogEnricherNodeJS sends N concurrent requests, each carrying a distinct
// W3C traceparent, and verifies that every injected trace_id appears in an
// enriched container log line. The server introduces a random async delay so
// that multiple libuv I/O callbacks are in-flight simultaneously, exercising
// the traces_ctx_v1 context-switch fix in the async_hooks before hook.
func testLogEnricherNodeJS(t *testing.T) {
	waitForTestComponentsNoMetrics(t, logEnricherNodeJSConstants.url+logEnricherNodeJSConstants.smokeEndpoint)

	cl, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Fire one request per traceparent concurrently so all libuv callbacks
		// are in-flight simultaneously. Goroutines are staggered by 5 ms so that
		// requests arrive at the server in array order (server delay is 35 ms,
		// much larger than the stagger), giving a deterministic log order.
		var wg sync.WaitGroup
		for i, tp := range logEnricherTestTraceparents {
			wg.Add(1)
			go func(tp struct{ traceID, parentID string }) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodGet,
					logEnricherNodeJSConstants.url+logEnricherNodeJSConstants.logEndpoint, nil)
				if err != nil {
					return
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", tp.traceID, tp.parentID))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				resp.Body.Close()
			}(tp)
			// Small stagger between goroutine starts so HTTP requests reach the
			// server in the same order they are launched.
			if i < len(logEnricherTestTraceparents)-1 {
				time.Sleep(5 * time.Millisecond)
			}
		}
		wg.Wait()

		containerID := testContainerID(ct, cl, logEnricherNodeJSConstants.containerImage)
		require.NotEmpty(ct, containerID, "could not find test container ID")
		logs := containerLogs(ct, cl, containerID)
		require.NotEmpty(ct, logs)

		// Find the last log-position of each injected trace_id (most recent retry).
		lastPos := make(map[string]int, len(logEnricherTestTraceparents))
		lastSpanID := make(map[string]string, len(logEnricherTestTraceparents))
		for i, line := range logs {
			var fields map[string]string
			if json.Unmarshal([]byte(line), &fields) != nil {
				continue
			}
			if tid, ok := fields["trace_id"]; ok {
				lastPos[tid] = i
				lastSpanID[tid] = fields["span_id"]
			}
		}

		// Every injected trace_id must appear with a non-empty span_id.
		for _, tp := range logEnricherTestTraceparents {
			_, found := lastPos[tp.traceID]
			assert.True(ct, found, "no enriched log line found for trace_id %s", tp.traceID)
			if found {
				assert.NotEmpty(ct, lastSpanID[tp.traceID], "span_id missing for trace_id %s", tp.traceID)
			}
		}

		// Log lines must appear in the same order requests were made.
		// Using last-occurrence positions compares within the most recent batch.
		for i := 0; i < len(logEnricherTestTraceparents)-1; i++ {
			a, b := logEnricherTestTraceparents[i], logEnricherTestTraceparents[i+1]
			posA, okA := lastPos[a.traceID]
			posB, okB := lastPos[b.traceID]
			if okA && okB {
				assert.Less(ct, posA, posB,
					"trace_id %s should appear before %s in logs (request order)",
					a.traceID, b.traceID)
			}
		}
	}, testTimeout, 500*time.Millisecond)
}

// testLogEnricherJava sends concurrent requests with distinct traceparent
// headers and verifies each enriched log line contains the exact trace_id from
// the request. This catches stale/wrong context that a simple existence check
// would miss.
func testLogEnricherJava(t *testing.T) {
	waitForTestComponentsNoMetrics(t, logEnricherJavaConstants.url+logEnricherJavaConstants.smokeEndpoint)

	cl, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var wg sync.WaitGroup
		for _, tp := range logEnricherTestTraceparents {
			wg.Add(1)
			go func(tp struct{ traceID, parentID string }) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodGet,
					logEnricherJavaConstants.url+logEnricherJavaConstants.logEndpoint, nil)
				if err != nil {
					return
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", tp.traceID, tp.parentID))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				resp.Body.Close()
			}(tp)
		}
		wg.Wait()

		containerID := testContainerID(ct, cl, logEnricherJavaConstants.containerImage)
		require.NotEmpty(ct, containerID, "could not find test container ID")
		logs := containerLogs(ct, cl, containerID)
		require.NotEmpty(ct, logs)

		// Collect the last occurrence of each injected trace_id.
		lastSpanID := make(map[string]string, len(logEnricherTestTraceparents))
		for _, line := range logs {
			var fields map[string]string
			if json.Unmarshal([]byte(line), &fields) != nil {
				continue
			}
			if tid, ok := fields["trace_id"]; ok {
				lastSpanID[tid] = fields["span_id"]
			}
		}

		// Every injected trace_id must appear with a non-empty span_id.
		for _, tp := range logEnricherTestTraceparents {
			spanID, found := lastSpanID[tp.traceID]
			assert.True(ct, found, "no enriched log line found for trace_id %s", tp.traceID)
			if found {
				assert.NotEmpty(ct, spanID, "span_id missing for trace_id %s", tp.traceID)
			}
		}
	}, testTimeout, 500*time.Millisecond)
}

// testLogEnricherRuby sends concurrent requests with distinct traceparent
// headers and verifies each enriched log line contains the exact trace_id from
// the request. Requests exceed Puma's thread pool size (2 threads), forcing the
// reactor thread to buffer HTTP requests before handing them to workers. This
// exercises the obi_ctx__set call in rb_ary_shift that refreshes traces_ctx_v1
// for the worker thread when the reactor already parsed the HTTP request.
func testLogEnricherRuby(t *testing.T, constants testServerConstants) {
	waitForTestComponentsNoMetrics(t, constants.url+constants.smokeEndpoint)

	cl, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Fire one request per traceparent concurrently against 2 Puma threads.
		// The server sleeps 50ms per request, so at least 3 requests will be
		// queued in the reactor, exercising the reactor→worker handoff path.
		var wg sync.WaitGroup
		for _, tp := range logEnricherTestTraceparents {
			wg.Add(1)
			go func(tp struct{ traceID, parentID string }) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodGet,
					constants.url+constants.logEndpoint, nil)
				if err != nil {
					return
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", tp.traceID, tp.parentID))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				resp.Body.Close()
			}(tp)
		}
		wg.Wait()

		containerID := testContainerID(ct, cl, constants.containerImage)
		require.NotEmpty(ct, containerID, "could not find test container ID")
		logs := containerLogs(ct, cl, containerID)
		require.NotEmpty(ct, logs)

		// Collect the last occurrence of each injected trace_id
		// from log lines matching this test's expected message.
		lastSpanID := make(map[string]string, len(logEnricherTestTraceparents))
		for _, line := range logs {
			var fields map[string]string
			if json.Unmarshal([]byte(line), &fields) != nil {
				continue
			}
			if fields["message"] != constants.message {
				continue
			}
			if tid, ok := fields["trace_id"]; ok {
				lastSpanID[tid] = fields["span_id"]
			}
		}

		// Every injected trace_id must appear with a non-empty span_id.
		for _, tp := range logEnricherTestTraceparents {
			spanID, found := lastSpanID[tp.traceID]
			assert.True(ct, found, "no enriched log line found for trace_id %s", tp.traceID)
			if found {
				assert.NotEmpty(ct, spanID, "span_id missing for trace_id %s", tp.traceID)
			}
		}
	}, testTimeout, 500*time.Millisecond)
}

func testLogEnricher(t *testing.T, constants testServerConstants) {
	waitForTestComponentsNoMetrics(t, constants.url+constants.smokeEndpoint)

	cl, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, constants.url+constants.logEndpoint, 200)

		containerID := testContainerID(ct, cl, constants.containerImage)
		require.NotEmpty(ct, containerID, "could not find test container ID")
		logs := containerLogs(ct, cl, containerID)
		require.NotEmpty(ct, logs)

		logIdx := -1
		// Loop from the end -- it might be possible that OBI wasn't ready to inject
		// context when the test started, so get the latest request logs every time.
		for i := len(logs) - 1; i >= 0; i-- {
			if strings.Contains(logs[i], "span_id") {
				logIdx = i
				break
			}
		}

		require.GreaterOrEqual(ct, logIdx, 0, "no enriched log line found yet")

		var logFields map[string]string
		require.NoError(ct, json.Unmarshal([]byte(logs[logIdx]), &logFields))

		assert.Equal(ct, constants.message, logFields["message"])
		assert.Equal(ct, "INFO", logFields["level"])
		assert.Contains(ct, logFields, "trace_id")
		assert.Contains(ct, logFields, "span_id")
	}, 2*testTimeout, time.Second)
}
