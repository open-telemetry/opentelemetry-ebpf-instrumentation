// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
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
	logEnricherGoWritevRegressionConstants = testServerConstants{
		url:            "http://localhost:8382",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/log_writev_regression",
		containerImage: "hatest-testserver-logenricher-grpc-go",
		message:        "go writev regression log",
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
	logEnricherDotNetConstants = testServerConstants{
		url:            "http://localhost:8386",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/json_logger",
		containerImage: "hatest-testserver-logenricher-dotnet",
		message:        "this is a json log from dotnet",
	}
	logEnricherPythonAsyncConstants = testServerConstants{
		url:            "http://localhost:8387",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/json_logger",
		containerImage: "hatest-testserver-logenricher-pythonasync",
		message:        "this is a json log from python async",
	}
	logEnricherMultiSegWritevConstants = testServerConstants{
		url:            "http://localhost:8388",
		smokeEndpoint:  "/smoke",
		logEndpoint:    "/json_logger",
		containerImage: "hatest-testserver-logenricher-multiseg-writev",
		message:        "this is a json log via multi-seg writev",
	}
)

const logEnricherGoWritevRegressionLeakMarker = "writev-leak-marker-should-never-appear"

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

func containerLogs(t assert.TestingT, cl *client.Client, containerID string) []string {
	reader, err := cl.ContainerLogs(context.TODO(), containerID, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		assert.NoError(t, err)
		return nil
	}
	defer reader.Close()

	var stdout, stderr strings.Builder
	_, err = stdcopy.StdCopy(&stdout, &stderr, reader)
	if err != nil {
		assert.NoError(t, err)
		return nil
	}

	combined := stdout.String() + stderr.String()

	scanner := bufio.NewScanner(strings.NewReader(combined))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		assert.NoError(t, err)
	}

	return lines
}

func testContainerID(t assert.TestingT, cl *client.Client, image string) string {
	result, err := cl.ContainerList(context.TODO(), client.ContainerListOptions{All: true})
	if err != nil {
		assert.NoError(t, err)
		return ""
	}

	for _, c := range result.Items {
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

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Fire one request per traceparent concurrently so all libuv callbacks
		// are in-flight simultaneously. Goroutines are staggered by 5 ms so that
		// requests arrive at the server in array order (server delay is 35 ms,
		// much larger than the stagger), giving a deterministic log order.
		errCh := make(chan error, len(logEnricherTestTraceparents))
		var wg sync.WaitGroup
		for i, tp := range logEnricherTestTraceparents {
			wg.Add(1)
			go func(tp struct{ traceID, parentID string }) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodGet,
					logEnricherNodeJSConstants.url+logEnricherNodeJSConstants.logEndpoint, nil)
				if err != nil {
					errCh <- err
					return
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", tp.traceID, tp.parentID))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					errCh <- err
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
		close(errCh)
		for err := range errCh {
			assert.NoError(ct, err, "HTTP request failed")
		}

		containerID := testContainerID(ct, cl, logEnricherNodeJSConstants.containerImage)
		if !assert.NotEmpty(ct, containerID, "could not find test container ID") {
			return
		}
		logs := containerLogs(ct, cl, containerID)
		if !assert.NotEmpty(ct, logs) {
			return
		}

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

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		errCh := make(chan error, len(logEnricherTestTraceparents))
		var wg sync.WaitGroup
		for _, tp := range logEnricherTestTraceparents {
			wg.Add(1)
			go func(tp struct{ traceID, parentID string }) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodGet,
					logEnricherJavaConstants.url+logEnricherJavaConstants.logEndpoint, nil)
				if err != nil {
					errCh <- err
					return
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", tp.traceID, tp.parentID))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					errCh <- err
					return
				}
				resp.Body.Close()
			}(tp)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			assert.NoError(ct, err, "HTTP request failed")
		}

		containerID := testContainerID(ct, cl, logEnricherJavaConstants.containerImage)
		if !assert.NotEmpty(ct, containerID, "could not find test container ID") {
			return
		}
		logs := containerLogs(ct, cl, containerID)
		if !assert.NotEmpty(ct, logs) {
			return
		}

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

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Fire one request per traceparent concurrently against 2 Puma threads.
		// The server sleeps 50ms per request, so at least 3 requests will be
		// queued in the reactor, exercising the reactor→worker handoff path.
		errCh := make(chan error, len(logEnricherTestTraceparents))
		var wg sync.WaitGroup
		for _, tp := range logEnricherTestTraceparents {
			wg.Add(1)
			go func(tp struct{ traceID, parentID string }) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodGet,
					constants.url+constants.logEndpoint, nil)
				if err != nil {
					errCh <- err
					return
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", tp.traceID, tp.parentID))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					errCh <- err
					return
				}
				resp.Body.Close()
			}(tp)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			assert.NoError(ct, err, "HTTP request failed")
		}

		containerID := testContainerID(ct, cl, constants.containerImage)
		if !assert.NotEmpty(ct, containerID, "could not find test container ID") {
			return
		}
		logs := containerLogs(ct, cl, containerID)
		if !assert.NotEmpty(ct, logs) {
			return
		}

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

// pythonAsyncLogEnricherVariants enumerates the asyncio scenarios exercised
// by the testserver. Each variant emits a distinct message so concurrent
// requests across variants don't cross-contaminate the assertions
var pythonAsyncLogEnricherVariants = []struct {
	name        string
	logEndpoint string
	message     string
}{
	{
		name:        "interleaved (sleep)",
		logEndpoint: "/json_logger",
		message:     "this is a json log from python async",
	},
	{
		name:        "asyncio.to_thread worker",
		logEndpoint: "/json_logger_to_thread",
		message:     "this is a json log from python async to_thread",
	},
	{
		name:        "nested create_task",
		logEndpoint: "/json_logger_nested",
		message:     "this is a json log from python async nested",
	},
	{
		name:        "asyncio.gather siblings",
		logEndpoint: "/json_logger_gather",
		message:     "this is a json log from python async gather",
	},
}

// testLogEnricherPythonAsync exercises the asyncio task-switch refresh of
// traces_ctx_v1 by interleaving concurrent requests on a single uvicorn/uvloop
// event-loop thread, across the variants above.
func testLogEnricherPythonAsync(t *testing.T) {
	waitForTestComponentsNoMetrics(t, logEnricherPythonAsyncConstants.url+logEnricherPythonAsyncConstants.smokeEndpoint)

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	defer cl.Close()

	for _, v := range pythonAsyncLogEnricherVariants {
		t.Run(v.name, func(t *testing.T) {
			testLogEnricherPythonAsyncEndpoint(t, cl, v.logEndpoint, v.message)
		})
	}
}

func testLogEnricherPythonAsyncEndpoint(t *testing.T, cl *client.Client, logEndpoint, message string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		errCh := make(chan error, len(logEnricherTestTraceparents))
		var wg sync.WaitGroup
		for _, tp := range logEnricherTestTraceparents {
			wg.Add(1)
			go func(tp struct{ traceID, parentID string }) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodGet,
					logEnricherPythonAsyncConstants.url+logEndpoint, nil)
				if err != nil {
					errCh <- err
					return
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", tp.traceID, tp.parentID))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					errCh <- err
					return
				}
				resp.Body.Close()
			}(tp)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			assert.NoError(ct, err, "HTTP request failed")
		}

		containerID := testContainerID(ct, cl, logEnricherPythonAsyncConstants.containerImage)
		if !assert.NotEmpty(ct, containerID, "could not find test container ID") {
			return
		}
		logs := containerLogs(ct, cl, containerID)
		if !assert.NotEmpty(ct, logs) {
			return
		}

		lastSpanID := make(map[string]string, len(logEnricherTestTraceparents))
		for _, line := range logs {
			var fields map[string]string
			if json.Unmarshal([]byte(line), &fields) != nil {
				continue
			}
			if fields["message"] != message {
				continue
			}
			if tid, ok := fields["trace_id"]; ok {
				lastSpanID[tid] = fields["span_id"]
			}
		}

		for _, tp := range logEnricherTestTraceparents {
			spanID, found := lastSpanID[tp.traceID]
			assert.True(ct, found, "no enriched log line found for trace_id %s", tp.traceID)
			if found {
				assert.NotEmpty(ct, spanID, "span_id missing for trace_id %s", tp.traceID)
			}
		}
	}, testTimeout, 500*time.Millisecond)
}

// testLogEnricherPythonAsyncOTelInstrumented exercises the trace_id-only
// behavior for services OBI detects as exporting OTel traces directly. The
// server endpoint makes an outgoing POST to /v1/traces (a "fake" OTLP HTTP
// endpoint on the backend) before logging, which triggers PIDsFilter's
// checkIfExportsOTel via the resulting EventTypeHTTPClient span. After
// detection fires, subsequent log lines from the same service must carry
// trace_id but no span_id.
func testLogEnricherPythonAsyncOTelInstrumented(t *testing.T) {
	waitForTestComponentsNoMetrics(t, logEnricherPythonAsyncConstants.url+logEnricherPythonAsyncConstants.smokeEndpoint)

	cl, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cl.Close()

	const expectedMessage = "this is a json log from python async otel exporter"

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		errCh := make(chan error, len(logEnricherTestTraceparents))
		var wg sync.WaitGroup
		for _, tp := range logEnricherTestTraceparents {
			wg.Add(1)
			go func(tp struct{ traceID, parentID string }) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodGet,
					logEnricherPythonAsyncConstants.url+"/json_logger_otel_exporter", nil)
				if err != nil {
					errCh <- err
					return
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", tp.traceID, tp.parentID))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					errCh <- err
					return
				}
				resp.Body.Close()
			}(tp)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			assert.NoError(ct, err, "HTTP request failed")
		}

		containerID := testContainerID(ct, cl, logEnricherPythonAsyncConstants.containerImage)
		if !assert.NotEmpty(ct, containerID, "could not find test container ID") {
			return
		}
		logs := containerLogs(ct, cl, containerID)
		if !assert.NotEmpty(ct, logs) {
			return
		}

		// For each trace_id, track whether the latest matching log line carried
		// a span_id. Once OBI detects the service as OTel-exporting, every
		// subsequent log line for that service drops span_id.
		lastHasSpanID := make(map[string]bool, len(logEnricherTestTraceparents))
		seen := make(map[string]bool, len(logEnricherTestTraceparents))
		for _, line := range logs {
			var fields map[string]any
			if json.Unmarshal([]byte(line), &fields) != nil {
				continue
			}
			if fields["message"] != expectedMessage {
				continue
			}
			tid, ok := fields["trace_id"].(string)
			if !ok {
				continue
			}
			seen[tid] = true
			_, hasSpan := fields["span_id"]
			lastHasSpanID[tid] = hasSpan
		}

		for _, tp := range logEnricherTestTraceparents {
			assert.True(ct, seen[tp.traceID],
				"expected an enriched log line for trace_id %s", tp.traceID)
			assert.False(ct, lastHasSpanID[tp.traceID],
				"latest log line for trace_id %s should not carry span_id once OBI flags the service as OTel-exporting",
				tp.traceID)
		}
	}, 2*testTimeout, time.Second)
}

// testLogEnricherDotNet sends concurrent requests with distinct traceparent
// headers and verifies each enriched log line contains the correct trace_id.
// ASP.NET Core (Kestrel) dispatches requests on a thread pool, so concurrent
// requests may run on different threads simultaneously — this exercises whether
// the logenricher correctly correlates the TID at write time with the trace
// context established when the HTTP request was received.
func testLogEnricherDotNet(t *testing.T) {
	waitForTestComponentsNoMetrics(t, logEnricherDotNetConstants.url+logEnricherDotNetConstants.smokeEndpoint)

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		errCh := make(chan error, len(logEnricherTestTraceparents))
		var wg sync.WaitGroup
		for _, tp := range logEnricherTestTraceparents {
			wg.Add(1)
			go func(tp struct{ traceID, parentID string }) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodGet,
					logEnricherDotNetConstants.url+logEnricherDotNetConstants.logEndpoint, nil)
				if err != nil {
					errCh <- err
					return
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", tp.traceID, tp.parentID))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					errCh <- err
					return
				}
				resp.Body.Close()
			}(tp)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			assert.NoError(ct, err, "HTTP request failed")
		}

		containerID := testContainerID(ct, cl, logEnricherDotNetConstants.containerImage)
		if !assert.NotEmpty(ct, containerID, "could not find test container ID") {
			return
		}
		logs := containerLogs(ct, cl, containerID)
		if !assert.NotEmpty(ct, logs) {
			return
		}

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

// testLogEnricherMultiSegWritev exercises the multi-segment ITER_IOVEC path.
// The C testserver emits JSON log lines via writev(2) split across 3 iovec
// segments. The BPF logenricher must concatenate all segments to capture the
// full line; userspace then enriches with trace_id/span_id.
func testLogEnricherMultiSegWritev(t *testing.T) {
	waitForTestComponentsNoMetrics(t, logEnricherMultiSegWritevConstants.url+logEnricherMultiSegWritevConstants.smokeEndpoint)

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		errCh := make(chan error, len(logEnricherTestTraceparents))
		var wg sync.WaitGroup
		for _, tp := range logEnricherTestTraceparents {
			wg.Add(1)
			go func(tp struct{ traceID, parentID string }) {
				defer wg.Done()
				req, err := http.NewRequest(http.MethodGet,
					logEnricherMultiSegWritevConstants.url+logEnricherMultiSegWritevConstants.logEndpoint, nil)
				if err != nil {
					errCh <- err
					return
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-01", tp.traceID, tp.parentID))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					errCh <- err
					return
				}
				resp.Body.Close()
			}(tp)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			assert.NoError(ct, err, "HTTP request failed")
		}

		containerID := testContainerID(ct, cl, logEnricherMultiSegWritevConstants.containerImage)
		if !assert.NotEmpty(ct, containerID, "could not find test container ID") {
			return
		}
		logs := containerLogs(ct, cl, containerID)
		if !assert.NotEmpty(ct, logs) {
			return
		}

		lastSpanID := make(map[string]string, len(logEnricherTestTraceparents))
		for _, line := range logs {
			var fields map[string]string
			if json.Unmarshal([]byte(line), &fields) != nil {
				continue
			}
			if fields["message"] != logEnricherMultiSegWritevConstants.message {
				continue
			}
			if tid, ok := fields["trace_id"]; ok {
				lastSpanID[tid] = fields["span_id"]
			}
		}

		for _, tp := range logEnricherTestTraceparents {
			spanID, found := lastSpanID[tp.traceID]
			assert.True(ct, found, "no enriched log line found for trace_id %s", tp.traceID)
			if found {
				assert.NotEmpty(ct, spanID, "span_id missing for trace_id %s", tp.traceID)
			}
		}
	}, testTimeout, 500*time.Millisecond)
}

// testLogEnricherShipperFilters validates the otelcol and fluent-bit filter
// configs documented in devdocs/trace-log-correlation.md actually drop the
// NUL-stuffed empty lines that the BPF logenricher leaves on stdout, while
// passing through the OBI-enriched JSON lines unchanged.
func testLogEnricherShipperFilters(t *testing.T) {
	type shipper struct {
		name     string
		filePath string
	}
	shippers := []shipper{
		{name: "otelcol", filePath: path.Join(pathOutput, "multiseg-shipper-output", "otelcol-filtered.json")},
		{name: "fluent-bit", filePath: path.Join(pathOutput, "multiseg-shipper-output", "fluentbit-filtered.json")},
	}

	for _, sh := range shippers {
		t.Run(sh.name, func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				data, err := os.ReadFile(sh.filePath)
				if !assert.NoError(ct, err) {
					return
				}
				if !assert.NotEmpty(ct, data, "shipper produced no filtered output yet") {
					return
				}

				// No NUL-only lines (the suppression pattern) should survive
				// the documented filter
				nulLine := regexp.MustCompile(`^[\x00\s]*$`)
				scanner := bufio.NewScanner(strings.NewReader(string(data)))
				scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						continue
					}
					assert.False(ct, nulLine.MatchString(line),
						"%s output still contains a NUL/whitespace-only line — filter is incorrect", sh.name)
				}
				assert.NoError(ct, scanner.Err(), "%s output scan failed", sh.name)

				// Every test traceparent should appear at least once as an
				// OBI-injected `"trace_id":"<id>"` field. Both fluent-bit
				// (docker JSON) and otelcol (OTLP attributes[log]) emit the
				// log content as a JSON-encoded string, so the literal
				// substring on disk is `\"trace_id\":\"<id>\"`. This guards
				// against the app's own `traceparent_seen` field satisfying
				// a plain hex-only `Contains(data, hex)` check
				for _, tp := range logEnricherTestTraceparents {
					needle := fmt.Sprintf(`\"trace_id\":\"%s\"`, tp.traceID)
					assert.Contains(ct, string(data), needle,
						"%s output missing enriched line for trace_id %s", sh.name, tp.traceID)
				}
			}, testTimeout, 1*time.Second)

			// Dump the multiseg testserver's `log` field one-per-line, quoted
			// so embedded newlines, NUL bytes and empty entries are visible.
			// fluent-bit emits docker JSON ({"log":"..","stream":..,..}) and
			// otelcol's file exporter emits OTLP JSON whose body.stringValue
			// holds the same docker JSON envelope — parse both shapes.
			// Filter by content to avoid drowning the test log in OBI/Java/
			// Docker chatter from sibling containers
			data, err := os.ReadFile(sh.filePath)
			require.NoError(t, err)
			t.Logf("=== %s app logs from multiseg_writev (%d bytes raw) ===", sh.name, len(data))
			dump := bufio.NewScanner(strings.NewReader(string(data)))
			dump.Buffer(make([]byte, 1024*1024), 1024*1024)
			lineNo := 0
			for dump.Scan() {
				logField := extractShipperLog(dump.Bytes())
				// match only the multiseg testserver's actual stdout/stderr
				// output (not OBI BPFLogger lines that happen to contain
				// `comm=multiseg_writev`)
				if !strings.Contains(logField, logEnricherMultiSegWritevConstants.message) &&
					!strings.HasPrefix(logField, "multiseg_writev listening") {
					continue
				}
				lineNo++
				t.Logf("[%4d] %q", lineNo, logField)
			}
			require.NoError(t, dump.Err(), "%s output dump scan failed", sh.name)
		})
	}
}

// extractShipperLog returns the `log` field from a single shipper output
// record. Handles fluent-bit's docker-shape lines and otelcol's OTLP
// stringValue wrapper. Returns the raw line as a fallback
func extractShipperLog(line []byte) string {
	var docker struct {
		Log string `json:"log"`
	}
	if err := json.Unmarshal(line, &docker); err == nil && docker.Log != "" {
		return docker.Log
	}
	var otlp struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					Body struct {
						StringValue string `json:"stringValue"`
					} `json:"body"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(line, &otlp); err == nil &&
		len(otlp.ResourceLogs) > 0 &&
		len(otlp.ResourceLogs[0].ScopeLogs) > 0 &&
		len(otlp.ResourceLogs[0].ScopeLogs[0].LogRecords) > 0 {
		body := otlp.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Body.StringValue
		// otelcol's body holds the docker JSON envelope as a string —
		// unwrap one more level to surface the actual log line
		if err := json.Unmarshal([]byte(body), &docker); err == nil && docker.Log != "" {
			return docker.Log
		}
		return body
	}
	return string(line)
}

func testLogEnricher(t *testing.T, constants testServerConstants) {
	waitForTestComponentsNoMetrics(t, constants.url+constants.smokeEndpoint)

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, constants.url+constants.logEndpoint, 200)

		containerID := testContainerID(ct, cl, constants.containerImage)
		if !assert.NotEmpty(ct, containerID, "could not find test container ID") {
			return
		}
		logs := containerLogs(ct, cl, containerID)
		if !assert.NotEmpty(ct, logs) {
			return
		}

		logIdx := -1
		// Loop from the end -- it might be possible that OBI wasn't ready to inject
		// context when the test started, so get the latest request logs every time.
		for i := len(logs) - 1; i >= 0; i-- {
			if strings.Contains(logs[i], "span_id") {
				logIdx = i
				break
			}
		}

		if !assert.GreaterOrEqual(ct, logIdx, 0, "no enriched log line found yet") {
			return
		}

		var logFields map[string]string
		assert.NoError(ct, json.Unmarshal([]byte(logs[logIdx]), &logFields))

		assert.Equal(ct, constants.message, logFields["message"])
		assert.Equal(ct, "INFO", logFields["level"])
		assert.Contains(ct, logFields, "trace_id")
		assert.Contains(ct, logFields, "span_id")
	}, 2*testTimeout, time.Second)
}

func testLogEnricherWritevClamp(t *testing.T, constants testServerConstants) {
	waitForTestComponentsNoMetrics(t, constants.url+constants.smokeEndpoint)

	cl, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cl.Close()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, constants.url+constants.logEndpoint, 200)

		containerID := testContainerID(ct, cl, constants.containerImage)
		if !assert.NotEmpty(ct, containerID, "could not find test container ID") {
			return
		}

		logs := containerLogs(ct, cl, containerID)
		if !assert.NotEmpty(ct, logs) {
			return
		}

		foundEnriched := false
		for _, line := range logs {
			assert.NotContains(ct, line, logEnricherGoWritevRegressionLeakMarker)

			var fields map[string]string
			if json.Unmarshal([]byte(line), &fields) != nil {
				continue
			}

			if fields["message"] != constants.message {
				continue
			}

			assert.NotEmpty(ct, fields["trace_id"], "trace_id missing from writev-regression log")
			assert.NotEmpty(ct, fields["span_id"], "span_id missing from writev-regression log")
			foundEnriched = true
		}

		assert.True(ct, foundEnriched, "no enriched writev-regression log line found yet")
	}, 2*testTimeout, time.Second)
}
