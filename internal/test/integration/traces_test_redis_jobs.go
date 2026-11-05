// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const redisJobsAddr = "localhost:16379"

// redisCommand sends one command to the Redis server the test server's workers fetch jobs from
func redisCommand(t *testing.T, args ...string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", redisJobsAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	var cmd strings.Builder
	fmt.Fprintf(&cmd, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&cmd, "$%d\r\n%s\r\n", len(arg), arg)
	}
	_, err = conn.Write([]byte(cmd.String()))
	require.NoError(t, err)

	reply, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	require.NotEqual(t, byte('-'), reply[0], "%s: %q", args[0], reply)
}

func pushRedisJob(t *testing.T, kind, job string) {
	redisCommand(t, "LPUSH", "obi-jobs-"+kind, job)
}

// redisTraces returns the traces holding an op command whose text is exactly text
func redisTraces(ct *assert.CollectT, op, text string) []jaeger.Trace {
	resp, err := getJaeger(jaegerQueryURL + "?service=main&operation=" + op + "&limit=1000")
	require.NoError(ct, err)
	require.NotNil(ct, resp)
	require.Equal(ct, http.StatusOK, resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

	return tq.FindBySpan(jaeger.Tag{Key: "db.query.text", Type: "string", Value: text})
}

func spanWithText(trace *jaeger.Trace, text string) (jaeger.Span, bool) {
	want := jaeger.Tag{Key: "db.query.text", Type: "string", Value: text}
	for _, span := range trace.Spans {
		if len(span.Diff(want)) == 0 {
			return span, true
		}
	}
	return jaeger.Span{}, false
}

// redisJobTrace returns the trace holding the job's first command, and that command
func redisJobTrace(t *testing.T, job string) (jaeger.Trace, jaeger.Span) {
	t.Helper()

	running := "SET obi-job:" + job + " running"
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		traces := redisTraces(ct, "SET", running)
		require.Len(ct, traces, 1)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	span, ok := spanWithText(&trace, running)
	require.True(t, ok, "the trace found by the job's command holds it")
	return trace, span
}

// A job's commands hang off the fetch that took it, and the fetch has nothing above it
func requireJobUnderFetch(t *testing.T, job, fetchOp string) {
	t.Helper()

	trace, running := redisJobTrace(t, job)
	fetch, ok := trace.ParentOf(&running)
	require.True(t, ok, "job %s: its commands have a parent", job)
	require.Equal(t, fetchOp, fetch.OperationName, "job %s: the fetch that took the job is the parent", job)
	_, ok = trace.ParentOf(&fetch)
	require.False(t, ok, "job %s: the fetch starts the trace", job)

	for _, op := range []string{"SET", "GET"} {
		commands := trace.FindByOperationName(op, "client")
		require.NotEmpty(t, commands, "job %s: %s in the job's trace", job, op)
		for _, cmd := range commands {
			parent, ok := trace.ParentOf(&cmd)
			require.True(t, ok)
			assert.Equal(t, fetch.SpanID, parent.SpanID, "job %s: %s hangs off the fetch", job, op)
		}
	}
	assert.Len(t, trace.FindByOperationName(fetchOp, "client"), 1, "job %s: one job per trace", job)
}

// A job no fetch can parent: its first command starts a trace of its own
func requireJobWithoutFetch(t *testing.T, job string) {
	t.Helper()

	trace, running := redisJobTrace(t, job)
	_, ok := trace.ParentOf(&running)
	assert.False(t, ok, "job %s: its commands have no parent", job)
	assert.Empty(t, trace.FindByOperationName("BLPOP", "client"), "job %s: not in a fetch's trace", job)
}

func testTracesRedisJobsInline(t *testing.T) {
	for _, job := range []string{"inline-1", "inline-2"} {
		pushRedisJob(t, "inline", job)
		requireJobUnderFetch(t, job, "BLPOP")
	}
}

func testTracesRedisJobsThreadPerJob(t *testing.T) {
	for _, job := range []string{"thread-1", "thread-2"} {
		pushRedisJob(t, "thread", job)
		requireJobUnderFetch(t, job, "BLPOP")
	}
}

func testTracesRedisJobsProcessPerJob(t *testing.T) {
	for _, job := range []string{"process-1", "process-2"} {
		pushRedisJob(t, "process", job)
		requireJobUnderFetch(t, job, "BLPOP")
	}
}

// The pool's thread starts during the first job, so it runs that job, but it
// must not carry the first job into the next one it is handed
func testTracesRedisJobsPool(t *testing.T) {
	pushRedisJob(t, "pool", "pool-1")
	requireJobUnderFetch(t, "pool-1", "BLPOP")

	pushRedisJob(t, "pool", "pool-2")
	requireJobWithoutFetch(t, "pool-2")
}

func testTracesRedisJobsPolled(t *testing.T) {
	for _, job := range []string{"poll-1", "poll-2"} {
		pushRedisJob(t, "poll", job)
		requireJobUnderFetch(t, job, "LPOP")
	}
}

func testTracesRedisJobsStream(t *testing.T) {
	for _, job := range []string{"stream-1", "stream-2"} {
		redisCommand(t, "XADD", "obi-jobs-stream", "*", "job", job)
		requireJobUnderFetch(t, job, "XREADGROUP")
	}
}

// A fetch that times out takes no job, so the call after it has no parent
func testTracesRedisEmptyFetch(t *testing.T) {
	// earlier subtests serve requests on the thread that started the idle worker
	since := time.Now().UnixMicro()

	var incrs []jaeger.Span
	var traces []jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		incrs, traces = nil, nil
		// redis-py sends INCR as INCRBY
		for _, trace := range redisTraces(ct, "INCRBY", "INCRBY obi-idle 1") {
			incr, ok := spanWithText(&trace, "INCRBY obi-idle 1")
			require.True(ct, ok)
			if incr.StartTime >= since {
				incrs = append(incrs, incr)
				traces = append(traces, trace)
			}
		}
		require.GreaterOrEqual(ct, len(incrs), 3)
	}, testTimeout, 100*time.Millisecond)

	for i, trace := range traces {
		incr := incrs[i]
		_, ok := trace.ParentOf(&incr)
		assert.False(t, ok, "an empty fetch starts no job")
		assert.Empty(t, trace.FindByOperationName("BLPOP", "client"))
	}
}

// A thread that serves another connection while its fetch is pending can't
// tell which job its later calls belong to
func testTracesRedisJobsBusyThread(t *testing.T) {
	pushRedisJob(t, "busy", "busy-1")
	requireJobWithoutFetch(t, "busy-1")
}

// A fetch that takes a job while a request is served is one of the request's
// calls, and so is what follows it
func testTracesRedisFetchInRequest(t *testing.T) {
	waitForTestComponentsSub(t, "http://localhost:8381", "/redis-job-in-request")
	ti.DoHTTPGet(t, "http://localhost:8381/redis-job-in-request", 200)

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?service=main&operation=GET%20%2Fredis-job-in-request&limit=100")
		require.NoError(ct, err)
		require.NotNil(ct, resp)
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/redis-job-in-request"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
		_, ok := spanWithText(&trace, "SET obi-job:request-job running")
		require.True(ct, ok)
	}, testTimeout, 100*time.Millisecond)

	server := trace.FindByOperationName("GET /redis-job-in-request", "server")
	require.Len(t, server, 1)
	for _, text := range []string{"LPOP obi-jobs-request", "SET obi-job:request-job running"} {
		span, ok := spanWithText(&trace, text)
		require.True(t, ok, text)

		// the request's spans sit between it and its calls
		for parent, ok := trace.ParentOf(&span); ok; parent, ok = trace.ParentOf(&parent) {
			require.NotEqual(t, "LPOP", parent.OperationName, "%s is not under the fetch", text)
			span = parent
		}
		assert.Equal(t, server[0].SpanID, span.SpanID, "%s is under the request", text)
	}
}
