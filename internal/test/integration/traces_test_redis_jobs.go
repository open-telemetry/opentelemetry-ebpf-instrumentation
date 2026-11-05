// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

const redisJobsAddr = "localhost:16379"

// pushRedisJob puts a job on a queue the test server's workers take jobs from
func pushRedisJob(t *testing.T, kind, job string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", redisJobsAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	queue := "obi-jobs-" + kind
	_, err = fmt.Fprintf(conn, "*3\r\n$5\r\nLPUSH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(queue), queue, len(job), job)
	require.NoError(t, err)

	reply, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, byte(':'), reply[0], "LPUSH replies with the list length: %q", reply)
}

// redisJobTrace returns the trace holding the job's first command, and that command
func redisJobTrace(t *testing.T, job string) (jaeger.Trace, jaeger.Span) {
	t.Helper()

	running := jaeger.Tag{Key: "db.query.text", Type: "string", Value: "SET obi-job:" + job + " running"}
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?service=main&operation=SET&limit=1000")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(running)
		require.Len(ct, traces, 1)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	for _, span := range trace.Spans {
		if len(span.Diff(running)) == 0 {
			return trace, span
		}
	}
	require.FailNow(t, "the trace found by the job's command lacks it")
	return trace, jaeger.Span{}
}

// A job's commands hang off the fetch that took it, and the fetch has nothing above it
func requireJobUnderFetch(t *testing.T, job string) {
	t.Helper()

	trace, running := redisJobTrace(t, job)
	fetch, ok := trace.ParentOf(&running)
	require.True(t, ok, "job %s: its commands have a parent", job)
	require.Equal(t, "BLPOP", fetch.OperationName, "job %s: the fetch that took the job is the parent", job)
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
	assert.Len(t, trace.FindByOperationName("BLPOP", "client"), 1, "job %s: one job per trace", job)
}

func testTracesRedisJobsInline(t *testing.T) {
	for _, job := range []string{"inline-1", "inline-2"} {
		pushRedisJob(t, "inline", job)
		requireJobUnderFetch(t, job)
	}
}

func testTracesRedisJobsThreadPerJob(t *testing.T) {
	for _, job := range []string{"thread-1", "thread-2"} {
		pushRedisJob(t, "thread", job)
		requireJobUnderFetch(t, job)
	}
}

// The pool's thread starts during the first job, so it runs that job, but it
// must not carry the first job into the next one it is handed
func testTracesRedisJobsPool(t *testing.T) {
	pushRedisJob(t, "pool", "pool-1")
	requireJobUnderFetch(t, "pool-1")

	pushRedisJob(t, "pool", "pool-2")
	trace, running := redisJobTrace(t, "pool-2")
	_, ok := trace.ParentOf(&running)
	assert.False(t, ok, "a reused thread doesn't know which job it runs")
	assert.Empty(t, trace.FindByOperationName("BLPOP", "client"), "pool-2 is not in a fetch's trace")
}
