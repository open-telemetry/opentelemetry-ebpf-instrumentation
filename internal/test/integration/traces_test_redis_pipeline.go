// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// A redis pipeline puts several commands in one socket write, so OBI parses them
// all out of a single event. Each command must still reach Jaeger as its own
// span, and because the pipeline runs while a request is being served they all
// belong to that request's trace, as siblings of each other.
func testTracesRedisPipeline(t *testing.T) {
	const pipelinedCommands = 4

	waitForTestComponentsSub(t, "http://localhost:8381", "/redis-pipeline")

	for range 3 {
		ti.DoHTTPGet(t, "http://localhost:8381/redis-pipeline", 200)
	}

	var commands []jaeger.Span
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=python3.14&operation=GET%20%2Fredis-pipeline")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/redis-pipeline"})
		require.NotEmpty(ct, traces)

		trace = traces[0]
		commands = pipelinedRedisCommands(trace)
		require.Len(ct, commands, pipelinedCommands)
	}, testTimeout, 100*time.Millisecond)

	server := trace.FindByOperationName("GET /redis-pipeline", "server")
	require.Len(t, server, 1)

	spanIDs := map[string]struct{}{}
	parents := map[string]struct{}{}
	for _, cmd := range commands {
		assert.Equal(t, server[0].TraceID, cmd.TraceID,
			"a pipelined command issued while serving a request belongs to that request's trace")

		require.NotEmpty(t, cmd.SpanID)
		require.NotContains(t, spanIDs, cmd.SpanID,
			"every command parsed out of the batch needs its own span id")
		spanIDs[cmd.SpanID] = struct{}{}

		parent, ok := trace.ParentOf(&cmd)
		require.True(t, ok, "a command issued while serving a request must have a parent")
		parents[parent.SpanID] = struct{}{}
	}
	assert.Len(t, parents, 1, "the whole batch hangs off the request that issued it")
}

// The background loop pipelines its commands with no request behind them, so
// none of them has a parent. Spans without a parent are roots, and a trace has
// room for exactly one, so each command has to arrive in a trace of its own
// rather than sharing the one trace id of the event they were parsed from.
func testTracesRedisPipelineNoParent(t *testing.T) {
	const wantTraces = 4

	var traces []jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=python3.14&operation=SADD")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.GreaterOrEqual(ct, len(tq.Data), wantTraces)
		traces = tq.Data
	}, testTimeout, 100*time.Millisecond)

	for _, trace := range traces {
		commands := backgroundRedisCommands(trace)
		require.Len(t, commands, 1,
			"a parentless command must not share a trace with the rest of its batch")

		_, hasParent := trace.ParentOf(&commands[0])
		assert.False(t, hasParent,
			"a command with no request behind it is the root of its own trace")
	}
}

// pipelinedRedisCommands returns the redis client spans for the commands the
// /redis-pipeline endpoint batches, ignoring the CLIENT SETINFO handshake the
// driver sends when it first connects.
func pipelinedRedisCommands(trace jaeger.Trace) []jaeger.Span {
	var commands []jaeger.Span
	for _, span := range trace.Spans {
		if span.OperationName != "SET" && span.OperationName != "GET" {
			continue
		}
		if system, ok := jaeger.FindIn(span.Tags, "db.system.name"); !ok || system.Value != "redis" {
			continue
		}
		commands = append(commands, span)
	}

	return commands
}

// backgroundRedisCommands returns the redis client spans for the commands the
// background loop batches.
func backgroundRedisCommands(trace jaeger.Trace) []jaeger.Span {
	var commands []jaeger.Span
	for _, span := range trace.Spans {
		if span.OperationName != "SADD" && span.OperationName != "SMEMBERS" {
			continue
		}
		commands = append(commands, span)
	}

	return commands
}
