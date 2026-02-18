// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testNestedTraces(t *testing.T) {
	var traceID string

	waitForTestComponents(t, "http://localhost:5000")
	waitForTestComponents(t, "http://localhost:5002")
	waitForTestComponents(t, "http://localhost:5003")

	// give enough time for the NodeJS injector to finish
	// TODO: once we implement the instrumentation status query API, replace
	// this with  a proper check to see if the target process has finished
	// being instrumented
	t.Log("checking instrumentation status")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:5000/a", 200)

		resp, err := http.Get(jaegerQueryURL + "?service=service-a&limit=1")
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			return
		}

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		if len(tq.Data) == 0 {
			return
		}
	}, 2*time.Minute, 1*time.Second)
	t.Log("instrumentation ready")

	// Add and check for specific trace ID
	// Run couple of requests to make sure we flush out any transactions that might be
	// stuck because of our tracking of full request times
	for i := 0; i < 10; i++ {
		ti.DoHTTPGet(t, "http://localhost:5000/a", 200)
	}

	// Get the first 5 traces
	var multipleTraces []jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=service-a&operation=GET%20%2Fa")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/a"})
		require.LessOrEqual(ct, 5, len(traces))
		multipleTraces = traces
	}, testTimeout, 500*time.Millisecond)

	checkTrace := func(trace *jaeger.Trace, route string, port int, status int) {
		res := trace.FindByOperationName("GET "+route, "server")
		require.Len(t, res, 1)
		parent := res[0]
		require.NotEmpty(t, parent.TraceID)

		if traceID == "" {
			traceID = parent.TraceID
		} else {
			require.Equal(t, traceID, parent.TraceID)
		}

		require.NotEmpty(t, parent.SpanID)

		// check duration is at least 2us
		assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)

		sd := parent.Diff(
			jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
			jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(status)},
			jaeger.Tag{Key: "url.path", Type: "string", Value: route},
			jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(port)},
			jaeger.Tag{Key: "http.route", Type: "string", Value: route},
			jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
		)
		assert.Empty(t, sd, sd.String())
	}

	// Ensure all 5 traces have proper full chain
	for _, trace := range multipleTraces {
		traceID = ""
		checkTrace(&trace, "/a", 5000, 200)
		checkTrace(&trace, "/c", 5002, 200)
		checkTrace(&trace, "/d", 5003, 200)
	}
}

func TestNodeJSMultiProc(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodemultiproc.yml", path.Join(pathOutput, "test-suite-node-multiproc.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("Nested traces", testNestedTraces)

	require.NoError(t, compose.Close())
}
