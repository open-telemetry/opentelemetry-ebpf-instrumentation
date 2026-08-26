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

// testParentBasedSamplerWireParent proves that parentbased_always_off follows
// the sampling decision carried by an incoming traceparent (a wire-received
// remote parent): requests joining a sampled trace are exported and keep the
// parent link, while requests joining an unsampled trace and requests with no
// traceparent at all export nothing.
func testParentBasedSamplerWireParent(t *testing.T) {
	waitForTestComponents(t, "http://localhost:5000")

	// give enough time for the NodeJS injector to finish
	// TODO: once we implement the instrumentation status query API, replace
	// this with  a proper check to see if the target process has finished
	// being instrumented
	time.Sleep(60 * time.Second)

	sampledTraceID := createTraceID()
	sampledParentID := createParentID()
	unsampledTraceID := createTraceID()

	// Run several requests of each kind to make sure we flush out any
	// transactions that might be stuck because of our tracking of full
	// request times.
	for i := 0; i < 10; i++ {
		// flags 01: the upstream sampler decided to sample this trace
		doHTTPGetWithTraceparent(t, "http://localhost:5000/a", 200, "00-"+sampledTraceID+"-"+sampledParentID+"-01")
		// flags 00: the upstream sampler decided NOT to sample this trace
		doHTTPGetWithTraceparent(t, "http://localhost:5000/a", 200, "00-"+unsampledTraceID+"-"+createParentID()+"-00")
		// no traceparent: a trace root, dropped by always_off
		ti.DoHTTPGet(t, "http://localhost:5000/a", 200)
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=service-a&operation=GET%20%2Fa")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		var sampled *jaeger.Trace
		for i := range tq.Data {
			if tq.Data[i].TraceID == sampledTraceID {
				sampled = &tq.Data[i]
			}
			require.NotEqual(ct, unsampledTraceID, tq.Data[i].TraceID,
				"a span joining an unsampled trace (traceparent flags 00) must not be exported")
		}
		require.NotNil(ct, sampled,
			"spans joining a sampled trace (traceparent flags 01) must be exported with the incoming trace ID")

		// the exported span must be linked to the wire parent, not re-rooted
		foundParentRef := false
		for _, span := range sampled.Spans {
			for _, ref := range span.References {
				if ref.SpanID == sampledParentID {
					foundParentRef = true
				}
			}
		}
		require.True(ct, foundParentRef,
			"the exported span must reference the traceparent's parent span ID")
	}, testTimeout, 1500*time.Millisecond)

	// The sampled trace has been exported by now, and all requests went
	// through the same short-batched pipeline: if the unsampled or root
	// spans had been exported at all, they would be visible by now.
	resp, err := http.Get(jaegerQueryURL + "?service=service-a&operation=GET%20%2Fa")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
	for i := range tq.Data {
		require.NotEqual(t, unsampledTraceID, tq.Data[i].TraceID)
	}
	// every exported trace for this service must be one that carried a
	// sampled incoming traceparent: with parentbased_always_off, roots
	// (requests without a traceparent) are never exported
	for i := range tq.Data {
		require.Equal(t, sampledTraceID, tq.Data[i].TraceID,
			"only the trace with a sampled wire parent may be exported; roots must be dropped")
	}
}

func TestParentBasedSamplerWireParent(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-parentbased-sampler.yml", path.Join(pathOutput, "test-suite-parentbased-sampler.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("ParentBasedSamplerWireParent", testParentBasedSamplerWireParent)

	require.NoError(t, compose.Close())
}
