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

func testJavaNestedTraces(t *testing.T, slug string) {
	// give enough time for the Java injector to finish and to
	// harvest the routes
	t.Log("checking proper server to client nesting for [/api/" + slug + "]")
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:8081/api/"+slug+"?url=https://httpbin.org/get", 200)

		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fapi%2F" + slug)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/api/" + slug})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
		res := trace.FindByOperationName("GET /get", "client")
		require.Len(ct, res, 1)
		child := res[0]
		require.NotEmpty(ct, child.TraceID)
	}, 2*time.Minute, 5*time.Second)
}

func TestJavaNestedTraces(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-java-dist.yml", path.Join(pathOutput, "test-suite-java-dist.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	waitForTestComponentsRoute(t, "http://localhost:8081", "/api/health")

	for _, slug := range []string{"request", "async-request", "async-request-c", "async-request-fj"} {
		t.Run("Nested traces for "+slug, func(t *testing.T) {
			testJavaNestedTraces(t, slug)
		})
	}

	require.NoError(t, compose.Close())
}
