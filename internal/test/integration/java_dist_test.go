// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
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
	test.Eventually(t, 2*time.Minute, func(t require.TestingT) {
		ti.DoHTTPGet(t, "http://localhost:8081/api/"+slug+"?url=https://httpbin.org/get", 200)

		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fapi%2F" + slug)
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/api/" + slug})
		require.GreaterOrEqual(t, len(traces), 1)
		trace = traces[0]
		res := trace.FindByOperationName("GET /get", "client")
		require.Len(t, res, 1)
		child := res[0]
		require.NotEmpty(t, child.TraceID)
	}, test.Interval(5*time.Second))
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
