// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testSelectiveExports(t *testing.T) {
	waitForTestComponents(t, "http://localhost:5003")

	getTraces := func(service string, path string) []jaeger.Trace {
		query := "http://localhost:16686/api/traces?service=" + service
		resp, err := http.Get(query)
		require.NoError(t, err)

		if resp == nil {
			return nil
		}

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))

		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: path})

		return traces
	}

	// give enough time for the NodeJS injector to finish
	// TODO: once we implement the instrumentation status query API, replace
	// this with  a proper check to see if the target process has finished
	// being instrumented
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:5001/b", 200)
		bTraces := getTraces("service-b", "/b")
		require.NotNil(ct, bTraces)
	}, 3*time.Minute, 100*time.Millisecond)

	// Run couple of requests to make sure we flush out any transactions that might be
	// stuck because of our tracking of full request times
	for i := 0; i < 10; i++ {
		ti.DoHTTPGet(t, "http://localhost:5000/a", 200)
		ti.DoHTTPGet(t, "http://localhost:5001/b", 200)
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		aTraces := getTraces("service-a", "/a")
		bTraces := getTraces("service-b", "/b")
		cTraces := getTraces("service-c", "/c")
		dTraces := getTraces("service-d", "/d")

		require.Empty(ct, aTraces)
		require.NotEmpty(ct, bTraces)
		require.NotEmpty(ct, cTraces)
		require.NotEmpty(ct, dTraces)
	}, testTimeout, 500*time.Millisecond)

	pq := promtest.Client{HostPort: "localhost:9090"}

	getMetrics := func(path string) []promtest.Result {
		query := fmt.Sprintf(`http_server_request_duration_seconds_count{url_path="%s"}`, path)
		results, err := pq.Query(query)

		require.NoError(t, err)

		return results
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		require.NotEmpty(ct, getMetrics("/a"))
	}, 10*time.Second, 100*time.Millisecond)

	bMetrics := getMetrics("/b")
	cMetrics := getMetrics("/c")
	dMetrics := getMetrics("/d")

	require.NotEmpty(t, bMetrics)
	require.Empty(t, cMetrics)
	require.NotEmpty(t, dMetrics)
}

func TestDiscoverySection(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-discovery.yml", path.Join(pathOutput, "test-suite-discovery.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("Selective exports", testSelectiveExports)

	require.NoError(t, compose.Close())
}
