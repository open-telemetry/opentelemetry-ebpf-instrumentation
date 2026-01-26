// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testSampler(t *testing.T) {
	waitForTestComponents(t, "http://localhost:5000")
	waitForTestComponents(t, "http://localhost:5002")
	waitForTestComponents(t, "http://localhost:5003")

	// give enough time for the NodeJS injector to finish
	// TODO: once we implement the instrumentation status query API, replace
	// this with  a proper check to see if the target process has finished
	// being instrumented
	time.Sleep(60 * time.Second)

	// Add and check for specific trace ID
	// Run couple of requests to make sure we flush out any transactions that might be
	// stuck because of our tracking of full request times
	for i := 0; i < 10; i++ {
		ti.DoHTTPGet(t, "http://localhost:5000/a", 200)
	}

	require.Eventually(t, func() bool {
		resp, err := http.Get(jaegerQueryURL + "?service=service-a&operation=GET%20%2Fa")

		if err != nil {
			return false
		}

		if resp == nil {
			return false
		}

		if resp.StatusCode != http.StatusOK {
			return false
		}

		var tq jaeger.TracesQuery

		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}

		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/a"})

		lenA := len(traces)

		if lenA < 10 {
			return false
		}

		resp, err = http.Get(jaegerQueryURL + "?service=service-c&operation=GET%20%2Fc")

		if err != nil {
			return false
		}

		if resp == nil {
			return false
		}

		if resp.StatusCode != http.StatusOK {
			return false
		}

		traces = tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/c"})

		lenC := len(traces)

		if lenC == 0 {
			return false
		}
		if lenC >= lenA {
			return false
		}
		return true
	}, testTimeout, 1500*time.Millisecond, "Sampler trace validation failed")
}

func TestSampler(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-sampler.yml", path.Join(pathOutput, "test-suite-sampler.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("Sampler", testSampler)

	require.NoError(t, compose.Close())
}
