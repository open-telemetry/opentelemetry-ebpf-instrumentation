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
)

// TestSuite_SocktracerHTTP2 tests that socktracer correctly detects and parses
// plaintext HTTP/2 (h2c) traffic. Go-specific tracers are disabled so that the
// traffic is handled entirely through the socktracer TCP path:
// matchHTTP2 heuristic → MisclassifiedEvent → http2SpanFromTCPEvent.
func TestSuite_SocktracerHTTP2(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-http2-socktracer.yml", path.Join(pathOutput, "test-suite-http2-socktracer.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Cleanup(func() { _ = compose.Close() })

	waitForTestComponentsNoMetrics(t, "http://localhost:7373/smoke")

	t.Run("h2c client spans detected", func(t *testing.T) {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			resp, err := http.Get(jaegerQueryURL + "?service=h2cclient&operation=GET%20%2Fping")
			require.NoError(ct, err)
			defer resp.Body.Close()
			require.Equal(ct, http.StatusOK, resp.StatusCode)

			var tq jaeger.TracesQuery
			require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
			traces := tq.FindBySpan(
				jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
				jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
			)
			require.GreaterOrEqual(ct, len(traces), 1)
		}, testTimeout, time.Second)
	})

	t.Run("h2c server spans detected", func(t *testing.T) {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			resp, err := http.Get(jaegerQueryURL + "?service=h2cserver&operation=GET%20%2Fping")
			require.NoError(ct, err)
			defer resp.Body.Close()
			require.Equal(ct, http.StatusOK, resp.StatusCode)

			var tq jaeger.TracesQuery
			require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
			traces := tq.FindBySpan(
				jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
				jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
			)
			require.GreaterOrEqual(ct, len(traces), 1)
		}, testTimeout, time.Second)
	})
}
