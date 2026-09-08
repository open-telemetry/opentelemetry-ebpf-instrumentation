// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const instrumentationErrorsHostPort = "8397"

// TestInstrumentationErrorsOTelMetrics runs OBI with the BPF capability dropped
// so every attempt to instrument the discovered testserver fails, emitting
// obi.instrumentation.errors over OTLP. The collector fans it out to Prometheus
// (asserted present here) and to weaver, which live-checks the error metric —
// including its process.executable.name / error.type attributes — against the
// registry.
func TestInstrumentationErrorsOTelMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-instrumentation-errors.yml", path.Join(pathOutput, "test-suite-instrumentation-errors-otel.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=`+instrumentationErrorsHostPort+`:8080`)
	require.NoError(t, compose.Up())

	// LIFO cleanup: Close last, after weaver has been /stopped and validated.
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	t.Cleanup(func() { runWeaverValidation(t) })

	t.Run("obi.instrumentation.errors exported over OTLP and weaver-validated", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}

		require.Eventually(t, func() bool {
			return pokeInstrumentationErrorsServer() == nil
		}, testTimeout, 500*time.Millisecond, "testserver never became reachable")

		// Keep the server discoverable and busy so OBI repeatedly attempts (and
		// fails) to instrument it.
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = pokeInstrumentationErrorsServer()
					time.Sleep(50 * time.Millisecond)
				}
			}
		}()
		defer close(stop)

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query("obi_instrumentation_errors_total")
			if !assert.NoError(ct, err, "querying obi_instrumentation_errors_total") {
				return
			}
			assert.NotEmpty(ct, results, "obi_instrumentation_errors_total should be present")
		}, testTimeout, 500*time.Millisecond)
	})
}

func pokeInstrumentationErrorsServer() error {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:" + instrumentationErrorsHostPort + "/ping")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
