// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

const avoidedServicesHostPort = "8394"

// TestAvoidedServicesOTelMetrics brings up a self-instrumented OpenTelemetry
// server (go_otel rolldice) that exports its own OTLP telemetry. OBI discovers
// it, observes the OTLP export calls, and avoids instrumenting it — recording
// obi.avoided.services, which is then live-checked by weaver.
func TestAvoidedServicesOTelMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-avoided-services.yml", path.Join(pathOutput, "test-suite-avoided-services.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=`+avoidedServicesHostPort+`:8080`)
	require.NoError(t, compose.Up())

	// LIFO cleanup: Close last, after weaver has been /stopped and validated.
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	t.Cleanup(func() { runWeaverValidation(t) })

	t.Run("OBI avoids the self-instrumented server", func(t *testing.T) {
		require.Eventually(t, func() bool {
			return pokeAvoidedServer() == nil
		}, testTimeout, 500*time.Millisecond, "testserver never became reachable")

		// Keep the server busy so it repeatedly produces and exports its own
		// OTLP telemetry, which OBI must observe to classify it as avoided.
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = pokeAvoidedServer()
					time.Sleep(50 * time.Millisecond)
				}
			}
		}()
		defer close(stop)

		// Give OBI time to discover the process, observe an OTLP export, and
		// record the avoided-services metric before weaver is stopped.
		time.Sleep(20 * time.Second)
	})
}

func pokeAvoidedServer() error {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:" + avoidedServicesHostPort + "/rolldice")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
