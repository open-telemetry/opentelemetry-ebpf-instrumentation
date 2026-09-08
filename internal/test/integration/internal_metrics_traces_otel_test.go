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

const internalMetricsTracesHostPort = "8395"

// internalMetricsTracesExpected are the OBI meta-telemetry series that only
// populate when OBI actually exports spans. Exporting spans over OTLP drives
// instrumentedTracesExporter.ConsumeTraces (obi.otel.trace.exports) and the
// ring-buffer forwarder flush path (obi.ebpf.tracer.flushes). The metrics-only
// internal-metrics suite has no traces endpoint and non-HTTP traffic, so it
// cannot reach either. tracer.flushes is a histogram (asserted via its _count
// series); trace.exports is a monotonic counter (_total suffix).
var internalMetricsTracesExpected = []string{
	"obi_otel_trace_exports_total",  // counter, per exported trace batch
	"obi_ebpf_tracer_flushes_count", // histogram count, per ring-buffer flush
}

// TestInternalOTelMetricsTraces brings up OBI with internal_metrics.exporter=otel
// AND the OTLP traces endpoint enabled, driving HTTP traffic against the
// testserver so OBI exports spans. That exercises the trace-export and
// ring-buffer-flush internal metrics, which are then fanned out to Prometheus
// (asserted present here) and to weaver for semantic-convention live-check.
func TestInternalOTelMetricsTraces(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-internal-metrics-traces.yml", path.Join(pathOutput, "test-suite-internal-metrics-traces.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=`+internalMetricsTracesHostPort+`:8080`)
	require.NoError(t, compose.Up())

	// Cleanups run LIFO: register compose.Close() first so it runs LAST, after
	// runWeaverValidation has /stopped the still-running weaver container.
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	t.Cleanup(func() { runWeaverValidation(t) })

	t.Run("obi trace-export internal metrics exported over OTLP", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}

		require.Eventually(t, func() bool {
			return pokeInternalMetricsTracesServer() == nil
		}, testTimeout, 500*time.Millisecond, "testserver never became reachable")

		// Drive continuous HTTP traffic so OBI keeps producing spans: each
		// request yields a server span that the ring-buffer forwarder flushes
		// (obi.ebpf.tracer.flushes) and the OTLP traces exporter submits
		// (obi.otel.trace.exports).
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = pokeInternalMetricsTracesServer()
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()
		defer close(stop)

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			for _, name := range internalMetricsTracesExpected {
				results, err := pq.Query(name)
				if !assert.NoError(ct, err, "querying %s", name) {
					continue
				}
				assert.NotEmptyf(ct, results, "internal metric %s should be present", name)
			}
		}, testTimeout, 500*time.Millisecond)
	})
}

// pokeInternalMetricsTracesServer drives a single HTTP request against the
// testserver so OBI produces and exports a server span.
func pokeInternalMetricsTracesServer() error {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:" + internalMetricsTracesHostPort + "/ping")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
