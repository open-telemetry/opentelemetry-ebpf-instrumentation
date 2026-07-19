// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"bufio"
	"net"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const internalMetricsHostPort = "8393"

// internalMetricsExpected are OBI's own meta-telemetry (obi.*) series this suite
// deterministically emits and asserts as present (so a regression that stops
// emitting them fails the test — weaver only catches convention violations, not
// absence). Names are the Prometheus form the collector exports (dots ->
// underscores, monotonic sums get a _total suffix). The eBPF probe families
// require kernel BPF run-stats plus sustained traffic (driven below).
var internalMetricsExpected = []string{
	"obi_internal_build_info",             // gauge, emitted once at startup
	"obi_instrumented_processes",          // updowncounter, +1 per instrumented process
	"obi_otel_metric_exports_total",       // counter, every metric export
	"obi_bpf_map_entries_total",           // gauge, per eBPF map
	"obi_bpf_map_max_entries_total",       // gauge, per eBPF map
	"obi_bpf_probe_executions_total",      // counter, needs BPF run-stats + traffic
	"obi_bpf_probe_latency_seconds_total", // counter, needs BPF run-stats + traffic
}

// TestInternalOTelMetrics brings up OBI with internal_metrics.exporter=otel so
// its obi.* meta-telemetry rides the OTLP metrics endpoint. The collector fans
// that out to a Prometheus exporter (asserted here) and to weaver, which
// live-checks the internal surface against the semantic-convention registry in
// enforce mode.
func TestInternalOTelMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-internal-metrics.yml", path.Join(pathOutput, "test-suite-internal-metrics.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=`+internalMetricsHostPort+`:8080`)
	require.NoError(t, compose.Up())

	// Cleanups run LIFO: register compose.Close() first so it runs LAST, after
	// runWeaverValidation has /stopped the still-running weaver container.
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	t.Cleanup(func() { runWeaverValidation(t) })

	t.Run("obi.* internal metrics exported over OTLP", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}

		require.Eventually(t, func() bool {
			return pokeInternalMetricsServer() == nil
		}, testTimeout, 500*time.Millisecond, "testserver never became reachable")

		// Drive continuous traffic in the background so the eBPF probes keep
		// executing between BPF-stats scrapes (probe run-counts must advance
		// between two consecutive scrapes for obi.bpf.probe.* to report) and the
		// trace/metric exporters keep firing.
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = pokeInternalMetricsServer()
				}
			}
		}()
		defer close(stop)

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			for _, name := range internalMetricsExpected {
				results, err := pq.Query(name)
				if !assert.NoError(ct, err, "querying %s", name) {
					continue
				}
				assert.NotEmptyf(ct, results, "internal metric %s should be present", name)
			}
		}, testTimeout, 500*time.Millisecond)

		// Diagnostic: log the full obi_* surface actually observed, so the
		// registry declarations can be driven by what the emitter really emits.
		if observed, err := pq.Query(`group by (__name__) ({__name__=~"obi_.*"})`); err == nil {
			names := make([]string, 0, len(observed))
			for _, r := range observed {
				names = append(names, r.Metric["__name__"])
			}
			t.Logf("observed obi_* internal metric series: %v", names)
		}
	})
}

// pokeInternalMetricsServer drives a single request against the testserver so
// OBI's eBPF probes fire and its internal counters advance.
func pokeInternalMetricsServer() error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("localhost", internalMetricsHostPort), 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("FORCE_GC\n")); err != nil {
		return err
	}
	_, err = bufio.NewReader(conn).ReadString('\n')
	return err
}
