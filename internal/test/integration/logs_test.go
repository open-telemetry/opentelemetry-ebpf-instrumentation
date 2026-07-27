// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func TestSuite_QueueProcessingLogs(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-queue-processing-logs.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env,
		`OTEL_EBPF_EXECUTABLE_PATH=(pingclient|testserver)`,
		`INSTRUMENTER_CONFIG_SUFFIX=-logs`,
	)
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	// Warm-up requests, same pattern as testHTTPTracesCommon: the first requests
	// after the containers come up may race with eBPF probe attachment/symbol
	// resolution, so we don't want to rely on the very first request below.
	ti.DoHTTPGet(t, instrumentedServiceStdURL+"/metrics", 200)
	ti.DoHTTPGet(t, instrumentedServiceStdURL+"/metrics", 200)

	ti.DoHTTPGet(t, instrumentedServiceStdURL+"/create-trace?delay=10ms&status=200", 200)

	// The span -> log-record pipeline is asynchronous (BPF ring buffer batching,
	// span processing, logs exporter batching), so the queue/processing log
	// record won't necessarily be in `docker compose logs obi`'s output the
	// instant the HTTP request completes. Poll until it shows up.
	//
	// The debugexporter (protocol: debug) renders logs with its "detailed"
	// verbosity as a human-readable field dump, not as JSON, e.g.:
	//   EventName: request.queue_processing
	//   Attributes:
	//        -> queue.duration: Double(0.000006625)
	//        -> processing.duration: Double(0.010251008)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logLines, err := compose.LogsOutput("obi")
		require.NoError(ct, err)
		require.Contains(ct, logLines, "EventName: request.queue_processing",
			"expected the debug-protocol logs exporter to print the queue/processing log record to OBI's own stdout")
		assert.Contains(ct, logLines, "queue.duration: Double(")
		assert.Contains(ct, logLines, "processing.duration: Double(")
	}, testTimeout, 500*time.Millisecond)
}
