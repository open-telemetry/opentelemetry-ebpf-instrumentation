// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

// The workload is a JVM started with the attach mechanism disabled, so the
// agent injection OBI attempts against it never completes and runs for the full
// OTEL_EBPF_JAVAAGENT_ATTACH_TIMEOUT, which the compose file sets well beyond
// this assertion window. Its Redis traffic is only visible if the eBPF PID
// filter is enabled without waiting for that injection.
func testJavaDiscoveryCapturesEarlyTraffic(t *testing.T, namespace string) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`db_client_operation_duration_seconds_count{` +
			`db_system_name="redis",` +
			`service_namespace="` + namespace + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.LessOrEqual(ct, 1, totalPromCount(ct, results))
	}, testTimeout, 100*time.Millisecond)
}

func testJavaDiscoveryEarlyTraffic(t *testing.T) {
	testJavaDiscoveryCapturesEarlyTraffic(t, "integration-test")
}
