// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

// TestEstablishedSocketBackfill verifies that socktracer detects TCP connections that were
// established before OBI started. The keepaliveclient connects to socktracer-server and
// writes /tmp/connected; OBI starts only after that flag appears. On AllowPID, OBI scans
// /proc/<pid>/fd via pidfd_getfd and registers pre-existing ESTABLISHED sockets into
// sk_data_map + sock_dir from userspace (no BPF iter/tcp required). The test passes when
// the keepaliveclient receives a Traceparent header echoed back by the server, proving that
// OBI injected it on the pre-existing connection.
func TestEstablishedSocketBackfill(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-keepalive.yml", path.Join(pathOutput, "test-suite-keepalive.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Cleanup(func() { _ = compose.Close() })

	waitForTestComponentsNoMetrics(t, "http://localhost:8080/smoke")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get("http://localhost:9091/status")
		require.NoError(ct, err)
		resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
	}, testTimeout, time.Second)
}
