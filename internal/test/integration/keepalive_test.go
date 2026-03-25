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

func TestExistingSocketsDetection(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-keepalive.yml", path.Join(pathOutput, "test-suite-keepalive.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	waitForTestComponentsNoMetrics(t, "http://localhost:8080/smoke")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get("http://localhost:9091/status")
		require.NoError(ct, err)
		resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
	}, testTimeout, time.Second)

	require.NoError(t, compose.Close())
}
