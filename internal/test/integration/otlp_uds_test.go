// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestOTLPMetricsOverUDS(t *testing.T) {
	// otelcol binds its OTLP listener on a socket in this shared dir; remove any socket left by a
	// previous run so the bind succeeds (Close only prunes anonymous volumes, not the bind mount).
	socketDir := path.Join(pathOutput, "run-otlp-uds")
	require.NoError(t, os.RemoveAll(socketDir))
	require.NoError(t, os.MkdirAll(socketDir, 0o755))

	compose, err := docker.ComposeSuite("docker-compose-otlp-uds.yml", path.Join(pathOutput, "test-suite-otlp-uds.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// waitForTestComponents returns only once a /smoke request's RED metric has reached Prometheus,
	// i.e. after OBI pushed it over the unix socket to otelcol — the end-to-end assertion.
	t.Run("RED metrics reach Prometheus over a unix-socket OTLP endpoint", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:8080")
	})

	require.NoError(t, compose.Close())
}
