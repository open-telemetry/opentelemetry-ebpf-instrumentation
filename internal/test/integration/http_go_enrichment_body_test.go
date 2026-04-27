// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

// TestSuiteGoBodyExtraction exercises the shared bodyExtraction* assertions
// against the Go uprobe tracer.
func TestSuiteGoBodyExtraction(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-go-body-extraction.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-http-enrichment-body")
	require.NoError(t, compose.Up())

	t.Run("Body extraction obfuscate", func(t *testing.T) {
		waitForTestComponents(t, instrumentedServiceStdURL)
		bodyExtractionObfuscate(t)
	})
	t.Run("Body extraction include", func(t *testing.T) {
		bodyExtractionInclude(t)
	})
	t.Run("Body excluded by default", func(t *testing.T) {
		// The Go uprobe tracer captures the native std-mux pattern, reported
		// verbatim as "GET /rolldice/{id}".
		bodyExtractionExcludedByDefault(t, "GET /rolldice/{id}")
	})
	t.Run("Body with Content-Type header", func(t *testing.T) {
		bodyExtractionContentTypeHeader(t)
	})

	require.NoError(t, compose.Close())
}
