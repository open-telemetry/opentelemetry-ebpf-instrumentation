// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"io"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestSuite_ConfigV2Standalone(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-config-v2-standalone.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-v2")
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	waitForTestComponentsNoMetrics(t, instrumentedServiceStdURL+"/smoke")

	requireOBIConfigV2(t, compose, `"cmd":"/testserver"`)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		appResp, err := http.Get(instrumentedServiceStdURL + "/smoke")
		require.NoError(ct, err)
		if err != nil {
			return
		}
		appResp.Body.Close()
		require.Equal(ct, http.StatusOK, appResp.StatusCode)

		metricsResp, err := http.Get("http://localhost:8999/metrics")
		require.NoError(ct, err)
		if err != nil {
			return
		}
		defer metricsResp.Body.Close()
		require.Equal(ct, http.StatusOK, metricsResp.StatusCode)

		body, err := io.ReadAll(metricsResp.Body)
		require.NoError(ct, err)
		require.Contains(ct, string(body), "http_server_request_duration_seconds_count")
		require.Contains(ct, string(body), `http_route="/smoke"`)
	}, 2*testTimeout, time.Second)
}

func requireOBIConfigV2(t *testing.T, compose *docker.Compose, target string) {
	t.Helper()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		obiLogs, err := compose.LogsOutput("obi")
		require.NoError(ct, err)

		var configV2Loaded, targetInstrumented bool
		for line := range strings.Lines(obiLogs) {
			if strings.Contains(line, "configuration loaded") &&
				(strings.Contains(line, `"version":"v2"`) || strings.Contains(line, "version=v2")) {
				configV2Loaded = true
			}
			if strings.Contains(line, "instrumenting process") && strings.Contains(line, target) {
				targetInstrumented = true
			}
		}

		require.True(ct, configV2Loaded, "OBI did not report loading Config v2")
		require.True(ct, targetInstrumented, "OBI did not report instrumenting %s", target)
	}, testTimeout, time.Second)
}
