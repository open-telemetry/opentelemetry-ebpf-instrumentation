// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

// TestExePathPermission validates that a process is still instrumented and produces
// kprobe-based spans when discovered by open_ports alone — the fallback that kicks in
// when /proc/<pid>/exe is unreadable (EACCES) on hardened kernels with restrictive
// ptrace_scope or SELinux policy.
func TestExePathPermission(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-exeperm.yml", path.Join(pathOutput, "test-suite-exeperm.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	defer compose.Close()

	waitForTestComponentsNoMetrics(t, "http://localhost:3030/smoke")

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := testHTTPClient.Get("http://localhost:3030/greeting")
		if assert.NoError(ct, err) {
			resp.Body.Close()
		}

		resp, err = http.Get(jaegerQueryURL + "?service=nodeserver&operation=GET%20%2Fgreeting")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/greeting"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, time.Second)

	spans := trace.FindByOperationName("GET /greeting", "server")
	require.NotEmpty(t, spans)

	tag, ok := jaeger.FindIn(spans[0].Tags, "http.response.status_code")
	require.True(t, ok)
	assert.InDelta(t, float64(200), tag.Value, 0)
}
