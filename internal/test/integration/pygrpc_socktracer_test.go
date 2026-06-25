// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"net/http"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

const pygrpcGetFeatureOp = "/routeguide.RouteGuide/GetFeature"

// TestSuite_PyGRPC_Socktracer is the isolated wire-level proof of socktracer's
// packet HPACK injection for a non-Go gRPC client. A Python (FastAPI) service
// makes RouteGuide/GetFeature gRPC calls to a Python gRPC server; socktracer is
// on and black-box (connect-info) correlation is OFF. With no gotracer in play
// and no black-box correlation, the only way the server's gRPC span can share
// the client's trace is a traceparent socktracer injected onto the wire.
func TestSuite_PyGRPC_Socktracer(t *testing.T) {
	compose, err := docker.ComposeSuite(
		"docker-compose-pygrpc-socktracer.yml",
		path.Join(pathOutput, "test-suite-pygrpc-socktracer.log"))
	require.NoError(t, err)

	if !KernelLockdownMode() {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		if err := compose.Close(); err != nil {
			t.Logf("compose.Close(): %v", err)
		}
	})

	// /query drives a gRPC GetFeature call; a 200 means both client and server are up.
	waitForTestComponentsNoMetrics(t, "http://localhost:8080/query")

	t.Run("python gRPC client→server wire propagation (socktracer, CP off)",
		testPyGRPCWirePropagation)
	t.Run("socktracer injected HPACK traceparent", testPyGRPCHPACKInjected)
}

func testPyGRPCWirePropagation(t *testing.T) {
	var matched bool
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// keep generating gRPC traffic each iteration
		if r, err := http.Get("http://localhost:8080/query"); err == nil && r != nil {
			r.Body.Close()
		}

		r, err := http.Get(jaegerQueryURL + "?service=grpcsrv&limit=30&lookback=5m")
		require.NoError(ct, err)
		require.NotNil(ct, r)
		defer r.Body.Close()
		require.Equal(ct, http.StatusOK, r.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(r.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data, "no grpcsrv traces yet")

		// Find a trace that holds BOTH a grpcsrv GetFeature server span and a
		// pygrpcclient span. With black-box CP off and no gotracer, the only way
		// the two non-Go processes share a trace is a traceparent socktracer
		// injected into the client's HPACK and extracted on the server's ingress.
		// (We assert shared trace_id, not exact span nesting: the egress emit and
		// inject paths currently mint different span_ids — see span-id follow-up.)
		found := false
		for _, trace := range tq.Data {
			serverSpans := trace.FindByOperationNameServiceAndKind(
				pygrpcGetFeatureOp, "grpcsrv", "server")
			if len(serverSpans) > 0 && traceServices(trace)["pygrpcclient"] {
				found = true
				break
			}
		}
		require.True(ct, found,
			"no trace shared between pygrpcclient and grpcsrv — wire-level "+
				"traceparent did not propagate (black-box CP is off)")
		matched = true
	}, 3*time.Minute, time.Second)

	require.True(t, matched)
}

// testPyGRPCHPACKInjected confirms the socktracer HPACK chain actually rewrote a
// frame, via the bpf_debug marker in the live OBI container logs (the suite log
// file is only flushed at teardown). tpinjector is not loaded (socket_tracer=true),
// so any such marker is socktracer's.
func testPyGRPCHPACKInjected(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		out, err := exec.Command("docker", "compose", "--ansi", "never",
			"-f", "docker-compose-pygrpc-socktracer.yml",
			"logs", "obi").CombinedOutput()
		require.NoError(ct, err)
		require.True(ct, strings.Contains(string(out), "written TP to HPACK"),
			"expected socktracer HPACK injection marker in OBI logs")
	}, time.Minute, 2*time.Second)
}
