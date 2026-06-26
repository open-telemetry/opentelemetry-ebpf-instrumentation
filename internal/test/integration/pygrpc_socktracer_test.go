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

		// Assert true span nesting: a grpcsrv GetFeature server span must be a
		// direct CHILD_OF a pygrpcclient GetFeature client span. With black-box CP
		// off and no gotracer, that only holds if socktracer (1) injected a wire
		// traceparent whose span_id equals the emitted client span's, and (2)
		// reliably emitted that client span — which the in-BPF h2 request/response
		// pairing (h2_pending map) guarantees. Shared trace_id alone is no longer
		// sufficient proof.
		found := false
		for i := range tq.Data {
			trace := tq.Data[i]
			serverSpans := trace.FindByOperationNameServiceAndKind(
				pygrpcGetFeatureOp, "grpcsrv", "server")
			clientSpans := trace.FindByOperationNameServiceAndKind(
				pygrpcGetFeatureOp, "pygrpcclient", "client")
			if len(serverSpans) == 0 || len(clientSpans) == 0 {
				continue
			}

			clientIDs := make(map[string]struct{}, len(clientSpans))
			for _, c := range clientSpans {
				clientIDs[c.SpanID] = struct{}{}
			}

			for j := range serverSpans {
				if parent, ok := trace.ParentOf(&serverSpans[j]); ok {
					if _, isClient := clientIDs[parent.SpanID]; isClient {
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}
		require.True(ct, found,
			"no grpcsrv GetFeature server span is a child of a pygrpcclient "+
				"GetFeature client span — socktracer must inject a wire traceparent "+
				"whose span_id matches the (reliably emitted) client span; black-box CP is off")
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
