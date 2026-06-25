// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

// TestSuite_GRPCRelay_Socktracer is the wire-level proof for socktracer's
// packet HPACK injection. It runs the same multi-language gRPC relay chain as
// TestSuite_GRPCRelay, but with the socket tracer enabled and black-box
// (connect-info) correlation DISABLED. With black-box CP off, a trace ID can
// only survive a hop if a traceparent was injected onto the wire — so a fully
// connected chain through the non-Go relays (python, nodejs, java, dotnet)
// proves OBI rewrote their outgoing gRPC HPACK headers. The non-Go hops are
// the ones that exercise socktracer's chain; Go hops inject via the gotracer
// uprobe.
func TestSuite_GRPCRelay_Socktracer(t *testing.T) {
	compose, err := docker.ComposeSuite(
		"docker-compose-grpc-relay-socktracer.yml",
		path.Join(pathOutput, "test-suite-grpc-relay-socktracer.log"))
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

	// Same health endpoints/ports as the non-socktracer relay suite.
	healthURLs := []string{
		"http://localhost:8080/health", // go-entry
		"http://localhost:8090/health", // python-relay
		"http://localhost:8091/health", // go-grpc-to-http
		"http://localhost:8081/health", // go-http-to-grpc
		"http://localhost:8092/health", // nodejs-relay
		"http://localhost:8093/health", // java-relay
		"http://localhost:8095/health", // dotnet-relay
		"http://localhost:8094/health", // go-terminal
	}
	for _, url := range healthURLs {
		waitForTestComponentsNoMetrics(t, url)
	}

	// Reuses the non-socktracer suite's assertions verbatim (ports/services are
	// identical). The propagation it checks is meaningful here precisely because
	// black-box CP is off: continuity through the chain == wire-level injection.
	t.Run("gRPC relay chain context propagation (socktracer, CP off)", testGRPCRelayChainContextPropagation)

	// Direct ground-truth signal: confirm the socktracer HPACK-injection chain
	// actually wrote a traceparent onto a non-Go relay's outgoing wire.
	t.Run("socktracer injected HPACK traceparent", testSocktracerHPACKInjected)
}

// testSocktracerHPACKInjected greps the OBI container's live logs for the
// bpf_debug marker emitted by the final stage of the HPACK injection chain
// (obi_egress_h2_write_step). bpf_debug is on for this suite, so the marker
// surfaces as an OBI DEBUG line whenever the chain rewrites a frame. tpinjector
// is not loaded here (socket_tracer=true), so any such marker is socktracer's.
// Live `docker compose logs` is used because the suite log file is only flushed
// at teardown, after subtests run.
func testSocktracerHPACKInjected(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		out, err := exec.Command("docker", "compose", "--ansi", "never",
			"-f", "docker-compose-grpc-relay-socktracer.yml",
			"logs", "obi").CombinedOutput()
		require.NoError(ct, err)
		require.True(ct, strings.Contains(string(out), "written TP to HPACK"),
			"expected socktracer HPACK injection marker in OBI logs — the packet-level chain never rewrote a frame")
	}, time.Minute, 2*time.Second)
}
