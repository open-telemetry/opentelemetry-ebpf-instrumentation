// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

const (
	grpcOwnedTraceparent        = "00-33333333333333333333333333333333-4444444444444444-01"
	grpcInvalidOwnedTraceparent = "application-owned-invalid-value"
)

type grpcOwnershipObservation struct {
	CaseID       string   `json:"case_id"`
	Traceparents []string `json:"traceparents"`
	Peer         string   `json:"peer"`
	MaxActive    int      `json:"max_active"`
}

func TestSuite_GRPCGoTraceparentOwnership(t *testing.T) {
	if KernelLockdownMode() {
		t.Skip("Go gRPC ownership probes require bpf_probe_write_user")
	}

	compose, err := docker.ComposeSuite(
		"docker-compose-grpc-go-traceparent.yml",
		path.Join(pathOutput, "test-suite-grpc-go-traceparent.log"),
	)
	require.NoError(t, err)
	compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		if err := compose.Close(); err != nil {
			t.Logf("compose.Close(): %v", err)
		}
	})

	for _, endpoint := range []string{
		"http://127.0.0.1:8097/health",
		"http://127.0.0.1:8098/health",
		"http://127.0.0.1:18082/health",
		"http://127.0.0.1:18083/health",
	} {
		waitForTestComponentsNoMetrics(t, endpoint)
	}
	waitForGRPCOwnershipInstrumentation(t)

	t.Run("plaintext", func(t *testing.T) {
		testGRPCGoTraceparentOwnership(
			t, compose, 18082, "go-ownership-receiver", strings.Repeat("a", 32))
	})
	t.Run("TLS", func(t *testing.T) {
		testGRPCGoTraceparentOwnership(
			t, compose, 18083, "go-ownership-receiver-tls", strings.Repeat("b", 32))
	})
}

func waitForGRPCOwnershipInstrumentation(t *testing.T) {
	t.Helper()

	services := []struct {
		name string
		url  string
	}{
		{name: "go-ownership-client", url: "http://127.0.0.1:18082/health"},
		{name: "go-ownership-client-tls", url: "http://127.0.0.1:18083/health"},
	}
	for _, service := range services {
		require.Eventually(t, func() bool {
			resp, err := http.Get(service.url)
			if err == nil && resp != nil {
				_ = resp.Body.Close()
			}
			return hasSpansInJaeger(service.name)
		}, time.Minute, time.Second, "%s was not instrumented", service.name)
	}
}

func testGRPCGoTraceparentOwnership(
	t *testing.T,
	compose *docker.Compose,
	port int,
	receiverService string,
	outerTraceID string,
) {
	t.Helper()

	runID := fmt.Sprintf("%d-%d", port, time.Now().UnixNano())
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/ownership?run=%s", port, runID), nil)
	require.NoError(t, err)
	req.Header.Set("traceparent", fmt.Sprintf("00-%s-eeeeeeeeeeeeeeee-01", outerTraceID))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	var observations map[string]grpcOwnershipObservation
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(2000, receiverService)
		require.NoError(ct, err)
		observations = parseGRPCOwnershipObservations(ct, logs, runID)
		require.Len(ct, observations, 11)
	}, 30*time.Second, 250*time.Millisecond)

	ownedCases := map[string]string{
		"owned-index-1": grpcOwnedTraceparent,
		"owned-index-2": grpcOwnedTraceparent,
		"owned-index-3": grpcOwnedTraceparent,
		"owned-index-4": grpcOwnedTraceparent,
		"owned-invalid": grpcInvalidOwnedTraceparent,
		"mux-owned-1":   grpcOwnedTraceparent,
		"mux-owned-2":   grpcOwnedTraceparent,
	}
	controlCases := map[string]struct{}{
		"control-after-index": {},
		"mux-control-1":       {},
		"mux-control-2":       {},
		"control-after-mux":   {},
	}
	controlSpanIDs := map[string]struct{}{}
	peerAddr := ""
	multiplexed := false
	for caseName, observation := range observations {
		if peerAddr == "" {
			peerAddr = observation.Peer
		}
		require.NotEmpty(t, observation.Peer, caseName)
		require.Equal(t, peerAddr, observation.Peer, caseName)
		require.Len(t, observation.Traceparents, 1, caseName)
		multiplexed = multiplexed || observation.MaxActive >= 2

		traceparent := observation.Traceparents[0]
		if expected, owned := ownedCases[caseName]; owned {
			require.Equal(t, expected, traceparent, caseName)
			continue
		}
		_, control := controlCases[caseName]
		require.True(t, control, caseName)

		parts := strings.Split(traceparent, "-")
		require.Len(t, parts, 4, caseName)
		require.Equal(t, outerTraceID, parts[1], caseName)
		_, duplicate := controlSpanIDs[parts[2]]
		require.False(t, duplicate, caseName)
		controlSpanIDs[parts[2]] = struct{}{}
	}
	require.Len(t, controlSpanIDs, 4)
	require.True(t, multiplexed, "gRPC receiver did not observe concurrent streams")
}

func parseGRPCOwnershipObservations(
	t require.TestingT,
	logs string,
	runID string,
) map[string]grpcOwnershipObservation {
	const marker = "OBI_GRPC_OBSERVATION "
	observations := map[string]grpcOwnershipObservation{}
	for line := range strings.SplitSeq(logs, "\n") {
		_, payload, found := strings.Cut(line, marker)
		if !found {
			continue
		}
		var observation grpcOwnershipObservation
		require.NoError(t, json.Unmarshal([]byte(payload), &observation))
		prefix := runID + "/"
		if !strings.HasPrefix(observation.CaseID, prefix) {
			continue
		}
		caseName := strings.TrimPrefix(observation.CaseID, prefix)
		_, duplicate := observations[caseName]
		require.False(t, duplicate, observation.CaseID)
		observations[caseName] = observation
	}
	return observations
}
