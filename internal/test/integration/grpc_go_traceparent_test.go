// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

type grpcOwnershipObservation struct {
	CaseID       string   `json:"case_id"`
	Traceparents []string `json:"traceparents"`
	Peer         string   `json:"peer"`
	MaxActive    int      `json:"max_active"`
	LargeLength  int      `json:"large_length"`
	LargeSHA256  string   `json:"large_sha256"`
}

func TestSuite_GRPCGoTraceparentOwnership(t *testing.T) {
	if KernelLockdownMode() {
		t.Skip("Go HTTP/2 ownership probes require bpf_probe_write_user")
	}
	compose, err := docker.ComposeSuite(
		"docker-compose-grpc-go-traceparent.yml",
		path.Join(pathOutput, "test-suite-grpc-go-traceparent.log"),
	)
	require.NoError(t, err)
	compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`, `GO_H2_FORCE_SOCKET_FALLBACK=0`)
	require.NoError(t, compose.Up())

	t.Run("grpc-go current", func(t *testing.T) {
		testGRPCGoTraceparentOwnership(t, compose, "current", 18082,
			"clientHeaderHandler", strings.Repeat("c", 32), "direct_write")
	})
	t.Run("grpc-go legacy", func(t *testing.T) {
		testGRPCGoTraceparentOwnership(t, compose, "legacy", 18083,
			"headerHandler", strings.Repeat("d", 32), "direct_write")
	})
	t.Run("grpc-go TLS pre-write boundary", func(t *testing.T) {
		testGRPCGoPrewriteBoundary(t, compose, 18084, strings.Repeat("a", 32))
	})
	t.Run("grpc-go current without write buffering", func(t *testing.T) {
		testGRPCGoTraceparentOwnership(t, compose, "current-unbuffered", 18084,
			"clientHeaderHandler", strings.Repeat("b", 32), "direct_write")
	})
	require.NoError(t, compose.Close())

	compose, err = docker.ComposeSuite(
		"docker-compose-grpc-go-traceparent.yml",
		path.Join(pathOutput, "test-suite-grpc-go-traceparent-socket.log"),
	)
	require.NoError(t, err)
	compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`, `GO_H2_FORCE_SOCKET_FALLBACK=1`)
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		if err := compose.Close(); err != nil {
			t.Logf("compose.Close(): %v", err)
		}
	})
	t.Run("grpc-go current socket fallback", func(t *testing.T) {
		testGRPCGoSocketFallback(t, compose, "current", 18082,
			"clientHeaderHandler", strings.Repeat("e", 32))
	})
	t.Run("grpc-go legacy socket fallback", func(t *testing.T) {
		testGRPCGoSocketFallback(t, compose, "legacy", 18083,
			"headerHandler", strings.Repeat("f", 32))
	})
}

func testGRPCGoTraceparentOwnership(
	t *testing.T,
	compose *docker.Compose,
	version string,
	port int,
	handler string,
	outerTraceID string,
	expectedWriteEvent string,
) {
	t.Helper()
	waitForTestComponentsNoMetrics(t, fmt.Sprintf("http://127.0.0.1:%d/health", port))
	waitForTestComponentsNoMetrics(t, "http://127.0.0.1:8097/health")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(2000, "obi")
		require.NoError(ct, err)
		assert.Contains(ct, logs, "attached optional Go probe group")
		assert.Contains(ct, logs,
			"go_grpc_ownership_google.golang.org/grpc/internal/transport.(*loopyWriter)."+handler)
		assert.Contains(ct, logs, "service=go-ownership-"+version)
	}, time.Minute, 250*time.Millisecond, "grpc-go ownership probe group did not attach")

	before := readGoH2AuditSnapshot(t)
	runID := fmt.Sprintf("%s-%d", version, time.Now().UnixNano())
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/ownership?run=%s", port, runID), nil)
	require.NoError(t, err)
	req.Header.Set("traceparent", fmt.Sprintf("00-%s-eeeeeeeeeeeeeeee-01", outerTraceID))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var observations []grpcOwnershipObservation
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		receiverService := "go-ownership-receiver"
		if version == "current-unbuffered" {
			receiverService = "go-ownership-receiver-tls"
		}
		logs, err := compose.LogsTail(10000, receiverService)
		require.NoError(ct, err)
		observations = observations[:0]
		for line := range strings.SplitSeq(logs, "\n") {
			marker := strings.Index(line, "OBI_GRPC_OBSERVATION ")
			if marker < 0 {
				continue
			}
			var observation grpcOwnershipObservation
			require.NoError(ct, json.Unmarshal(
				[]byte(line[marker+len("OBI_GRPC_OBSERVATION "):]), &observation))
			if strings.HasPrefix(observation.CaseID, runID+"/") {
				observations = append(observations, observation)
			}
		}
		require.Len(ct, observations, 13+((32768-32500)/4)+1)
	}, 30*time.Second, 250*time.Millisecond)

	expected := map[string]struct {
		owned bool
		large bool
	}{
		"owned-index-1": {owned: true}, "owned-index-2": {owned: true},
		"owned-index-3": {owned: true}, "owned-index-4": {owned: true},
		"control-after-index": {}, "owned-continuation": {owned: true, large: true},
		"control-continuation": {large: true}, "control-after-continuation": {},
		"mux-owned-1": {owned: true}, "mux-control-1": {},
		"mux-owned-2": {owned: true}, "mux-control-2": {}, "control-after-mux": {},
	}
	for length := 32500; length <= 32768; length += 4 {
		expected[fmt.Sprintf("control-prewrite-%d", length)] = struct{ owned, large bool }{large: true}
	}
	sequential := []string{
		"owned-index-1", "owned-index-2", "owned-index-3", "owned-index-4",
		"control-after-index", "owned-continuation", "control-continuation",
		"control-after-continuation",
	}
	for length := 32500; length <= 32768; length += 4 {
		sequential = append(sequential, fmt.Sprintf("control-prewrite-%d", length))
	}
	for index, caseName := range sequential {
		require.Equal(t, runID+"/"+caseName, observations[index].CaseID)
	}
	concurrent := map[string]struct{}{
		"mux-owned-1": {}, "mux-control-1": {}, "mux-owned-2": {}, "mux-control-2": {},
	}
	for _, observation := range observations[len(sequential) : len(sequential)+len(concurrent)] {
		caseName := strings.TrimPrefix(observation.CaseID, runID+"/")
		_, ok := concurrent[caseName]
		require.True(t, ok, observation.CaseID)
		delete(concurrent, caseName)
	}
	require.Empty(t, concurrent)
	require.Equal(t, runID+"/control-after-mux", observations[len(observations)-1].CaseID)

	caseIDs := map[string]struct{}{}
	controlSpanIDs := map[string]struct{}{}
	peer := ""
	multiplexed := false
	ownedCount := 0
	controlCount := 0
	for _, observation := range observations {
		caseName := strings.TrimPrefix(observation.CaseID, runID+"/")
		expectation, expectedCase := expected[caseName]
		require.True(t, expectedCase, observation.CaseID)
		_, duplicate := caseIDs[observation.CaseID]
		require.False(t, duplicate, observation.CaseID)
		caseIDs[observation.CaseID] = struct{}{}
		if peer == "" {
			peer = observation.Peer
		}
		require.Equal(t, peer, observation.Peer, observation.CaseID)
		multiplexed = multiplexed || observation.MaxActive >= 2
		if expectation.large {
			if strings.Contains(observation.CaseID, "/control-prewrite-") {
				length, parseErr := strconv.Atoi(observation.CaseID[strings.LastIndexByte(observation.CaseID, '-')+1:])
				require.NoError(t, parseErr)
				require.Equal(t, length, observation.LargeLength, observation.CaseID)
			} else {
				require.Equal(t, 43691, observation.LargeLength, observation.CaseID)
				require.Equal(t, "85095decffb5b5830065c819108851b7b078f7801cc50d43e1b581db8019cf6f",
					observation.LargeSHA256, observation.CaseID)
			}
		} else {
			require.Zero(t, observation.LargeLength, observation.CaseID)
		}
		require.Len(t, observation.Traceparents, 1, observation.CaseID)
		traceparent := observation.Traceparents[0]
		if expectation.owned {
			ownedCount++
			require.Equal(t,
				"00-33333333333333333333333333333333-4444444444444444-01",
				traceparent,
				observation.CaseID)
			continue
		}

		controlCount++
		parts := strings.Split(traceparent, "-")
		require.Len(t, parts, 4, observation.CaseID)
		require.Equal(t, outerTraceID, parts[1], observation.CaseID)
		_, duplicate = controlSpanIDs[parts[2]]
		require.False(t, duplicate, observation.CaseID)
		controlSpanIDs[parts[2]] = struct{}{}
	}
	require.Len(t, caseIDs, len(expected))
	require.Equal(t, 7, ownedCount)
	require.Equal(t, 6+((32768-32500)/4)+1, controlCount)
	require.True(t, multiplexed, "gRPC receiver never handled two streams concurrently")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		after := readGoH2AuditSnapshot(ct)
		assertGoH2AuditCohort(ct, before, after, "grpc", len(expected), ownedCount,
			"observing", expectedWriteEvent)
	}, time.Minute, 250*time.Millisecond)
	require.Positive(t, goH2AuditEventDelta(before, readGoH2AuditSnapshot(t), "grpc", "prewrite_write"),
		"near-full grpc-go frame never reached the pre-Writer.Write probe")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=go-ownership-" + version + "&traceID=" + outerTraceID)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		var traces jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&traces))
		exported := map[string]struct{}{}
		for _, trace := range traces.Data {
			for _, span := range trace.Spans {
				process, ok := trace.Processes[span.ProcessID]
				if !ok || process.ServiceName != "go-ownership-"+version {
					continue
				}
				kind, ok := jaeger.FindIn(span.Tags, "span.kind")
				if ok && kind.Value == "client" {
					exported[span.SpanID] = struct{}{}
				}
			}
		}
		for spanID := range controlSpanIDs {
			_, ok := exported[spanID]
			assert.True(ct, ok, "receiver span ID %s was not an exported client span", spanID)
		}
	}, time.Minute, 250*time.Millisecond)
}

func requireGRPCControlSpansExported(
	t *testing.T,
	service string,
	traceID string,
	spanIDs ...string,
) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + service + "&traceID=" + traceID)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		var traces jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&traces))
		exported := map[string]struct{}{}
		for _, trace := range traces.Data {
			for _, span := range trace.Spans {
				process, ok := trace.Processes[span.ProcessID]
				if !ok || process.ServiceName != service {
					continue
				}
				kind, ok := jaeger.FindIn(span.Tags, "span.kind")
				if ok && kind.Value == "client" {
					exported[span.SpanID] = struct{}{}
				}
			}
		}
		for _, spanID := range spanIDs {
			_, ok := exported[spanID]
			assert.True(ct, ok, "receiver span ID %s was not an exported client span", spanID)
		}
	}, time.Minute, 250*time.Millisecond)
}

func testGRPCGoPrewriteBoundary(
	t *testing.T,
	compose *docker.Compose,
	port int,
	outerTraceID string,
) {
	t.Helper()
	waitForTestComponentsNoMetrics(t, fmt.Sprintf("http://127.0.0.1:%d/health", port))
	waitForTestComponentsNoMetrics(t, "http://127.0.0.1:8098/health")

	before := readGoH2AuditSnapshot(t)
	runID := fmt.Sprintf("current-unbuffered-prewrite-%d", time.Now().UnixNano())
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/ownership?mode=prewrite&run=%s", port, runID), nil)
	require.NoError(t, err)
	req.Header.Set("traceparent", fmt.Sprintf("00-%s-eeeeeeeeeeeeeeee-01", outerTraceID))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	observations := map[string]grpcOwnershipObservation{}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(1000, "go-ownership-receiver-tls")
		require.NoError(ct, err)
		clear(observations)
		for line := range strings.SplitSeq(logs, "\n") {
			marker := strings.Index(line, "OBI_GRPC_OBSERVATION ")
			if marker < 0 {
				continue
			}
			var candidate grpcOwnershipObservation
			require.NoError(ct, json.Unmarshal(
				[]byte(line[marker+len("OBI_GRPC_OBSERVATION "):]), &candidate))
			if strings.HasPrefix(candidate.CaseID, runID+"/") {
				_, duplicate := observations[candidate.CaseID]
				require.False(ct, duplicate, candidate.CaseID)
				observations[candidate.CaseID] = candidate
			}
		}
		require.Len(ct, observations, 3)
	}, 30*time.Second, 250*time.Millisecond)
	first := observations[runID+"/prewrite-first-control"]
	require.Len(t, first.Traceparents, 1)
	firstParts := strings.Split(first.Traceparents[0], "-")
	require.Len(t, firstParts, 4)
	require.Equal(t, outerTraceID, firstParts[1])
	warmup := observations[runID+"/prewrite-capacity"]
	require.Equal(t, []string{
		"00-33333333333333333333333333333333-4444444444444444-01",
	}, warmup.Traceparents)
	require.Equal(t, 43691, warmup.LargeLength)
	observation := observations[runID+"/prewrite-postwarm-control"]
	require.Len(t, observation.Traceparents, 1)
	parts := strings.Split(observation.Traceparents[0], "-")
	require.Len(t, parts, 4)
	require.Equal(t, outerTraceID, parts[1])
	require.NotEmpty(t, first.Peer)
	require.Equal(t, first.Peer, warmup.Peer)
	require.Equal(t, first.Peer, observation.Peer)
	require.NotEqual(t, firstParts[2], parts[2])
	requireGRPCControlSpansExported(
		t,
		"go-ownership-current-unbuffered",
		outerTraceID,
		firstParts[2],
		parts[2],
	)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		after := readGoH2AuditSnapshot(ct)
		assertGoH2AuditCohort(ct, before, after, "grpc", 3, 1,
			"observing", "direct_write")
	}, time.Minute, 250*time.Millisecond)
}

func testGRPCGoSocketFallback(
	t *testing.T,
	compose *docker.Compose,
	version string,
	port int,
	handler string,
	outerTraceID string,
) {
	t.Helper()
	waitForTestComponentsNoMetrics(t, fmt.Sprintf("http://127.0.0.1:%d/health", port))
	waitForTestComponentsNoMetrics(t, "http://127.0.0.1:8097/health")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(2000, "obi")
		require.NoError(ct, err)
		assert.Contains(ct, logs,
			"go_grpc_ownership_google.golang.org/grpc/internal/transport.(*loopyWriter)."+handler)
		assert.Contains(ct, logs, "service=go-ownership-"+version)
	}, time.Minute, 250*time.Millisecond)

	before := readGoH2AuditSnapshot(t)
	runID := fmt.Sprintf("%s-socket-%d", version, time.Now().UnixNano())
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/ownership?mode=socket&run=%s", port, runID), nil)
	require.NoError(t, err)
	req.Header.Set("traceparent", fmt.Sprintf("00-%s-eeeeeeeeeeeeeeee-01", outerTraceID))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var observations []grpcOwnershipObservation
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(1000, "go-ownership-receiver")
		require.NoError(ct, err)
		observations = observations[:0]
		for line := range strings.SplitSeq(logs, "\n") {
			marker := strings.Index(line, "OBI_GRPC_OBSERVATION ")
			if marker < 0 {
				continue
			}
			var candidate grpcOwnershipObservation
			require.NoError(ct, json.Unmarshal(
				[]byte(line[marker+len("OBI_GRPC_OBSERVATION "):]), &candidate))
			if strings.HasPrefix(candidate.CaseID, runID+"/") {
				observations = append(observations, candidate)
			}
		}
		require.Len(ct, observations, 2)
	}, 30*time.Second, 250*time.Millisecond)
	require.Equal(t, runID+"/socket-continuation", observations[0].CaseID)
	require.Equal(t, runID+"/socket-control", observations[1].CaseID)
	require.NotEmpty(t, observations[0].Peer)
	require.Equal(t, observations[0].Peer, observations[1].Peer)
	require.Equal(t, 20027, observations[0].LargeLength)
	require.Equal(t, "9dc880038de8fb82055048dc5ff997c637641cbd25916ee65cfcc505a20a862f",
		observations[0].LargeSHA256)
	require.Zero(t, observations[1].LargeLength)
	spanIDs := make([]string, 0, len(observations))
	for _, observation := range observations {
		require.Len(t, observation.Traceparents, 1, observation.CaseID)
		parts := strings.Split(observation.Traceparents[0], "-")
		require.Len(t, parts, 4, observation.CaseID)
		require.Equal(t, outerTraceID, parts[1], observation.CaseID)
		require.NotEqual(t, strings.Repeat("0", 16), parts[2], observation.CaseID)
		spanIDs = append(spanIDs, parts[2])
	}
	require.NotEqual(t, spanIDs[0], spanIDs[1])
	requireGRPCControlSpansExported(
		t, "go-ownership-"+version, outerTraceID, spanIDs...)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		after := readGoH2AuditSnapshot(ct)
		assertGoH2AuditCohort(ct, before, after, "grpc", 2, 0, "observing", "socket_write")
		continuationWrites := 0
		baseline := map[string]int{}
		for _, event := range before.Events {
			baseline[goH2AuditEventKey(event)] = event.Count
		}
		for _, event := range after.Events {
			if event.Protocol == "grpc" && event.Event == "socket_continuation_write" &&
				event.Count-baseline[goH2AuditEventKey(event)] == 1 {
				continuationWrites++
			}
		}
		require.Equal(ct, 1, continuationWrites)
	}, time.Minute, 250*time.Millisecond)
}
