// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const (
	goHTTP2ApplicationTraceparent = "00-11111111111111111111111111111111-2222222222222222-01"
	goHTTP2OuterTraceparent       = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
)

type goHTTP2Observation struct {
	CaseID       string   `json:"case_id"`
	Traceparents []string `json:"traceparents"`
	ProtoMajor   int      `json:"proto_major"`
	RemoteAddr   string   `json:"remote_addr"`
	MaxActive    int      `json:"max_active"`
	LargeLength  int      `json:"large_length"`
	LargeSHA256  string   `json:"large_sha256"`
}

type goHTTP2RunResult struct {
	CaseID      string             `json:"case_id"`
	Observation goHTTP2Observation `json:"observation"`
	Error       string             `json:"error"`
}

type goHTTP2RunResponse struct {
	Implementation string             `json:"implementation"`
	Results        []goHTTP2RunResult `json:"results"`
}

type goHTTP2AuditEvent struct {
	PID                uint32 `json:"pid"`
	ProcessStart       uint64 `json:"process_start"`
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"destination_address"`
	SourcePort         uint16 `json:"source_port"`
	DestinationPort    uint16 `json:"destination_port"`
	StreamID           uint32 `json:"stream_id"`
	Protocol           string `json:"protocol"`
	Event              string `json:"event"`
	State              string `json:"state"`
	TraceID            string `json:"trace_id"`
	Count              int    `json:"count"`
}

type goHTTP2AuditSnapshot struct {
	Events []goHTTP2AuditEvent `json:"events"`
	Active []struct {
		PID                uint32 `json:"pid"`
		ProcessStart       uint64 `json:"process_start"`
		SourceAddress      string `json:"source_address"`
		DestinationAddress string `json:"destination_address"`
		SourcePort         uint16 `json:"source_port"`
		DestinationPort    uint16 `json:"destination_port"`
		StreamID           uint32 `json:"stream_id"`
		Protocol           string `json:"protocol"`
	} `json:"active_streams"`
}

func testREDMetricsForHTTP2Library(t *testing.T, route, svcNs string) {
	// Eventually, Prometheus would make this query visible
	var (
		pq           = promtest.Client{HostPort: prometheusHostPort}
		serverLabels = `http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="server",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"`
		clientLabels = `http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="client"`
	)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_server_request_duration_seconds_count{%s}", serverLabels)
		checkServerPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_server_request_body_size_bytes_count{%s}", serverLabels)
		checkServerPromQueryResult(ct, pq, query, 3)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_server_response_body_size_bytes_count{%s}", serverLabels)
		checkServerPromQueryResult(ct, pq, query, 3)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_client_request_duration_seconds_count{%s}", clientLabels)
		checkClientPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_client_request_body_size_bytes_count{%s}", clientLabels)
		checkClientPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_client_response_body_size_bytes_count{%s}", clientLabels)
		checkClientPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)
}

func testNestedHTTP2Traces(t *testing.T, url string) {
	var traceID string

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=client&operation=GET%20%2F" + url)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
	}, 1*time.Minute, 100*time.Millisecond)

	// Check the information of the HTTP2 client span
	res := trace.FindByOperationName("GET /"+url, "client")
	require.NotEmpty(t, res)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	traceID = parent.TraceID
	require.NotEmpty(t, parent.SpanID)

	// Find the same traceID on a server span
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=server&operation=GET%20%2F" + url + "&traceID=" + traceID)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
	}, 1*time.Minute, 100*time.Millisecond)
}

func TestHTTP2Go(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-http2.yml", path.Join(pathOutput, "test-suite-http2.log"))
	require.NoError(t, err)

	testHTTP2GO(t, compose, false)
}

func testHTTP2GO(t *testing.T, compose *docker.Compose, useHTTPProtocols bool) {
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	if useHTTPProtocols {
		compose.Env = append(compose.Env, `TEST_HTTP2_PROTOCOLS=1`)
	}
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())
	if !KernelLockdownMode() {
		if useHTTPProtocols {
			testGoHTTP2TraceparentOwnership(
				t, compose, 28080, "go_http2_stdlib_ownership", "net/http", false)
		} else {
			testGoHTTP2TraceparentOwnership(
				t, compose, 28080, "go_http2_xnet_ownership", "golang.org/x/net/http2", true)
			testGoHTTP2TraceparentOwnership(
				t, compose, 28081, "go_http2_xnet_legacy_ownership", "golang.org/x/net/http2", true)
			testGoHTTP2TraceparentOwnership(
				t, compose, 28082, "go_http2_stdlib_ownership", "net/http-go1.17", false)
		}
	}

	t.Run("Go RED metrics: http2 service", func(t *testing.T) {
		testREDMetricsForHTTP2Library(t, "/ping", "http2-go")
		testREDMetricsForHTTP2Library(t, "/pingdo", "http2-go")
		testREDMetricsForHTTP2Library(t, "/pingrt", "http2-go")
	})

	if !lockdown {
		t.Run("Go RED metrics: http2 context propagation ", func(t *testing.T) {
			testNestedHTTP2Traces(t, "pingdo")
		})
	}

	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func testGoHTTP2TraceparentOwnership(
	t *testing.T,
	compose *docker.Compose,
	port int,
	group string,
	implementation string,
	expectAbandonment bool,
) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsOutput("obi")
		require.NoError(ct, err)
		assert.Contains(ct, logs,
			"level=INFO msg=\"attached optional Go probe group\" component=ebpf.Instrumenter group="+group)
	}, time.Minute, 250*time.Millisecond, "ownership probe group did not attach")
	if expectAbandonment {
		testGoHTTP2Abandonment(t, port, implementation)
	}

	before := readGoH2AuditSnapshot(t)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/run", port), nil)
	require.NoError(t, err)
	req.Header.Set("traceparent", goHTTP2OuterTraceparent)
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var run goHTTP2RunResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&run))
	require.Equal(t, implementation, run.Implementation)
	expected := []struct {
		id        string
		owned     bool
		large     bool
		abandoned bool
	}{
		{id: "metric-ping-1"},
		{id: "metric-ping-2"},
		{id: "metric-ping-3"},
		{id: "metric-pingdo-1"},
		{id: "metric-pingdo-2"},
		{id: "metric-pingdo-3"},
		{id: "metric-pingrt-1"},
		{id: "metric-pingrt-2"},
		{id: "metric-pingrt-3"},
		{id: "owned-index-1", owned: true},
		{id: "owned-index-2", owned: true},
		{id: "owned-index-3", owned: true},
		{id: "owned-index-4", owned: true},
	}
	expected = append(expected, []struct {
		id        string
		owned     bool
		large     bool
		abandoned bool
	}{
		{id: "control-after-index"},
		{id: "owned-continuation", owned: true, large: true},
		{id: "control-continuation", large: true},
		{id: "control-after-continuation"},
	}...)
	for length := 32500; length <= 32768; length += 4 {
		expected = append(expected, struct {
			id        string
			owned     bool
			large     bool
			abandoned bool
		}{id: fmt.Sprintf("control-prewrite-%d", length), large: true})
	}
	expected = append(expected, []struct {
		id        string
		owned     bool
		large     bool
		abandoned bool
	}{
		{id: "mux-owned-1", owned: true},
		{id: "mux-control-1"},
		{id: "mux-owned-2", owned: true},
		{id: "mux-control-2"},
	}...)
	require.Len(t, run.Results, len(expected))

	caseIDs := map[string]struct{}{}
	controlSpanIDs := map[string]map[string]struct{}{}
	remoteAddr := ""
	multiplexed := false
	ownedCount := 0
	controlCount := 0
	for index, result := range run.Results {
		require.Equal(t, expected[index].id, result.CaseID)
		if expected[index].abandoned {
			require.Equal(t, "forced abandonment before Framer.WriteHeaders", result.Error)
			require.Empty(t, result.Observation.CaseID)
			continue
		}
		require.Empty(t, result.Error, result.CaseID)
		observation := result.Observation
		require.Equal(t, expected[index].id, observation.CaseID)
		_, duplicate := caseIDs[observation.CaseID]
		require.False(t, duplicate, observation.CaseID)
		caseIDs[observation.CaseID] = struct{}{}
		require.Equal(t, 2, observation.ProtoMajor, observation.CaseID)
		require.Len(t, observation.Traceparents, 1, observation.CaseID)
		if remoteAddr == "" {
			remoteAddr = observation.RemoteAddr
		}
		require.Equal(t, remoteAddr, observation.RemoteAddr, observation.CaseID)
		multiplexed = multiplexed || observation.MaxActive >= 2
		if expected[index].large {
			if strings.HasPrefix(observation.CaseID, "control-prewrite-") {
				length, parseErr := strconv.Atoi(strings.TrimPrefix(
					observation.CaseID, "control-prewrite-"))
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

		traceparent := observation.Traceparents[0]
		if expected[index].owned {
			ownedCount++
			require.Equal(t, goHTTP2ApplicationTraceparent, traceparent, observation.CaseID)
			continue
		}

		controlCount++
		parts := strings.Split(traceparent, "-")
		require.Len(t, parts, 4, observation.CaseID)
		require.Len(t, parts[1], 32, observation.CaseID)
		require.NotEqual(t, strings.Repeat("0", 32), parts[1], observation.CaseID)
		if !strings.HasPrefix(observation.CaseID, "mux-") {
			require.Equal(t, strings.Repeat("a", 32), parts[1], observation.CaseID)
		}
		require.Len(t, parts[2], 16, observation.CaseID)
		if controlSpanIDs[parts[1]] == nil {
			controlSpanIDs[parts[1]] = map[string]struct{}{}
		}
		_, duplicate = controlSpanIDs[parts[1]][parts[2]]
		require.False(t, duplicate, observation.CaseID)
		controlSpanIDs[parts[1]][parts[2]] = struct{}{}
	}
	require.Equal(t, 7, ownedCount)
	require.Equal(t, 14+((32768-32500)/4)+1, controlCount)
	require.True(t, multiplexed, "server never handled two streams concurrently")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		after := readGoH2AuditSnapshot(ct)
		assertGoH2AuditCohort(ct, before, after, "http2", len(run.Results), ownedCount,
			"obi_pending", "direct_write")
	}, time.Minute, 250*time.Millisecond, "runtime ownership audit did not reach terminal states")
	require.Positive(t, goH2AuditEventDelta(before, readGoH2AuditSnapshot(t), "http2", "prewrite_write"),
		"near-full HTTP/2 frame never reached the pre-Writer.Write probe")

	for traceID, spanIDs := range controlSpanIDs {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			resp, err := http.Get(jaegerQueryURL + "?service=client&traceID=" + traceID)
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
					if !ok || process.ServiceName != "client" {
						continue
					}
					kind, ok := jaeger.FindIn(span.Tags, "span.kind")
					if ok && kind.Value == "client" {
						exported[span.SpanID] = struct{}{}
					}
				}
			}
			for spanID := range spanIDs {
				_, ok := exported[spanID]
				assert.True(ct, ok, "receiver span ID %s was not an exported client span", spanID)
			}
		}, time.Minute, 250*time.Millisecond)
	}
}

func testGoHTTP2Abandonment(t *testing.T, port int, implementation string) {
	t.Helper()
	before := readGoH2AuditSnapshot(t)
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/run?mode=abandonment", port),
		nil,
	)
	require.NoError(t, err)
	req.Header.Set("traceparent", goHTTP2OuterTraceparent)
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var run goHTTP2RunResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&run))
	require.Equal(t, implementation, run.Implementation)
	require.Len(t, run.Results, 3)
	require.Equal(t, "control-before-abandonment", run.Results[0].CaseID)
	require.Empty(t, run.Results[0].Error)
	require.Equal(t, "owned-abandoned-before-framer", run.Results[1].CaseID)
	require.Equal(t, "forced abandonment before Framer.WriteHeaders", run.Results[1].Error)
	require.Empty(t, run.Results[1].Observation.CaseID)
	require.Equal(t, "control-after-abandonment", run.Results[2].CaseID)
	require.Empty(t, run.Results[2].Error)

	controlSpanIDs := make([]string, 0, 2)
	remoteAddr := ""
	for _, result := range []goHTTP2RunResult{run.Results[0], run.Results[2]} {
		observation := result.Observation
		require.Equal(t, result.CaseID, observation.CaseID)
		require.Equal(t, 2, observation.ProtoMajor)
		require.Len(t, observation.Traceparents, 1, observation.CaseID)
		if remoteAddr == "" {
			remoteAddr = observation.RemoteAddr
		}
		require.NotEmpty(t, observation.RemoteAddr)
		require.Equal(t, remoteAddr, observation.RemoteAddr,
			"abandonment controls did not reuse the same HTTP/2 connection")
		parts := strings.Split(observation.Traceparents[0], "-")
		require.Len(t, parts, 4)
		require.Equal(t, strings.Repeat("a", 32), parts[1])
		require.Len(t, parts[2], 16)
		controlSpanIDs = append(controlSpanIDs, parts[2])
	}
	require.NotEqual(t, controlSpanIDs[0], controlSpanIDs[1])

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		after := readGoH2AuditSnapshot(ct)
		assertGoH2AuditCohort(
			ct, before, after, "http2", 3, 1, "obi_pending", "direct_write")
	}, time.Minute, 250*time.Millisecond)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=client&traceID=" + strings.Repeat("a", 32))
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
				if !ok || process.ServiceName != "client" {
					continue
				}
				kind, ok := jaeger.FindIn(span.Tags, "span.kind")
				if ok && kind.Value == "client" {
					exported[span.SpanID] = struct{}{}
				}
			}
		}
		for _, spanID := range controlSpanIDs {
			_, ok := exported[spanID]
			assert.True(ct, ok, "receiver span ID %s was not an exported client span", spanID)
		}
	}, time.Minute, 250*time.Millisecond)
}

func TestHTTP2GoWithHTTPProtocols(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-http2.yml", path.Join(pathOutput, "test-suite-http2-protocols.log"))
	require.NoError(t, err)

	testHTTP2GO(t, compose, true)
}
