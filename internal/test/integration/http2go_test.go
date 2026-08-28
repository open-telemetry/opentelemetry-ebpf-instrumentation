// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"regexp"
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
	http2OwnedTraceparent = "00-11111111111111111111111111111111-2222222222222222-01"
	http2MuxTraceparent   = "00-33333333333333333333333333333333-4444444444444444-01"
)

var http2TraceparentPattern = regexp.MustCompile(`^00-[[:xdigit:]]{32}-[[:xdigit:]]{16}-[[:xdigit:]]{2}$`)

type http2HeaderObservation struct {
	Traceparents []string `json:"traceparents"`
	RemoteAddr   string   `json:"remote_addr"`
	Protocol     string   `json:"protocol"`
}

type http2OwnershipResult struct {
	Transport string                   `json:"transport"`
	Repeated  []http2HeaderObservation `json:"repeated"`
	Controls  []http2HeaderObservation `json:"controls"`
	MuxOwned  http2HeaderObservation   `json:"mux_owned"`
	MuxPlain  http2HeaderObservation   `json:"mux_plain"`
	Error     string                   `json:"error"`
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
	require.Len(t, res, 1)
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

	if !lockdown {
		t.Run("Go HTTP/2 application traceparent ownership", func(t *testing.T) {
			testHTTP2TraceparentOwnership(t, compose)
		})
	}

	require.NoError(t, compose.Close())
}

func testHTTP2TraceparentOwnership(t *testing.T, compose *docker.Compose) {
	resp, err := http.Get("http://localhost:7575/run")
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.NoError(t, resp.Body.Close())

	for _, transport := range []string{"tls", "plaintext"} {
		t.Run(transport, func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				logs, err := compose.LogsTail(1000, "testclient")
				require.NoError(ct, err)

				lastErr := fmt.Errorf("no %s ownership result logged", transport)
				for _, result := range parseHTTP2OwnershipResults(logs) {
					if result.Transport != transport {
						continue
					}
					if err := validateHTTP2OwnershipResult(result); err == nil {
						return
					} else {
						lastErr = err
					}
				}
				require.NoError(ct, lastErr, "no valid %s ownership result", transport)
			}, time.Minute, time.Second)
		})
	}
}

func parseHTTP2OwnershipResults(logs string) []http2OwnershipResult {
	const prefix = "HTTP2_OWNERSHIP_RESULT "
	var results []http2OwnershipResult
	for line := range strings.SplitSeq(logs, "\n") {
		start := strings.Index(line, prefix)
		if start < 0 {
			continue
		}
		var result http2OwnershipResult
		if json.Unmarshal([]byte(line[start+len(prefix):]), &result) == nil {
			results = append(results, result)
		}
	}
	return results
}

func validateHTTP2OwnershipResult(result http2OwnershipResult) error {
	if result.Error != "" {
		return fmt.Errorf("client error: %s", result.Error)
	}
	if len(result.Repeated) != 4 {
		return fmt.Errorf("repeated request count: got %d, want 4", len(result.Repeated))
	}

	remoteAddr := result.Repeated[0].RemoteAddr
	for i, observation := range result.Repeated {
		if err := validateHTTP2Observation(observation, http2OwnedTraceparent); err != nil {
			return fmt.Errorf("repeated request %d: %w", i, err)
		}
		if observation.RemoteAddr != remoteAddr {
			return fmt.Errorf("repeated request %d used %q, want persistent connection %q",
				i, observation.RemoteAddr, remoteAddr)
		}
	}

	if len(result.Controls) != 2 {
		return fmt.Errorf("control request count: got %d, want 2", len(result.Controls))
	}
	for i, observation := range result.Controls {
		if err := validateHTTP2InjectedObservation(observation); err != nil {
			return fmt.Errorf("control request %d: %w", i, err)
		}
	}

	if err := validateHTTP2Observation(result.MuxOwned, http2MuxTraceparent); err != nil {
		return fmt.Errorf("owned multiplexed request: %w", err)
	}
	if err := validateHTTP2InjectedObservation(result.MuxPlain); err != nil {
		return fmt.Errorf("plain multiplexed request: %w", err)
	}
	if result.MuxOwned.RemoteAddr != result.MuxPlain.RemoteAddr ||
		result.MuxOwned.RemoteAddr != remoteAddr {
		return fmt.Errorf("multiplexed requests did not share persistent connection %q: owned=%q plain=%q",
			remoteAddr, result.MuxOwned.RemoteAddr, result.MuxPlain.RemoteAddr)
	}
	return nil
}

func validateHTTP2Observation(observation http2HeaderObservation, want string) error {
	if observation.Protocol != "HTTP/2.0" {
		return fmt.Errorf("protocol: got %q, want HTTP/2.0", observation.Protocol)
	}
	if len(observation.Traceparents) != 1 || observation.Traceparents[0] != want {
		return fmt.Errorf("traceparents: got %q, want [%s]", observation.Traceparents, want)
	}
	return nil
}

func validateHTTP2InjectedObservation(observation http2HeaderObservation) error {
	if observation.Protocol != "HTTP/2.0" {
		return fmt.Errorf("protocol: got %q, want HTTP/2.0", observation.Protocol)
	}
	if len(observation.Traceparents) != 1 {
		return fmt.Errorf("traceparent count: got %d, want 1 (%q)",
			len(observation.Traceparents), observation.Traceparents)
	}
	traceparent := observation.Traceparents[0]
	if !http2TraceparentPattern.MatchString(traceparent) {
		return fmt.Errorf("invalid injected traceparent %q", traceparent)
	}
	if traceparent == http2OwnedTraceparent || traceparent == http2MuxTraceparent {
		return fmt.Errorf("owned traceparent leaked into unowned stream: %q", traceparent)
	}
	return nil
}

func TestHTTP2GoWithHTTPProtocols(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-http2.yml", path.Join(pathOutput, "test-suite-http2-protocols.log"))
	require.NoError(t, err)

	testHTTP2GO(t, compose, true)
}
