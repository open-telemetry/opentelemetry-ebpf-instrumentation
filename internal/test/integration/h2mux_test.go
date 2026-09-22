// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// Several bursts per mode must pass, so one lucky burst can't pass the test alone.
const h2muxMinBursts = 3

// h2muxStreams is how many streams each side sends in one write. The compose
// file passes it to both programs. Raise it to find how many streams OBI can
// read from one buffer.
var h2muxStreams = envInt("H2MUX_STREAMS", 5)

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return value
}

// h2muxBurstRecord is what the h2mux client and server print for each burst.
type h2muxBurstRecord struct {
	Burst                string          `json:"burst"`
	Mode                 string          `json:"mode"`
	Conn                 string          `json:"conn"`
	Index                int             `json:"index"`
	ReqHeadersInOneRead  int             `json:"req_headers_in_one_read"`
	RespHeadersInOneRead int             `json:"resp_headers_in_one_read"`
	Exchanges            []h2muxExchange `json:"exchanges"`
	Error                string          `json:"error"`
}

type h2muxExchange struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

// h2muxBurst is one burst as both sides saw it.
type h2muxBurst struct {
	client h2muxBurstRecord
	server h2muxBurstRecord
}

// sharedOneBuffer reports whether all streams of this burst really went
// through one buffer in both directions. Without this check the test could
// pass on traffic that never put two streams in one buffer, which is how this
// bug went unnoticed in the older gRPC tests.
func (b *h2muxBurst) sharedOneBuffer() bool {
	if b.client.Burst == "" || b.server.Burst == "" {
		return false
	}
	if b.client.Error != "" || b.server.Error != "" {
		return false
	}

	// gRPC sends two HEADERS frames per stream: the headers and the trailers.
	responseHeaders := h2muxStreams
	if b.client.Mode == modeGRPC {
		responseHeaders = 2 * h2muxStreams
	}

	return b.server.ReqHeadersInOneRead == h2muxStreams &&
		b.client.RespHeadersInOneRead == responseHeaders
}

const (
	modeHTTP = "http"
	modeGRPC = "grpc"
)

// TestSuite_HTTP2Multiplexing checks that when many HTTP/2 streams share one
// buffer, every stream is captured with the right method, path and status.
//
// Both sides send a whole burst of streams with one write and report how many
// of them the other side got from a single read, so the test only checks bursts
// that really shared one buffer. It covers plain HTTP/2 and gRPC, where the
// status comes in trailers after the body. The checked values are only right
// if OBI's HPACK tables stay in sync with the peers'.
func TestSuite_HTTP2Multiplexing(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-h2mux.yml", path.Join(pathOutput, "test-suite-h2mux.log"))
	require.NoError(t, err)

	// the client and server must send as many streams per write as the test expects
	compose.Env = append(compose.Env, "H2MUX_STREAMS="+strconv.Itoa(h2muxStreams))

	if !KernelLockdownMode() {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		if err := compose.Close(); err != nil {
			t.Logf("compose.Close(): %v", err)
		}
	})

	require.Eventually(t, func() bool {
		return hasSpansInJaeger("h2mux-server") && hasSpansInJaeger("h2mux-client")
	}, 3*time.Minute, time.Second, "OBI did not instrument the h2mux workloads")

	// Connections opened before OBI started can't be used: OBI detects HTTP/2
	// from the connection preface and only tracks HPACK tables for connections
	// it saw open.
	established := h2muxConnections(t, compose)

	bursts := h2muxCollectBursts(t, compose, established)

	for _, mode := range []string{modeHTTP, modeGRPC} {
		t.Run(mode, func(t *testing.T) {
			for _, burst := range bursts[mode] {
				h2muxAssertBurstCaptured(t, burst)
			}
		})
	}
}

// h2muxConnections returns the client connection ids seen so far.
func h2muxConnections(t *testing.T, compose *docker.Compose) map[string]struct{} {
	t.Helper()

	logs, err := compose.LogsTail(5000, "h2mux-client")
	require.NoError(t, err)

	seen := map[string]struct{}{}
	for _, record := range h2muxParseRecords(logs, "H2MUX_CLIENT ") {
		seen[record.Conn] = struct{}{}
	}
	return seen
}

// h2muxCollectBursts waits for enough bursts per mode that went through one
// buffer, on connections opened after OBI started. The first burst of each
// connection is skipped, so the HPACK tables are already in use.
func h2muxCollectBursts(t *testing.T, compose *docker.Compose, established map[string]struct{}) map[string][]h2muxBurst {
	t.Helper()

	collected := map[string][]h2muxBurst{}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		clientLogs, err := compose.LogsTail(5000, "h2mux-client")
		require.NoError(ct, err)
		serverLogs, err := compose.LogsTail(5000, "h2mux-server")
		require.NoError(ct, err)

		servers := map[string]h2muxBurstRecord{}
		for _, record := range h2muxParseRecords(serverLogs, "H2MUX_SERVER ") {
			servers[record.Burst] = record
		}

		usable, shared := 0, map[string][]h2muxBurst{}
		for _, record := range h2muxParseRecords(clientLogs, "H2MUX_CLIENT ") {
			if _, old := established[record.Conn]; old || record.Index == 0 {
				continue
			}
			usable++
			burst := h2muxBurst{client: record, server: servers[record.Burst]}
			if burst.sharedOneBuffer() {
				shared[record.Mode] = append(shared[record.Mode], burst)
			}
		}

		for _, mode := range []string{modeHTTP, modeGRPC} {
			require.GreaterOrEqualf(ct, len(shared[mode]), h2muxMinBursts,
				"%s: only %d of %d usable bursts sent all %d streams in one buffer; "+
					"the test condition was not met",
				mode, len(shared[mode]), usable, h2muxStreams)
		}
		collected = shared
	}, 3*time.Minute, 2*time.Second)

	return collected
}

// h2muxOperation matches OBI's span names for these requests: "<METHOD> <path>"
// for HTTP, just the path for gRPC.
var h2muxOperation = regexp.MustCompile(`^(?:([A-Z]+) )?(/burst/\d+/stream/\d+)$`)

// h2muxAssertBurstCaptured checks that every stream of one burst shows up on
// both sides with the values the peers really sent.
func h2muxAssertBurstCaptured(t *testing.T, burst h2muxBurst) {
	t.Helper()

	for _, service := range []string{"h2mux-server", "h2mux-client"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			spans := h2muxSpansByPath(ct, service, burst.client.Burst)

			for _, want := range burst.client.Exchanges {
				span, found := spans[want.Path]
				require.Truef(ct, found, "%s: burst %s stream %s was not captured (%d of %d streams captured)",
					service, burst.client.Burst, want.Path, len(spans), len(burst.client.Exchanges))
				h2muxAssertSpanMatches(ct, service, burst.client.Mode, span, want)
			}
		}, time.Minute, 2*time.Second)
	}
}

// h2muxAssertSpanMatches checks values that are only right when OBI's HPACK
// tables stayed in sync with the peers' for the whole burst.
func h2muxAssertSpanMatches(ct *assert.CollectT, service, mode string, span jaeger.Span, want h2muxExchange) {
	expected := []jaeger.Tag{
		{Key: "http.response.status_code", Type: "int64", Value: float64(want.Status)},
		{Key: "http.request.method", Type: "string", Value: want.Method},
	}
	if mode == modeGRPC {
		expected = []jaeger.Tag{
			{Key: "rpc.response.status_code", Type: "string", Value: request.GRPCStatusCodeString(want.Status)},
		}
	}

	diff := span.Diff(expected...)
	require.Emptyf(ct, diff, "%s: %s %s", service, want.Path, diff)
}

// h2muxSpansByPath returns the service's spans for one burst, by request path.
func h2muxSpansByPath(ct *assert.CollectT, service, burstID string) map[string]jaeger.Span {
	resp, err := getJaeger(fmt.Sprintf("%s?service=%s&limit=2000&lookback=10m", jaegerQueryURL, service))
	require.NoError(ct, err)
	defer resp.Body.Close()
	require.Equal(ct, http.StatusOK, resp.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

	prefix := "/burst/" + burstID + "/"
	spans := map[string]jaeger.Span{}
	for _, trace := range tq.Data {
		for _, span := range trace.Spans {
			if process, ok := trace.Processes[span.ProcessID]; !ok || process.ServiceName != service {
				continue
			}
			match := h2muxOperation.FindStringSubmatch(span.OperationName)
			if match == nil || !strings.HasPrefix(match[2], prefix) {
				continue
			}
			spans[match[2]] = span
		}
	}
	return spans
}

func h2muxParseRecords(logs, prefix string) []h2muxBurstRecord {
	var records []h2muxBurstRecord
	for line := range strings.SplitSeq(logs, "\n") {
		_, payload, found := strings.Cut(line, prefix)
		if !found {
			continue
		}
		var record h2muxBurstRecord
		if json.Unmarshal([]byte(payload), &record) == nil {
			records = append(records, record)
		}
	}
	return records
}
