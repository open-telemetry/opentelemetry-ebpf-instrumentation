// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

// yamuxStats mirrors the /stats payload exposed by the yamux component.
type yamuxStats struct {
	Successes  int `json:"successes"`
	Failures   int `json:"failures"`
	Corruption int `json:"corruption"`
}

func getYamuxStats(t require.TestingT, url string) yamuxStats {
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var s yamuxStats
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&s))
	return s
}

// callYamux hits the client's /call endpoint carrying a fresh Traceparent, so
// OBI has an active trace to propagate into the downstream yamux writes — the
// context it tries (and fails) to inject into the tunneled HTTP/2 frames.
func callYamux() {
	now := uint64(time.Now().UnixNano())
	tp := fmt.Sprintf("00-%016x%016x-%016x-01", now, now+1, now+2)
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8081/call", nil)
	if err != nil {
		return
	}
	req.Header.Set("Traceparent", tp)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
}

// TestSuite_YamuxGRPC is a regression test for issue #2706: OBI's sk_msg HPACK
// traceparent injection corrupts an HTTP/2 stream tunneled inside a yamux-
// multiplexed TCP connection (GitLab Gitaly's backchannel wire layout).
//
// The client speaks HTTP/2 by hand over yamux (24-byte preface + synthetic
// HEADERS frames) — deliberately NOT via google.golang.org/grpc, because OBI's
// Go uprobe tracer recognizes real grpc-go client connections and routes their
// propagation through a user-buffer injection that yamux frames correctly (no
// corruption). Gitaly's yamux-tunneled conn is not recognized that way and
// falls through to the raw sk_msg HPACK path — which is what this component
// exercises. See the component's main.go for the full rationale.
//
// Once OBI has discovered and instrumented the processes (so its
// context-propagation sk_msg program is live on their sockets), the test
// asserts the multiplexed stream is NOT corrupted: no stream failures and no
// yamux framing errors. Before the fix, injecting HPACK bytes into the
// separately-written yamux frame bodies desyncs the stream and the counters
// climb.
func TestSuite_YamuxGRPC(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-yamux-grpc.yml", path.Join(pathOutput, "test-suite-yamux-grpc.log"))
	require.NoError(t, err)

	if !KernelLockdownMode() {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`, `OTEL_EBPF_BPF_DEBUG=true`)
	}

	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		if err := compose.Close(); err != nil {
			t.Logf("compose.Close(): %v", err)
		}
	})

	const (
		clientStats = "http://localhost:8081/stats"
		serverStats = "http://localhost:8080/stats"
	)

	// Both roles must be up: /health returns 200 once each HTTP status server
	// is serving.
	waitForTestComponentsNoMetrics(t, "http://localhost:8080/health")
	waitForTestComponentsNoMetrics(t, "http://localhost:8081/health")

	// Gate on OBI actually instrumenting the client process. Driving /call (with
	// a Traceparent) exercises the client's HTTP server AND the downstream yamux
	// path; a yamux-client span appearing in Jaeger proves OBI has discovered
	// the pid and its tracer is live — the precondition for the sk_msg injection
	// path to activate on that process's sockets.
	t.Log("waiting for OBI to instrument yamux-client")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		callYamux()
		r, err := http.Get(jaegerQueryURL + "?service=yamux-client&limit=1&lookback=5m")
		require.NoError(ct, err)
		require.NotNil(ct, r)
		defer r.Body.Close()
		require.Equal(ct, http.StatusOK, r.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(r.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data, "yamux-client not yet instrumented by OBI")
	}, 3*time.Minute, time.Second)
	t.Log("yamux-client instrumented; sk_msg propagation path is now active")

	// Actively drive /call (each carrying a fresh Traceparent) repeated times.
	// Every call opens a fresh connection (fresh HTTP/2 preface, so OBI
	// re-flags the socket) and tunnels several HEADERS frames — each one a
	// traceparent-injection target while OBI has an active trace to propagate.
	const calls = 200
	t.Logf("driving %d Traceparent-carrying calls under active instrumentation", calls)
	for range calls {
		callYamux()
	}

	// wait until at least 90% calls are processed
	var cs, ss yamuxStats
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		cs = getYamuxStats(t, clientStats)
		ss = getYamuxStats(t, serverStats)
		require.GreaterOrEqual(t, cs.Successes+cs.Failures+cs.Corruption, 9*calls/10)
	}, 5*time.Second, 10*time.Millisecond)

	t.Logf("client stats: successes=%d failures=%d corruption=%d", cs.Successes, cs.Failures, cs.Corruption)
	t.Logf("server stats: corruption=%d", ss.Corruption)

	// Sanity: traffic actually flowed during the window.
	require.Positive(t, cs.Successes, "no successful calls during the window — traffic generator stalled")

	// The regression assertions: instrumenting a yamux-multiplexed service must
	// not corrupt its wire protocol.
	require.Zero(t, cs.Failures,
		"downstream calls failed while OBI was instrumenting the yamux connection (issue #2706 wire corruption)")
	require.Zero(t, cs.Corruption,
		"client reported framing corruption (issue #2706)")
	require.Zero(t, ss.Corruption,
		"server reported framing corruption — 'Invalid protocol version' equivalent (issue #2706)")
}
