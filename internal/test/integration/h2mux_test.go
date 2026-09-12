// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

// h2muxStreams is the streams per burst, kept within the frame scanner's
// per-buffer budget (~6) so a correct scanner captures the whole burst.
const h2muxStreams = 5

// minFullyCapturedBursts guards against one lucky burst passing the assertion.
const minFullyCapturedBursts = 5

// TestSuite_HTTP2Multiplexing checks that the generic tracer captures every
// stream of a densely multiplexed HTTP/2 connection. The client sends
// h2muxStreams requests in one write and the server replies to them in one
// write, forcing many streams into a single read/write buffer — the condition
// that used to collapse span capture. Both the server and client side must show
// fully-captured bursts and no partially-captured burst.
func TestSuite_HTTP2Multiplexing(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-h2mux.yml", path.Join(pathOutput, "test-suite-h2mux.log"))
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

	require.Eventually(t, func() bool {
		return hasSpansInJaeger("h2mux-server") && hasSpansInJaeger("h2mux-client")
	}, 90*time.Second, time.Second, "OBI did not instrument the h2mux workloads")

	// Retrying lets warm-up bursts (uprobe not yet attached) age out of the
	// lookback window, leaving a clean window of fully-captured bursts.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assertBurstsFullyCaptured(ct, "h2mux-server", "server")
		assertBurstsFullyCaptured(ct, "h2mux-client", "client")
	}, 90*time.Second, 2*time.Second)
}

func assertBurstsFullyCaptured(ct *assert.CollectT, service, kind string) {
	full, partial := capturedBurstStats(ct, service, kind)
	require.Zero(ct, partial,
		"%s: %d burst(s) had streams dropped within a multiplexed buffer", service, partial)
	require.GreaterOrEqual(ct, full, minFullyCapturedBursts,
		"%s: only %d burst(s) fully captured, want >= %d", service, full, minFullyCapturedBursts)
}

var burstPathRe = regexp.MustCompile(`/burst/(\d+)/stream/(\d+)`)

// capturedBurstStats groups a side's spans by burst id and counts bursts whose
// h2muxStreams streams were all captured (full) versus only some (partial).
func capturedBurstStats(ct *assert.CollectT, service, kind string) (full, partial int) {
	resp, err := http.Get(jaegerQueryURL + "?service=" + service + "&limit=500&lookback=30s")
	require.NoError(ct, err)
	defer resp.Body.Close()
	require.Equal(ct, http.StatusOK, resp.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
	require.NotEmpty(ct, tq.Data, "no %s traces in jaeger yet", service)

	streamsByBurst := map[string]map[string]struct{}{}
	for _, trace := range tq.Data {
		for _, s := range trace.Spans {
			proc, ok := trace.Processes[s.ProcessID]
			if !ok || proc.ServiceName != service {
				continue
			}
			if tag, ok := jaeger.FindIn(s.Tags, "span.kind"); !ok || tag.Value != kind {
				continue
			}
			m := burstPathRe.FindStringSubmatch(s.OperationName)
			if m == nil {
				continue
			}
			burstID, streamIdx := m[1], m[2]
			if streamsByBurst[burstID] == nil {
				streamsByBurst[burstID] = map[string]struct{}{}
			}
			streamsByBurst[burstID][streamIdx] = struct{}{}
		}
	}
	for _, streams := range streamsByBurst {
		if len(streams) >= h2muxStreams {
			full++
		} else {
			partial++
		}
	}
	return full, partial
}
