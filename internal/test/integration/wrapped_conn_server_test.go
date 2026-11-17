// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path"
	"strconv"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

// TestWrappedConnServerSpans covers #3725: each request must produce one span
// with the accepted connection's addresses, even when its handler reads another socket.
func TestWrappedConnServerSpans(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-wrapped-server.yml", path.Join(pathOutput, "test-suite-wrapped-server.log"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	for _, tc := range []wrappedServerMode{
		{name: "bare-http1", port: 8080, major: 1},
		{name: "wrapped-http1", port: 8081, major: 1},
		{name: "prefixed-http1", port: 8082, major: 1},
		{name: "h2c", port: 8083, h2c: true, major: 2},
		{name: "wrapped-h2c", port: 8084, h2c: true, major: 2},
		{name: "prefixed-h2c", port: 8085, h2c: true, major: 2},
		{name: "bare-tls-http2", port: 8383, tls: true, major: 2},
		{name: "wrapped-tls-http2", port: 8384, tls: true, major: 2},
		{name: "prefixed-tls-http2", port: 8385, tls: true, major: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, keepAlive := range []bool{false, true} {
				t.Run(fmt.Sprintf("keepalive=%t", keepAlive), func(t *testing.T) {
					testWrappedServerSpans(t, tc, keepAlive)
				})
			}
		})
	}
}

type wrappedServerMode struct {
	name  string
	port  int
	h2c   bool
	tls   bool
	major int
}

func testWrappedServerSpans(t *testing.T, tc wrappedServerMode, keepAlive bool) {
	t.Helper()

	transport := &http.Transport{
		DisableKeepAlives: !keepAlive,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}
	if tc.h2c {
		transport.Protocols = new(http.Protocols)
		transport.Protocols.SetUnencryptedHTTP2(true)
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	scheme := "http"
	if tc.tls {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://localhost:%d", scheme, tc.port)
	require.Eventually(t, func() bool {
		resp, err := client.Get(baseURL + "/ready")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK && hasSpansInJaeger("wrappedconnserver")
	}, 2*time.Minute, time.Second)
	client.CloseIdleConnections()

	observations := map[string]struct{ Local, Remote string }{}
	peers := map[string]struct{}{}
	for i := range 20 {
		requestPath := fmt.Sprintf("/%s/%t/%d", tc.name, keepAlive, i)
		resp, err := client.Get(baseURL + requestPath)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, tc.major, resp.ProtoMajor)
		var observed struct{ Local, Remote string }
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&observed))
		require.NoError(t, resp.Body.Close())
		observations[requestPath] = observed
		peers[observed.Remote] = struct{}{}
	}
	client.CloseIdleConnections()
	if keepAlive {
		require.Len(t, peers, 1, "requests must reuse one connection")
	} else {
		require.Len(t, peers, len(observations), "each request must open a connection")
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		spansByPath := serverSpansByPath(ct, "wrappedconnserver")
		for requestPath, observed := range observations {
			spans := spansByPath[requestPath]
			if !assert.Len(ct, spans, 1, "one server span for %s", requestPath) {
				continue
			}
			host, port, err := net.SplitHostPort(observed.Remote)
			require.NoError(ct, err)
			peerPort, err := strconv.Atoi(port)
			require.NoError(ct, err)
			assert.Empty(ct, spans[0].Diff(
				jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(tc.port)},
				jaeger.Tag{Key: "network.peer.address", Type: "string", Value: host},
				jaeger.Tag{Key: "network.peer.port", Type: "int64", Value: float64(peerPort)},
			), requestPath)
		}
	}, 30*time.Second, time.Second)
	assert.Never(t, func() bool {
		spansByPath := serverSpansByPath(t, "wrappedconnserver")
		for requestPath := range observations {
			if len(spansByPath[requestPath]) > 1 {
				return true
			}
		}
		return false
	}, 2*time.Second, 200*time.Millisecond, "delayed generic events must not duplicate server spans")
}

func serverSpansByPath(t require.TestingT, service string) map[string][]jaeger.Span {
	resp, err := getJaeger(jaegerQueryURL + "?service=" + service + "&limit=1500")
	require.NoError(t, err)
	defer resp.Body.Close()
	var query jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&query))
	spansByPath := map[string][]jaeger.Span{}
	for _, trace := range query.Data {
		for _, span := range trace.Spans {
			if spanKind(span) == "server" && trace.Processes[span.ProcessID].ServiceName == service {
				if tag, ok := jaeger.FindIn(span.Tags, "url.path"); ok {
					spansByPath[fmt.Sprint(tag.Value)] = append(spansByPath[fmt.Sprint(tag.Value)], span)
				}
			}
		}
	}
	return spansByPath
}
