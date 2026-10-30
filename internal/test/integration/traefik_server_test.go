// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
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

// TestTraefikServerSpans reproduces the Traefik cases in #3725: 20 requests on
// separate connections must yield 20 correctly attributed server spans.
func TestTraefikServerSpans(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-traefik-server.yml", path.Join(pathOutput, "test-suite-traefik-server.log"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	for _, tc := range []struct {
		name       string
		url        string
		service    string
		serverPort int
		protoMajor int
		direct     bool
	}{
		{name: "http1", url: "http://localhost:18080", service: "traefik-validation", serverPort: 8080, protoMajor: 1},
		{name: "tls-http2", url: "https://localhost:18443", service: "traefik-validation", serverPort: 8443, protoMajor: 2},
		{name: "direct-tls-http2", url: "https://localhost:18383", service: "traefik-backend", serverPort: 8383, protoMajor: 2, direct: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{
				Transport: &http.Transport{
					DisableKeepAlives: true,
					ForceAttemptHTTP2: true,
					TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				},
				Timeout: 5 * time.Second,
			}
			defer client.CloseIdleConnections()
			require.Eventually(t, func() bool {
				resp, err := client.Get(tc.url + "/ready")
				if err != nil {
					return false
				}
				resp.Body.Close()
				return resp.StatusCode == http.StatusOK && hasSpansInJaeger(tc.service)
			}, 2*time.Minute, time.Second)

			peers := map[string]string{}
			for i := range 20 {
				requestPath := fmt.Sprintf("/traefik-%s/%d", tc.name, i)
				resp, err := client.Get(tc.url + requestPath)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, tc.protoMajor, resp.ProtoMajor)
				var observed struct{ Remote string }
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&observed))
				_, err = io.Copy(io.Discard, resp.Body)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				peers[requestPath] = observed.Remote
			}
			if !tc.direct {
				peers = traefikClientAddresses(t, compose, peers)
			}
			connections := map[string]struct{}{}
			for _, peer := range peers {
				connections[peer] = struct{}{}
			}
			require.Len(t, connections, len(peers), "each request must use a separate connection")

			checkSpans := func(ct *assert.CollectT) {
				spans := serverSpansByPath(ct, tc.service)
				for requestPath, peer := range peers {
					if !assert.Len(ct, spans[requestPath], 1, "one server span for %s", requestPath) {
						continue
					}
					host, port, err := net.SplitHostPort(peer)
					require.NoError(ct, err)
					peerPort, err := strconv.Atoi(port)
					require.NoError(ct, err)
					assert.Empty(ct, spans[requestPath][0].Diff(
						jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(tc.serverPort)},
						jaeger.Tag{Key: "network.peer.address", Type: "string", Value: host},
						jaeger.Tag{Key: "network.peer.port", Type: "int64", Value: float64(peerPort)},
					), requestPath)
				}
			}
			require.EventuallyWithT(t, checkSpans, 30*time.Second, time.Second)
			time.Sleep(2 * time.Second)
			require.EventuallyWithT(t, checkSpans, time.Second, 100*time.Millisecond)
		})
	}
}

func traefikClientAddresses(t *testing.T, compose *docker.Compose, requests map[string]string) map[string]string {
	t.Helper()

	peers := map[string]string{}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(200, "traefik-validation")
		require.NoError(ct, err)
		for line := range strings.SplitSeq(logs, "\n") {
			start := strings.IndexByte(line, '{')
			if start < 0 {
				continue
			}
			var entry struct{ RequestPath, ClientAddr string }
			if json.Unmarshal([]byte(line[start:]), &entry) != nil {
				continue
			}
			if _, ok := requests[entry.RequestPath]; ok {
				assert.NotEmpty(ct, entry.ClientAddr)
				peers[entry.RequestPath] = entry.ClientAddr
			}
		}
		require.Len(ct, peers, len(requests), "Traefik must log every incoming request")
	}, 10*time.Second, 100*time.Millisecond)
	return peers
}
