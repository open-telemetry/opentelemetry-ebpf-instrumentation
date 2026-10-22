// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/pkg/metadata/peer"
)

const (
	peerMetadataServerURL   = "http://localhost:18998" + peer.MetadataPath
	peerMetadataClientURL   = "http://localhost:28998" + peer.MetadataPath
	peerMetadataWorkloadURL = "http://localhost:8081"
)

var peerMetadataHTTPClient = &http.Client{Timeout: 5 * time.Second}

func TestSuite_PeerMetadata(t *testing.T) {
	require.NoError(t, os.MkdirAll(pathOutput, 0o755))
	compose, err := docker.ComposeSuite("docker-compose-peer-metadata.yml",
		path.Join(pathOutput, "test-suite-peer-metadata.log"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	t.Run("inventory includes idle services", testPeerMetadataInventory)
	t.Run("caller observations reject other targets", func(t *testing.T) {
		destination := peerMetadataDestination(t)
		resp, err := peerMetadataHTTPClient.Get(peerMetadataClientURL + "?target=" + url.QueryEscape(destination.IP))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
	t.Run("service graph counts each request once", testPeerMetadataServiceGraph)
	t.Run("traces resolve service identities", func(t *testing.T) {
		testPeerMetadataTraces(t, "unique", "frontend.frontend-ns")
	})
	t.Run("ambiguous callers use the hostname", func(t *testing.T) {
		testPeerMetadataAmbiguousCaller(t, compose)
	})
	t.Run("caller identity recovers after expiry", func(t *testing.T) {
		testPeerMetadataCallers(t, compose, "recovered", []peer.Service{
			{Name: "frontend", Namespace: "frontend-ns", ServiceGraph: true},
		})
		testPeerMetadataTraces(t, "recovered", "frontend.frontend-ns")
	})
	t.Run("client counts requests when peer metrics are disabled", testPeerMetadataWithoutServerMetrics)
}

func testPeerMetadataInventory(t *testing.T) {
	backend := peer.Service{Name: "backend", Namespace: "backend-ns", ServiceGraph: true}
	idle := peer.Service{Name: "idle-backend", Namespace: "backend-ns"}
	frontend := peer.Service{Name: "frontend", Namespace: "frontend-ns", ServiceGraph: true}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		server := peerMetadataSnapshot(ct, peerMetadataServerURL)
		assert.Equal(ct, peer.ProtocolVersion, server.Version)
		assert.Equal(ct, "peer-server-host", server.Hostname)
		assert.ElementsMatch(ct, []peer.Service{backend, idle}, server.Services)
		assert.Contains(ct, server.Listeners, peer.Listener{
			Endpoint: peer.Endpoint{IP: "0.0.0.0", Port: 8082}, Service: idle,
		})
		byPort := peerMetadataSnapshot(ct, peerMetadataServerURL+"?port=8080")
		assert.ElementsMatch(ct, []peer.Listener{{
			Endpoint: peer.Endpoint{IP: "0.0.0.0", Port: 8080}, Service: backend,
		}}, byPort.Listeners)
		client := peerMetadataSnapshot(ct, peerMetadataClientURL)
		assert.Equal(ct, "peer-client-host", client.Hostname)
		assert.ElementsMatch(ct, []peer.Service{frontend}, client.Services)
	}, testTimeout, time.Second)
}

func peerMetadataSnapshot(t require.TestingT, endpoint string) peer.Snapshot {
	resp, err := peerMetadataHTTPClient.Get(endpoint)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var snapshot peer.Snapshot
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&snapshot))
	return snapshot
}

func testPeerMetadataTraces(t *testing.T, phase, caller string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		peerMetadataCall(ct, phase)
		assert.Contains(ct, peerMetadataTracePeers(ct, "frontend", phase, "client"), "backend.backend-ns")
		assert.Contains(ct, peerMetadataTracePeers(ct, "backend", phase, "server"), caller)
	}, testTimeout, time.Second)
}

func peerMetadataCall(t require.TestingT, phase string) {
	resp, err := peerMetadataHTTPClient.Get(peerMetadataWorkloadURL + "/call/" + phase)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func peerMetadataTracePeers(t require.TestingT, service, phase, kind string) []any {
	query := url.Values{"service": {service}, "operation": {"GET /" + phase}, "limit": {"100"}}
	resp, err := getJaeger(jaegerQueryURL + "?" + query.Encode())
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var traces jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&traces))
	key := "service.peer.name"
	if kind == "server" {
		key = "client.address"
	}
	var peers []any
	for _, trace := range traces.Data {
		for _, span := range trace.FindByOperationNameServiceAndKind("GET /"+phase, service, kind) {
			if tag, ok := jaeger.FindIn(span.Tags, key); ok {
				peers = append(peers, tag.Value)
			}
		}
	}
	return peers
}

func testPeerMetadataAmbiguousCaller(t *testing.T, compose *docker.Compose) {
	t.Cleanup(func() {
		peerMetadataComposeCommand(t, compose, "rm", "--force", "--stop", "--volumes", "second-caller")
	})
	peerMetadataComposeCommand(t, compose, "up", "--detach", "--no-build", "second-caller")
	testPeerMetadataCallers(t, compose, "ambiguous", []peer.Service{
		{Name: "frontend", Namespace: "frontend-ns", ServiceGraph: true},
		{Name: "second-caller", Namespace: "frontend-ns", ServiceGraph: true},
	})
	testPeerMetadataTraces(t, "ambiguous", "peer-client-host")
}

func testPeerMetadataCallers(t *testing.T, compose *docker.Compose, phase string, expected []peer.Service) {
	destination := peerMetadataDestination(t)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		peerMetadataCall(ct, phase)
		data := peerMetadataComposeCommand(ct, compose, "exec", "-T", "server", "python", "-c",
			"import sys, urllib.request; print(urllib.request.urlopen(sys.argv[1], timeout=5).read().decode())",
			"http://client:"+strconv.Itoa(peer.DefaultPort)+peer.MetadataPath)
		var snapshot peer.Snapshot
		require.NoError(ct, json.Unmarshal(data, &snapshot))
		var services []peer.Service
		for _, caller := range snapshot.Callers {
			if caller.Destination == destination {
				for _, candidate := range caller.Services {
					services = append(services, candidate.Service)
				}
			}
		}
		assert.ElementsMatch(ct, expected, services)
	}, testTimeout, time.Second)
}

func peerMetadataDestination(t require.TestingT) peer.Endpoint {
	resp, err := peerMetadataHTTPClient.Get(peerMetadataWorkloadURL + "/target")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	destination, err := url.Parse(string(body))
	require.NoError(t, err)
	port, err := strconv.Atoi(destination.Port())
	require.NoError(t, err)
	return peer.Endpoint{IP: destination.Hostname(), Port: port}
}

func peerMetadataComposeCommand(t require.TestingT, compose *docker.Compose, args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-f", compose.Path}, args...)...)
	cmd.Env = compose.Env
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", output)
	return output
}

func testPeerMetadataServiceGraph(t *testing.T) {
	warmCalls := 0
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		peerMetadataCall(ct, "graph-warmup")
		warmCalls++
		assert.Contains(ct, peerMetadataTracePeers(ct, "frontend", "graph-warmup", "client"), "backend.backend-ns")
		assert.Contains(ct, peerMetadataTracePeers(ct, "backend", "graph-warmup", "server"), "frontend.frontend-ns")
	}, testTimeout, time.Second)

	endpoints := []struct {
		url            string
		service        string
		histogram      string
		countsRequests bool
	}{
		{"http://localhost:28999/metrics", "", "traces_service_graph_request_client_seconds_count", false},
		{"http://localhost:18999/metrics", "", "traces_service_graph_request_server_seconds_count", true},
		{"http://localhost:19464/metrics", "frontend", "traces_service_graph_request_client_seconds_count", false},
		{"http://localhost:19464/metrics", "backend", "traces_service_graph_request_server_seconds_count", true},
	}
	baseline := make([]float64, len(endpoints))
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for i, endpoint := range endpoints {
			metrics := peerMetadataGraphMetrics(ct, endpoint.url, endpoint.service, "backend")
			assert.InDelta(ct, float64(warmCalls), metrics[endpoint.histogram], 0, "%s %s", endpoint.url, endpoint.service)
			baseline[i] = metrics["traces_service_graph_request_total"]
		}
	}, testTimeout, 100*time.Millisecond)

	const calls = 5
	for range calls {
		peerMetadataCall(t, "graph-counts")
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for i, endpoint := range endpoints {
			metrics := peerMetadataGraphMetrics(ct, endpoint.url, endpoint.service, "backend")
			assert.InDelta(ct, float64(warmCalls+calls), metrics[endpoint.histogram], 0, "%s %s", endpoint.url, endpoint.service)
			expected := baseline[i]
			if endpoint.countsRequests {
				expected += calls
			}
			assert.InDelta(ct, expected, metrics["traces_service_graph_request_total"], 0, "%s %s", endpoint.url, endpoint.service)
		}
	}, testTimeout, 100*time.Millisecond)
}

func peerMetadataGraphMetrics(t require.TestingT, endpoint, service, server string) map[string]float64 {
	metrics, err := promtest.Scrape(endpoint)
	require.NoError(t, err)
	counts := map[string]float64{}
	for _, metric := range metrics {
		if service != "" && metric.Labels["service_name"] != service {
			continue
		}
		if metric.Name == "traces_service_graph_request_total" &&
			(metric.Labels["client"] != "frontend" || metric.Labels["server"] != server) {
			continue
		}
		counts[metric.Name] += metric.Value
	}
	return counts
}

func testPeerMetadataWithoutServerMetrics(t *testing.T) {
	const calls = 5
	for range calls {
		peerMetadataCall(t, "idle/graph-no-server-metrics")
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, endpoint := range []struct{ url, service string }{
			{"http://localhost:28999/metrics", ""},
			{"http://localhost:19464/metrics", "frontend"},
		} {
			metrics := peerMetadataGraphMetrics(ct, endpoint.url, endpoint.service, "idle-backend")
			assert.InDelta(ct, float64(calls), metrics["traces_service_graph_request_total"], 0, "%s %s", endpoint.url, endpoint.service)
		}
		for _, endpoint := range []struct{ url, service string }{
			{"http://localhost:18999/metrics", ""},
			{"http://localhost:19464/metrics", "idle-backend"},
		} {
			metrics := peerMetadataGraphMetrics(ct, endpoint.url, endpoint.service, "idle-backend")
			assert.Zero(ct, metrics["traces_service_graph_request_total"], "%s %s", endpoint.url, endpoint.service)
		}
	}, testTimeout, 100*time.Millisecond)
}
