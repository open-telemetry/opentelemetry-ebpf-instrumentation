// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"errors"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/metadata/peer"
	"go.opentelemetry.io/obi/pkg/metadata/peer/metadatapb"
)

const (
	peerMetadataServerAddress = "localhost:18998"
	peerMetadataClientAddress = "localhost:28998"
	peerMetadataWorkloadURL   = "http://localhost:8081"
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
	t.Run("service graph counts each request once", func(t *testing.T) {
		testPeerMetadataServiceGraph(t, true)
	})
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

func TestSuite_PeerMetadataHTTPMetricsDisabled(t *testing.T) {
	require.NoError(t, os.MkdirAll(pathOutput, 0o755))
	compose, err := docker.ComposeSuite("docker-compose-peer-metadata.yml",
		path.Join(pathOutput, "test-suite-peer-metadata-http-metrics-disabled.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, "PEER_METADATA_SERVER_CONFIG=obi-config-peer-metadata-server-http-traces-only-v2.yml")
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	t.Run("inventory includes instrumented services", testPeerMetadataInventory)
	t.Run("metadata advertises protocol eligibility", func(t *testing.T) {
		snapshot := peerMetadataSnapshot(t, peerMetadataServerAddress)
		require.NotNil(t, snapshot.MetricProtocols)
		protocols := instrumentations.InstrumentationSelection(snapshot.GetMetricProtocols())
		require.False(t, protocols.HTTPEnabled())
		require.True(t, protocols.GRPCEnabled())
	})
	t.Run("client counts HTTP requests", func(t *testing.T) {
		testPeerMetadataServiceGraph(t, false)
	})
	t.Run("HTTP traces still resolve both services", func(t *testing.T) {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			assert.Contains(ct, peerMetadataTracePeers(ct, "frontend", "graph-counts", "client"), "backend.backend-ns")
			assert.Contains(ct, peerMetadataTracePeers(ct, "backend", "graph-counts", "server"), "frontend.frontend-ns")
		}, testTimeout, time.Second)
	})
}

func TestSuite_PeerMetadataCentral(t *testing.T) {
	require.NoError(t, os.MkdirAll(pathOutput, 0o755))
	compose, err := docker.ComposeSuite("docker-compose-peer-metadata.yml",
		path.Join(pathOutput, "test-suite-peer-metadata-central.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env,
		"COMPOSE_PROFILES=central",
		"PEER_METADATA_SERVER_CONFIG=obi-config-peer-metadata-server-central-v2.yml",
		"PEER_METADATA_CLIENT_CONFIG=obi-config-peer-metadata-client-central-v2.yml")
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	t.Run("metadata service stores the published inventory", func(t *testing.T) {
		testPeerMetadataCentralInventory(t, compose)
	})
	t.Run("service graph counts each request once", func(t *testing.T) {
		testPeerMetadataServiceGraph(t, true)
	})
	t.Run("traces resolve service identities", func(t *testing.T) {
		testPeerMetadataTraces(t, "central", "frontend.frontend-ns")
	})
}

// testPeerMetadataCentralInventory looks up the server host in the metadata service.
func testPeerMetadataCentralInventory(t *testing.T, compose *docker.Compose) {
	backend := peer.Service{Name: "backend", Namespace: "backend-ns", ServiceGraph: true}
	idle := peer.Service{Name: "idle-backend", Namespace: "backend-ns"}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// The workload may not accept connections yet when the suite starts.
		request, err := json.Marshal(map[string]string{"address": peerMetadataDestination(ct).IP})
		require.NoError(ct, err)
		data := peerMetadataComposeOutput(ct, compose, "run", "--rm", "--no-deps", "server-grpcurl",
			"-plaintext", "-import-path", "/proto", "-proto", "metadata.proto", "-d", string(request),
			"metadata-service:8999", "metadata.MetadataService/Lookup")
		var response metadatapb.LookupResponse
		require.NoError(ct, protojson.Unmarshal(data, &response))
		assert.Equal(ct, "peer-server-host", response.GetSnapshot().GetHostname())
		assert.ElementsMatch(ct, []peer.Service{backend, idle}, peerMetadataServices(response.GetSnapshot().GetServices()))
	}, testTimeout, time.Second)
}

func testPeerMetadataInventory(t *testing.T) {
	backend := peer.Service{Name: "backend", Namespace: "backend-ns", ServiceGraph: true}
	idle := peer.Service{Name: "idle-backend", Namespace: "backend-ns"}
	frontend := peer.Service{Name: "frontend", Namespace: "frontend-ns", ServiceGraph: true}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		server := peerMetadataSnapshot(ct, peerMetadataServerAddress)
		assert.Equal(ct, "peer-server-host", server.GetHostname())
		assert.ElementsMatch(ct, []peer.Service{backend, idle}, peerMetadataServices(server.GetServices()))
		listeners := peerMetadataListeners(server.GetListeners())
		assert.Contains(ct, listeners, peer.Listener{
			Endpoint: peer.Endpoint{IP: "0.0.0.0", Port: 8082}, Service: idle,
		})
		assert.Contains(ct, listeners, peer.Listener{
			Endpoint: peer.Endpoint{IP: "0.0.0.0", Port: 8080}, Service: backend,
		})
		client := peerMetadataSnapshot(ct, peerMetadataClientAddress)
		assert.Equal(ct, "peer-client-host", client.GetHostname())
		assert.ElementsMatch(ct, []peer.Service{frontend}, peerMetadataServices(client.GetServices()))
	}, testTimeout, time.Second)
}

func peerMetadataSnapshot(t require.TestingT, address string) *metadatapb.Snapshot {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := metadatapb.NewPeerMetadataServiceClient(conn).GetSnapshot(ctx, &metadatapb.GetSnapshotRequest{})
	require.NoError(t, err)
	return snapshot
}

func peerMetadataService(service *metadatapb.Service) peer.Service {
	return peer.Service{Name: service.GetName(), Namespace: service.GetNamespace(), ServiceGraph: service.GetServiceGraph()}
}

func peerMetadataServices(services []*metadatapb.Service) []peer.Service {
	converted := make([]peer.Service, 0, len(services))
	for _, service := range services {
		converted = append(converted, peerMetadataService(service))
	}
	return converted
}

func peerMetadataEndpoint(endpoint *metadatapb.Endpoint) peer.Endpoint {
	return peer.Endpoint{IP: endpoint.GetIp(), Port: int(endpoint.GetPort())}
}

func peerMetadataListeners(listeners []*metadatapb.Listener) []peer.Listener {
	converted := make([]peer.Listener, 0, len(listeners))
	for _, listener := range listeners {
		converted = append(converted, peer.Listener{
			Endpoint: peerMetadataEndpoint(listener.GetEndpoint()),
			Service:  peerMetadataService(listener.GetService()),
		})
	}
	return converted
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
		data := peerMetadataComposeOutput(ct, compose, "run", "--rm", "--no-deps", "server-grpcurl",
			"-plaintext", "-import-path", "/proto", "-proto", "metadata.proto", "-d", "{}",
			"client:"+strconv.Itoa(peer.DefaultPort), "metadata.PeerMetadataService/GetSnapshot")
		var snapshot metadatapb.Snapshot
		require.NoError(ct, protojson.Unmarshal(data, &snapshot))
		var services []peer.Service
		for _, caller := range snapshot.GetCallers() {
			if peerMetadataEndpoint(caller.GetDestination()) == destination {
				for _, candidate := range caller.GetServices() {
					services = append(services, peerMetadataService(candidate.GetService()))
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

func peerMetadataComposeCommand(t require.TestingT, compose *docker.Compose, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-f", compose.Path}, args...)...)
	cmd.Env = compose.Env
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", output)
}

// peerMetadataComposeOutput returns the standard output of a compose command, which must not include compose logs.
func peerMetadataComposeOutput(t require.TestingT, compose *docker.Compose, args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-f", compose.Path}, args...)...)
	cmd.Env = compose.Env
	output, err := cmd.Output()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		require.NoError(t, err, "%s", exitErr.Stderr)
	}
	require.NoError(t, err)
	return output
}

func testPeerMetadataServiceGraph(t *testing.T, serverMetrics bool) {
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
		hasHistogram   bool
	}{
		{"http://localhost:28999/metrics", "", "traces_service_graph_request_client_seconds_count", !serverMetrics, true},
		{"http://localhost:18999/metrics", "", "traces_service_graph_request_server_seconds_count", serverMetrics, serverMetrics},
		{"http://localhost:19464/metrics", "frontend", "traces_service_graph_request_client_seconds_count", !serverMetrics, true},
		{"http://localhost:19464/metrics", "backend", "traces_service_graph_request_server_seconds_count", serverMetrics, serverMetrics},
	}
	baseline := make([]float64, len(endpoints))
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for i, endpoint := range endpoints {
			metrics := peerMetadataGraphMetrics(ct, endpoint.url, endpoint.service, "backend")
			var expectedHistogram float64
			if endpoint.hasHistogram {
				expectedHistogram = float64(warmCalls)
			}
			assert.InDelta(ct, expectedHistogram, metrics[endpoint.histogram], 0, "%s %s", endpoint.url, endpoint.service)
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
			var expectedHistogram float64
			if endpoint.hasHistogram {
				expectedHistogram = float64(warmCalls + calls)
			}
			assert.InDelta(ct, expectedHistogram, metrics[endpoint.histogram], 0, "%s %s", endpoint.url, endpoint.service)
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
