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
	t.Run("traces resolve service identities", func(t *testing.T) {
		testPeerMetadataTraces(t, "unique", "frontend.frontend-ns")
	})
	t.Run("ambiguous callers use the hostname", func(t *testing.T) {
		testPeerMetadataAmbiguousCaller(t, compose)
	})
	t.Run("caller identity recovers after expiry", func(t *testing.T) {
		testPeerMetadataCallers(t, "recovered", []peer.Service{
			{Name: "frontend", Namespace: "frontend-ns"},
		})
		testPeerMetadataTraces(t, "recovered", "frontend.frontend-ns")
	})
}

func testPeerMetadataInventory(t *testing.T) {
	backend := peer.Service{Name: "backend", Namespace: "backend-ns"}
	idle := peer.Service{Name: "idle-backend", Namespace: "backend-ns"}
	frontend := peer.Service{Name: "frontend", Namespace: "frontend-ns"}
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
	testPeerMetadataCallers(t, "ambiguous", []peer.Service{
		{Name: "frontend", Namespace: "frontend-ns"},
		{Name: "second-caller", Namespace: "frontend-ns"},
	})
	testPeerMetadataTraces(t, "ambiguous", "peer-client-host")
}

func testPeerMetadataCallers(t *testing.T, phase string, expected []peer.Service) {
	destination := peerMetadataDestination(t)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		peerMetadataCall(ct, phase)
		snapshot := peerMetadataSnapshot(ct, peerMetadataClientURL+"?target="+url.QueryEscape(destination.IP))
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

func peerMetadataComposeCommand(t require.TestingT, compose *docker.Compose, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-f", compose.Path}, args...)...)
	cmd.Env = compose.Env
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", output)
}
