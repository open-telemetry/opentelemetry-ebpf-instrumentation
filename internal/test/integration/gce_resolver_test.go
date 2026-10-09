// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/ory/dockertest/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/compute/v1"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func TestGCEServiceResolution(t *testing.T) {
	t.Run("explicit scope", func(t *testing.T) { testGCEServiceResolution(t, false) })
	t.Run("detected scope", func(t *testing.T) { testGCEServiceResolution(t, true) })
}

func testGCEServiceResolution(t *testing.T, detect bool) {
	t.Helper()
	network := setupDockerNetwork(t)
	setupMockGCPIMDS(t, network)
	setupContainerPrometheus(t, network, "prometheus-config-perapp.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	backendIP := setupGCEResolverApplication(t, network, false)
	frontendIP := setupGCEResolverApplication(t, network, true)

	const apiPrefix = "/projects/my-test-project/zones/us-central1-a/"
	var available atomic.Bool
	var denied atomic.Int64
	mock := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer gce-integration-token", r.Header.Get("Authorization"))
		if !available.Load() {
			denied.Add(1)
			http.Error(w, "inventory not ready", http.StatusForbidden)
			return
		}
		var response any
		switch r.URL.Path {
		case apiPrefix + "instanceGroupManagers":
			assert.Equal(t, http.MethodGet, r.Method)
			response = &compute.InstanceGroupManagerList{Items: []*compute.InstanceGroupManager{{Name: "storefront"}, {Name: "checkout"}}}
		case apiPrefix + "instanceGroupManagers/storefront/listManagedInstances":
			assert.Equal(t, http.MethodPost, r.Method)
			response = &compute.InstanceGroupManagersListManagedInstancesResponse{
				ManagedInstances: []*compute.ManagedInstance{{Instance: apiPrefix + "instances/frontend"}},
			}
		case apiPrefix + "instanceGroupManagers/checkout/listManagedInstances":
			assert.Equal(t, http.MethodPost, r.Method)
			response = &compute.InstanceGroupManagersListManagedInstancesResponse{
				ManagedInstances: []*compute.ManagedInstance{{Instance: apiPrefix + "instances/backend"}},
			}
		case apiPrefix + "instances/frontend":
			response = &compute.Instance{
				Id: 1234567890123456789, Status: "RUNNING",
				NetworkInterfaces: []*compute.NetworkInterface{{NetworkIP: frontendIP}},
			}
		case apiPrefix + "instances/backend":
			response = &compute.Instance{
				Id: 202, Status: "RUNNING",
				NetworkInterfaces: []*compute.NetworkInterface{{NetworkIP: backendIP}},
			}
		default:
			t.Errorf("unexpected Compute API request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(response))
	}))
	require.NoError(t, mock.Listener.Close())
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	mock.Listener = listener
	mock.Start()
	t.Cleanup(mock.Close)
	require.NotEmpty(t, network.Inspect().IPAM.Config)
	gateway := network.Inspect().IPAM.Config[0].Gateway.String()
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		gateway = "host.docker.internal"
	}
	endpoint := "http://" + net.JoinHostPort(gateway, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	o := obi{
		Env: []string{
			// Only the frontend listens on 8080. The checkout has no OBI or SDK.
			"OTEL_EBPF_OPEN_PORT=8080",
			"OTEL_EBPF_BPF_DEBUG=false",
			"OTEL_EBPF_PROMETHEUS_PORT=8999",
			"OTEL_EBPF_METRICS_FEATURES=application,application_span_otel,application_service_graph",
			"OTEL_EBPF_PROMETHEUS_FEATURES=application,application_span_otel,application_service_graph",
			"OTEL_EBPF_NAME_RESOLVER_SOURCES=gce",
			"OTEL_EBPF_NAME_RESOLVER_GCE_ENDPOINT=" + endpoint,
			"OTEL_EBPF_CLOUD_META_REFRESH_INTERVAL=1s",
			"OTEL_EBPF_HOST_ID=custom-exported-host",
			"GCE_METADATA_HOST=mock-imds",
		},
		Logs: createLogOutput(t, "gce-resolver"),
	}
	if !detect {
		o.Env = append(o.Env,
			"OTEL_EBPF_NAME_RESOLVER_GCE_PROJECT_ID=my-test-project",
			"OTEL_EBPF_NAME_RESOLVER_GCE_ZONE=us-central1-a",
		)
	}
	if !KernelLockdownMode() {
		o.SecurityConfigSuffix = "_none"
	}
	o.instrument(t, network, "obi-config.yml")
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Positive(ct, denied.Load())
		results, err := pq.Query(`target_info{exported="prometheus",service_name="nginx"}`)
		require.NoError(ct, err)
		assert.NotEmpty(ct, results)
	}, testTimeout, 100*time.Millisecond)
	available.Store(true)

	// Inventory recovery must update target_info before any application traffic.
	for _, exporter := range []string{"prometheus", "otel"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(fmt.Sprintf(`target_info{exported=%q,service_name="storefront",host_id="custom-exported-host"}`, exporter))
			require.NoError(ct, err)
			assert.NotEmpty(ct, results)
		}, testTimeout, 100*time.Millisecond)
	}
	httpClient := &http.Client{Timeout: time.Second}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := httpClient.Get("http://localhost:8080/")
		require.NoError(ct, err)
		require.NoError(ct, resp.Body.Close())
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		for _, exporter := range []string{"prometheus", "otel"} {
			results, err := pq.Query(fmt.Sprintf(`traces_service_graph_request_total{exported=%q,client="storefront",server="checkout"}`, exporter))
			require.NoError(ct, err)
			assert.NotEmpty(ct, results)
		}
	}, testTimeout, 100*time.Millisecond)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?service=storefront")
		require.NoError(ct, err)
		require.NotNil(ct, resp)
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var traces jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&traces))
		assert.NotEmpty(ct, traces.Data)
	}, testTimeout, 100*time.Millisecond)
	for _, exporter := range []string{"prometheus", "otel"} {
		results, err := pq.Query(fmt.Sprintf(`target_info{exported=%q,service_name="checkout"}`, exporter))
		require.NoError(t, err)
		assert.Empty(t, results, "the destination must remain uninstrumented")
	}
}

func setupGCEResolverApplication(t *testing.T, network dockertest.Network, frontend bool) string {
	t.Helper()
	name := "gce-checkout"
	opts := []dockertest.RunOption{dockertest.WithTag(imgNginx.Tag()), dockertest.WithoutReuse()}
	if frontend {
		name = "gce-storefront"
		opts = append(opts,
			dockertest.WithMounts([]string{pathRoot + "/internal/test/integration/configs/gce-frontend-nginx.conf:/etc/nginx/nginx.conf:ro"}),
			dockertest.WithPortBindings(portBindings("8080/tcp", "8080")),
			dockertest.WithContainerConfig(func(cfg *container.Config) { cfg.ExposedPorts = exposedPorts("8080/tcp") }),
		)
	}
	opts = append(opts, dockertest.WithName(fmt.Sprintf("%s-%d", name, time.Now().UnixNano())))
	app, err := dockerPool.Run(t.Context(), imgNginx.Repository(), opts...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, app.Close(context.Background())) })
	_, err = dockerPool.Client().NetworkConnect(t.Context(), network.ID(), client.NetworkConnectOptions{
		Container: app.ID(), EndpointConfig: endpointAliases(name),
	})
	require.NoError(t, err)
	_, err = dockerPool.Client().NetworkDisconnect(t.Context(), "bridge", client.NetworkDisconnectOptions{Container: app.ID()})
	require.NoError(t, err)
	inspect, err := dockerPool.Client().ContainerInspect(t.Context(), app.ID(), client.ContainerInspectOptions{})
	require.NoError(t, err)
	for _, endpoint := range inspect.Container.NetworkSettings.Networks {
		if endpoint.NetworkID == network.ID() {
			return endpoint.IPAddress.String()
		}
	}
	t.Fatal("application has no IP on the integration network")
	return ""
}
