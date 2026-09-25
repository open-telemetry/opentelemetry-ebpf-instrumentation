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
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/ory/dockertest/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func TestECSServiceResolution(t *testing.T) {
	t.Run("explicit settings", func(t *testing.T) { testECSServiceResolution(t, false) })
	t.Run("discovered settings", func(t *testing.T) { testECSServiceResolution(t, true) })
}

func testECSServiceResolution(t *testing.T, discover bool) {
	t.Helper()
	network := setupDockerNetwork(t)
	if discover {
		setupECSMetadataMock(t, network)
	}
	setupContainerPrometheus(t, network, "prometheus-config-perapp.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	tasks := []map[string]any{
		setupECSResolverApplication(t, network, "ecs-backend", false),
		setupECSResolverApplication(t, network, "ecs-frontend", true),
	}
	// Use the same network for published ports and communication between containers.
	inspect, err := dockerPool.Client().NetworkInspect(t.Context(), network.ID(), client.NetworkInspectOptions{})
	require.NoError(t, err)
	for id := range inspect.Network.Containers {
		_, err := dockerPool.Client().NetworkDisconnect(t.Context(), "bridge", client.NetworkDisconnectOptions{Container: id})
		require.NoError(t, err)
	}
	if discover {
		require.NoError(t, waitUntilReadyToServe("http://127.0.0.1:1339/v3/containers/ecs-frontend/task"))
	}

	var available atomic.Bool
	var denied atomic.Int64
	mock := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		var input struct{ Cluster string }
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Errorf("decoding ECS request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		wantCluster := "integration-test"
		if discover {
			wantCluster = "arn:aws:ecs:us-east-1:111111111111:cluster/integration-test"
		}
		assert.Equal(t, wantCluster, input.Cluster)
		assert.Contains(t, r.Header.Get("Authorization"), "/us-east-1/ecs/aws4_request")
		if !available.Load() {
			denied.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"__type":"AccessDeniedException","message":"not ready"}`)
			return
		}
		var response any
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonEC2ContainerServiceV20141113.ListTasks":
			response = map[string]any{"taskArns": []string{"ecs-backend", "ecs-frontend"}}
		case "AmazonEC2ContainerServiceV20141113.DescribeTasks":
			response = map[string]any{"tasks": tasks}
		default:
			t.Errorf("unexpected ECS operation: %s", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encoding ECS response: %v", err)
		}
	}))
	require.NoError(t, mock.Listener.Close())
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	mock.Listener = listener
	mock.Start()
	defer mock.Close()
	require.NotEmpty(t, network.Inspect().IPAM.Config)
	gateway := network.Inspect().IPAM.Config[0].Gateway.String()
	endpoint := "http://" + net.JoinHostPort(gateway, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	o := obi{
		Env: []string{
			"OTEL_EBPF_OPEN_PORT=80,8080",
			"OTEL_EBPF_BPF_DEBUG=false",
			"OTEL_EBPF_PROMETHEUS_PORT=8999",
			"OTEL_EBPF_METRICS_FEATURES=application,application_span_otel,application_service_graph",
			"OTEL_EBPF_PROMETHEUS_FEATURES=application,application_span_otel,application_service_graph",
			"OTEL_EBPF_NAME_RESOLVER_SOURCES=ecs",
			"OTEL_EBPF_NAME_RESOLVER_ECS_REFRESH_INTERVAL=1s",
			"AWS_ENDPOINT_URL_ECS=" + endpoint,
			"AWS_ACCESS_KEY_ID=test", "AWS_SECRET_ACCESS_KEY=test",
			"AWS_EC2_METADATA_DISABLED=true", "AWS_MAX_ATTEMPTS=1",
		},
		Logs: createLogOutput(t, "ecs-resolver"),
	}
	if discover {
		// The official mock serves V4-compatible metadata through its /v3 route.
		o.Env = append(o.Env, "ECS_CONTAINER_METADATA_URI_V4=http://ecs-metadata/v3/containers/obi")
	} else {
		o.Env = append(o.Env,
			"OTEL_EBPF_CLUSTER_NAME=integration-test",
			"OTEL_EBPF_CLOUD_REGION=us-east-1",
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

	for _, exporter := range []string{"prometheus", "otel"} {
		for _, service := range []string{"ecs-frontend", "ecs-backend"} {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(fmt.Sprintf(`target_info{exported=%q,service_name=%q}`, exporter, service))
				require.NoError(ct, err)
				assert.NotEmpty(ct, results)
			}, testTimeout, 100*time.Millisecond)
		}
	}
	httpClient := &http.Client{Timeout: time.Second}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := httpClient.Get("http://localhost:8080/")
		require.NoError(ct, err)
		require.NoError(ct, resp.Body.Close())
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		for _, exporter := range []string{"prometheus", "otel"} {
			results, err := pq.Query(fmt.Sprintf(`traces_service_graph_request_total{exported=%q,client="ecs-frontend",server="ecs-backend"}`, exporter))
			require.NoError(ct, err)
			assert.NotEmpty(ct, results)
		}
	}, testTimeout, 100*time.Millisecond)
	for _, service := range []string{"ecs-frontend", "ecs-backend"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			resp, err := httpClient.Get(jaegerQueryURL + "?service=" + service)
			require.NoError(ct, err)
			defer resp.Body.Close()
			require.Equal(ct, http.StatusOK, resp.StatusCode)
			var traces jaeger.TracesQuery
			require.NoError(ct, json.NewDecoder(resp.Body).Decode(&traces))
			assert.NotEmpty(ct, traces.Data)
		}, testTimeout, 100*time.Millisecond)
	}
}

func setupECSMetadataMock(t *testing.T, network dockertest.Network) {
	t.Helper()
	mock, err := dockerPool.Run(t.Context(), imgECSMetaMock.Repository(),
		dockertest.WithTag(imgECSMetaMock.Tag()),
		dockertest.WithName(fmt.Sprintf("ecs-metadata-%d", time.Now().UnixNano())),
		dockertest.WithMounts([]string{"/var/run/docker.sock:/var/run/docker.sock"}),
		dockertest.WithEnv([]string{
			// The mock's default Docker API version is too old for Docker 29.
			"DOCKER_API_VERSION=1.44",
			"AWS_ACCESS_KEY_ID=test", "AWS_SECRET_ACCESS_KEY=test", "AWS_REGION=us-east-1",
			"CLUSTER_ARN=integration-test",
			"TASK_ARN=arn:aws:ecs:us-east-1:111111111111:task/integration-test/obi",
		}),
		dockertest.WithPortBindings(portBindings("80/tcp", "1339")),
		dockertest.WithContainerConfig(func(cfg *container.Config) { cfg.ExposedPorts = exposedPorts("80/tcp") }),
		dockertest.WithoutReuse(),
	)
	require.NoError(t, err, "could not start ECS metadata mock")
	t.Cleanup(func() { require.NoError(t, mock.Close(context.Background())) })
	_, err = dockerPool.Client().NetworkConnect(t.Context(), network.ID(), client.NetworkConnectOptions{
		Container: mock.ID(), EndpointConfig: endpointAliases("ecs-metadata"),
	})
	require.NoError(t, err, "could not connect ECS metadata mock to network")
}

func setupECSResolverApplication(t *testing.T, network dockertest.Network, service string, frontend bool) map[string]any {
	t.Helper()
	opts := []dockertest.RunOption{
		dockertest.WithTag(imgNginx.Tag()),
		dockertest.WithName(fmt.Sprintf("%s-%d", service, time.Now().UnixNano())),
		dockertest.WithoutReuse(),
	}
	if frontend {
		opts = append(opts,
			dockertest.WithMounts([]string{pathRoot + "/internal/test/integration/configs/ecs-frontend-nginx.conf:/etc/nginx/nginx.conf:ro"}),
			dockertest.WithPortBindings(portBindings("8080/tcp", "8080")),
			dockertest.WithContainerConfig(func(cfg *container.Config) { cfg.ExposedPorts = exposedPorts("8080/tcp") }),
		)
	}
	app, err := dockerPool.Run(t.Context(), imgNginx.Repository(), opts...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, app.Close(context.Background())) })
	_, err = dockerPool.Client().NetworkConnect(t.Context(), network.ID(), client.NetworkConnectOptions{
		Container: app.ID(), EndpointConfig: endpointAliases(service),
	})
	require.NoError(t, err)
	inspect, err := dockerPool.Client().ContainerInspect(t.Context(), app.ID(), client.ContainerInspectOptions{})
	require.NoError(t, err)
	var ip string
	for _, endpoint := range inspect.Container.NetworkSettings.Networks {
		if endpoint.NetworkID == network.ID() {
			ip = endpoint.IPAddress.String()
		}
	}
	require.NotEmpty(t, ip)
	return map[string]any{
		"taskArn": service, "group": "service:" + service,
		"containers": []map[string]string{{"runtimeId": app.ID()}},
		"attachments": []map[string]any{{"type": "ElasticNetworkInterface", "details": []map[string]string{
			{"name": "privateIPv4Address", "value": ip},
		}}},
	}
}
