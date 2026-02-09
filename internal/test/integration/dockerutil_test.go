// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
)

// setupDockerNetwork initializes a custom network for the test.
func setupDockerNetwork(t *testing.T) *dockertest.Network {
	t.Helper()

	networkName := fmt.Sprintf("test-network-%d", time.Now().UnixNano())
	network, err := dockerPool.CreateNetwork(networkName)
	require.NoError(t, err, "could not create Docker network")
	t.Cleanup(func() {
		require.NoError(t, dockerPool.RemoveNetwork(network), "could not remove Docker network")
	})

	return network
}

// setupContainerPrometheus starts a Prometheus container for metrics scraping.
func setupContainerPrometheus(t *testing.T, network *dockertest.Network, configFile string) { //nolint:unparam // configFile is always passed in current usages but may vary in future
	t.Helper()

	t.Log("Starting Prometheus container...")
	prometheus, err := dockerPool.RunWithOptions(&dockertest.RunOptions{
		Repository: "quay.io/prometheus/prometheus",
		Tag:        "v2.55.1",
		Name:       fmt.Sprintf("prometheus-otel-test-%d", time.Now().UnixNano()),
		Networks:   []*dockertest.Network{network},
		Mounts: []string{
			filepath.Join(pathRoot, "internal/test/integration/configs") + ":/etc/prometheus",
		},
		Cmd: []string{
			"--config.file=/etc/prometheus/" + configFile,
			"--web.enable-lifecycle",
			"--web.route-prefix=/",
		},
		ExposedPorts: []string{"9090/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"9090/tcp": {{HostIP: "localhost", HostPort: "9090"}},
		},
	})
	require.NoError(t, err, "could not start Prometheus container")
	t.Cleanup(func() {
		require.NoError(t, dockerPool.Purge(prometheus), "could not remove Prometheus container")
	})
	t.Log("Prometheus container started")
}

// setupContainerJaeger starts a Jaeger container for trace collection.
func setupContainerJaeger(t *testing.T, network *dockertest.Network) {
	t.Helper()

	t.Log("Starting Jaeger container...")
	jaeger, err := dockerPool.RunWithOptions(&dockertest.RunOptions{
		Repository: "jaegertracing/all-in-one",
		Tag:        "1.60",
		Name:       fmt.Sprintf("jaeger-otel-test-%d", time.Now().UnixNano()),
		Env: []string{
			"COLLECTOR_OTLP_ENABLED=true",
			"LOG_LEVEL=debug",
		},
		ExposedPorts: []string{"16686/tcp", "4317/tcp", "4318/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"16686/tcp": {{HostIP: "localhost", HostPort: "16686"}},
		},
	})
	require.NoError(t, err, "could not start Jaeger container")
	t.Cleanup(func() {
		require.NoError(t, dockerPool.Purge(jaeger), "could not remove Jaeger container")
	})

	// Connect to custom network with alias
	err = dockerPool.Client.ConnectNetwork(network.Network.ID, docker.NetworkConnectionOptions{
		Container: jaeger.Container.ID,
		EndpointConfig: &docker.EndpointConfig{
			Aliases: []string{"jaeger"},
		},
	})
	require.NoError(t, err, "could not connect Jaeger container to network")
	t.Log("Jaeger container started")
}

// setupContainerCollector starts an OpenTelemetry Collector container.
func setupContainerCollector(t *testing.T, network *dockertest.Network, configFile string) { //nolint:unparam // configFile is always passed in current usages but may vary in future
	t.Helper()

	t.Log("Starting OpenTelemetry Collector container...")
	otelcol, err := dockerPool.RunWithOptions(&dockertest.RunOptions{
		Repository: "otel/opentelemetry-collector-contrib",
		Tag:        "0.144.0",
		Name:       fmt.Sprintf("otelcol-otel-test-%d", time.Now().UnixNano()),
		Cmd:        []string{"--config=/etc/otelcol-config/" + configFile},
		Mounts: []string{
			filepath.Join(pathRoot, "internal/test/integration/configs") + ":/etc/otelcol-config",
		},
		ExposedPorts: []string{"4317/tcp", "4318/tcp", "9464/tcp", "8888/tcp"},
	})
	require.NoError(t, err, "could not start OpenTelemetry Collector container")
	t.Cleanup(func() {
		require.NoError(t, dockerPool.Purge(otelcol), "could not remove OpenTelemetry Collector container")
	})

	// Connect to custom network with alias
	err = dockerPool.Client.ConnectNetwork(network.Network.ID, docker.NetworkConnectionOptions{
		Container: otelcol.Container.ID,
		EndpointConfig: &docker.EndpointConfig{
			Aliases: []string{"otelcol"},
		},
	})
	require.NoError(t, err, "could not connect OpenTelemetry Collector container to network")
	t.Log("OpenTelemetry Collector container started")
}

// buildOBIImage builds the OBI image.
func buildOBIImage() error {
	return dockerPool.Client.BuildImage(docker.BuildImageOptions{
		Name:         "hatest-obi",
		ContextDir:   pathRoot,
		Dockerfile:   "internal/test/integration/components/obi/Dockerfile",
		OutputStream: os.Stdout,
		ErrorStream:  os.Stderr,
	})
}

// obi holds configuration for OBI instrumentation.
type obi struct {
	// Env holds additional environment variables to set in the OBI container.
	Env []string
	// SecurityConfigSuffix is the suffix for the security config file to use.
	SecurityConfigSuffix string
}

// instrument starts the OBI container to instrument the target application.
func (o obi) instrument(t *testing.T, network *dockertest.Network, resource *dockertest.Resource, configFile string) { //nolint:unparam // configFile is always passed in current usages but may vary in future
	t.Helper()

	t.Log("Starting OBI container with PID namespace sharing...")
	runOtelDir := filepath.Join(pathOutput, "run-otel")
	require.NoError(t, os.MkdirAll(pathOutput, 0o755), "could not create coverage directory")
	require.NoError(t, os.MkdirAll(runOtelDir, 0o755), "could not create run-otel directory")

	obi, err := dockerPool.RunWithOptions(&dockertest.RunOptions{
		Repository: "hatest-obi",
		Name:       fmt.Sprintf("obi-otel-test-%d", time.Now().UnixNano()),
		Networks:   []*dockertest.Network{network},
		Cmd: []string{
			"--config=/configs/" + configFile,
		},
		Mounts: []string{
			filepath.Join(pathRoot, "internal/test/integration/configs") + ":/configs",
			filepath.Join(pathRoot, "internal/test/integration/system/sys/kernel/security"+o.SecurityConfigSuffix) + ":/sys/kernel/security",
			pathOutput + ":/coverage",
			runOtelDir + ":/var/run/beyla",
		},
		Env: append([]string{
			"GOCOVERDIR=/coverage",
			"OTEL_EBPF_TRACE_PRINTER=text",
			"OTEL_EBPF_METRICS_FEATURES=application,application_span",
			"OTEL_EBPF_PROMETHEUS_FEATURES=application,application_span",
			"OTEL_EBPF_DISCOVERY_POLL_INTERVAL=500ms",
			"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT=1ms",
			"OTEL_EBPF_SERVICE_NAMESPACE=integration-test",
			"OTEL_EBPF_METRICS_INTERVAL=10ms",
			"OTEL_EBPF_BPF_BATCH_TIMEOUT=10ms",
			"OTEL_EBPF_LOG_LEVEL=DEBUG",
			"OTEL_EBPF_BPF_DEBUG=TRUE",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT=8999",
			"OTEL_EBPF_PROCESSES_INTERVAL=100ms",
			"OTEL_EBPF_HOSTNAME=beyla",
		}, o.Env...),
		Privileged:   true,
		ExposedPorts: []string{"8999/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8999/tcp": {{HostIP: "localhost", HostPort: "8999"}},
		},
	}, func(hc *docker.HostConfig) {
		hc.PidMode = "container:" + resource.Container.ID
	})
	require.NoError(t, err, "could not start OBI container")
	t.Cleanup(func() {
		require.NoError(t, dockerPool.Purge(obi), "could not remove OBI container")
	})
	t.Log("OBI container started")
}
