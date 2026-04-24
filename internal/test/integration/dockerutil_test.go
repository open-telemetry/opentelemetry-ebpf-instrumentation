// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/ory/dockertest/v4"
	"github.com/stretchr/testify/require"
)

const (
	versionPrometheus  = "v2.55.1"
	versionJaeger      = "1.60"
	versionCollector   = "0.144.0"
	versionAWSMetaMock = "v1.9.2"
	versionNginx       = "1.29.5"
)

// setupDockerNetwork initializes a custom network for the test.
func setupDockerNetwork(t *testing.T) dockertest.Network {
	t.Helper()

	networkName := fmt.Sprintf("test-network-%d", time.Now().UnixNano())
	net, err := dockerPool.CreateNetwork(t.Context(), networkName, nil)
	require.NoError(t, err, "could not create Docker network")
	t.Cleanup(func() {
		require.NoError(t, net.Close(context.Background()), "could not remove Docker network")
	})

	return net
}

func endpointAliases(aliases ...string) *network.EndpointSettings {
	return &network.EndpointSettings{Aliases: aliases}
}

func endpointIPv4(address string) *network.EndpointSettings {
	return &network.EndpointSettings{
		IPAMConfig: &network.EndpointIPAMConfig{
			IPv4Address: netip.MustParseAddr(address),
		},
	}
}

func exposedPorts(ports ...string) network.PortSet {
	portSet := network.PortSet{}
	for _, port := range ports {
		portSet[network.MustParsePort(port)] = struct{}{}
	}
	return portSet
}

func portBindings(containerPort, hostPort string) network.PortMap {
	return network.PortMap{
		network.MustParsePort(containerPort): {
			{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: hostPort},
		},
	}
}

func bindMount(source, target string) mount.Mount {
	return mount.Mount{
		Type:   mount.TypeBind,
		Source: source,
		Target: target,
	}
}

// setupContainerPrometheus starts a Prometheus container for metrics scraping.
func setupContainerPrometheus(t *testing.T, net dockertest.Network, configFile string) {
	t.Helper()

	t.Log("Starting Prometheus container...")
	prometheus, err := dockerPool.Run(t.Context(), "quay.io/prometheus/prometheus",
		dockertest.WithTag(versionPrometheus),
		dockertest.WithName(fmt.Sprintf("prometheus-otel-test-%d", time.Now().UnixNano())),
		dockertest.WithMounts([]string{
			filepath.Join(pathRoot, "internal/test/integration/configs") + ":/etc/prometheus",
		}),
		dockertest.WithCmd([]string{
			"--config.file=/etc/prometheus/" + configFile,
			"--web.enable-lifecycle",
			"--web.route-prefix=/",
		}),
		dockertest.WithPortBindings(portBindings("9090/tcp", "9090")),
		dockertest.WithContainerConfig(func(config *container.Config) {
			config.ExposedPorts = exposedPorts("9090/tcp")
		}),
		dockertest.WithoutReuse(),
	)
	require.NoError(t, err, "could not start Prometheus container")
	t.Cleanup(func() {
		require.NoError(t, prometheus.Close(context.Background()), "could not remove Prometheus container")
	})
	_, err = dockerPool.Client().NetworkConnect(t.Context(), net.ID(), client.NetworkConnectOptions{
		Container: prometheus.ID(),
	})
	require.NoError(t, err, "could not connect Prometheus container to network")
	t.Log("Prometheus container started")
}

// setupContainerJaeger starts a Jaeger container for trace collection.
func setupContainerJaeger(t *testing.T, net dockertest.Network) {
	t.Helper()

	t.Log("Starting Jaeger container...")
	jaeger, err := dockerPool.Run(t.Context(), "jaegertracing/all-in-one",
		dockertest.WithTag(versionJaeger),
		dockertest.WithName(fmt.Sprintf("jaeger-otel-test-%d", time.Now().UnixNano())),
		dockertest.WithEnv([]string{
			"COLLECTOR_OTLP_ENABLED=true",
			"LOG_LEVEL=debug",
		}),
		dockertest.WithPortBindings(portBindings("16686/tcp", "16686")),
		dockertest.WithContainerConfig(func(config *container.Config) {
			config.ExposedPorts = exposedPorts("16686/tcp", "4317/tcp", "4318/tcp")
		}),
		dockertest.WithoutReuse(),
	)
	require.NoError(t, err, "could not start Jaeger container")
	t.Cleanup(func() {
		require.NoError(t, jaeger.Close(context.Background()), "could not remove Jaeger container")
	})

	_, err = dockerPool.Client().NetworkConnect(t.Context(), net.ID(), client.NetworkConnectOptions{
		Container:      jaeger.ID(),
		EndpointConfig: endpointAliases("jaeger"),
	})
	require.NoError(t, err, "could not connect Jaeger container to network")
	t.Log("Jaeger container started")
}

// setupContainerCollector starts an OpenTelemetry Collector container.
func setupContainerCollector(t *testing.T, net dockertest.Network, configFile string) { //nolint:unparam // configFile is always passed in current usages but may vary in future
	t.Helper()

	t.Log("Starting OpenTelemetry Collector container...")
	otelcol, err := dockerPool.Run(t.Context(), "otel/opentelemetry-collector-contrib",
		dockertest.WithTag(versionCollector),
		dockertest.WithName(fmt.Sprintf("otelcol-otel-test-%d", time.Now().UnixNano())),
		dockertest.WithCmd([]string{"--config=/etc/otelcol-config/" + configFile}),
		dockertest.WithMounts([]string{
			filepath.Join(pathRoot, "internal/test/integration/configs") + ":/etc/otelcol-config",
		}),
		dockertest.WithContainerConfig(func(config *container.Config) {
			config.ExposedPorts = exposedPorts("4317/tcp", "4318/tcp", "9464/tcp", "8888/tcp")
		}),
		dockertest.WithoutReuse(),
	)
	require.NoError(t, err, "could not start OpenTelemetry Collector container")
	t.Cleanup(func() {
		require.NoError(t, otelcol.Close(context.Background()), "could not remove OpenTelemetry Collector container")
	})

	_, err = dockerPool.Client().NetworkConnect(t.Context(), net.ID(), client.NetworkConnectOptions{
		Container:      otelcol.ID(),
		EndpointConfig: endpointAliases("otelcol"),
	})
	require.NoError(t, err, "could not connect OpenTelemetry Collector container to network")
	t.Log("OpenTelemetry Collector container started")
}

// buildOBIImage builds the OBI image. When SKIP_DOCKER_BUILD is set, the image
// has been pre-built for the VM workflow prior to QEMU startup.
func buildOBIImage(ctx context.Context) error {
	if os.Getenv("SKIP_DOCKER_BUILD") != "" {
		_, err := dockerPool.Client().ImageInspect(ctx, "hatest-obi")
		if err == nil {
			fmt.Println("Skipping OBI image build (pre-built image found)")
			return nil
		}
		fmt.Println("SKIP_DOCKER_BUILD set but hatest-obi image not found, building...")
	}
	return buildDockerImage(ctx, os.Stdout, "hatest-obi", "internal/test/integration/components/obi/Dockerfile")
}

func buildDockerImage(ctx context.Context, output io.Writer, tag, dockerfile string) error {
	buildContext, err := createBuildContext(pathRoot)
	if err != nil {
		return err
	}
	defer func() {
		_ = buildContext.Close()
	}()

	result, err := dockerPool.Client().ImageBuild(ctx, buildContext, client.ImageBuildOptions{
		Tags:       []string{tag},
		Dockerfile: dockerfile,
		Remove:     true,
	})
	if err != nil {
		return fmt.Errorf("building Docker image %q: %w", tag, err)
	}

	buildErr := drainDockerBuildStream(result.Body, output)
	closeErr := result.Body.Close()
	if buildErr != nil {
		return fmt.Errorf("building Docker image %q: %w", tag, buildErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing Docker build response for %q: %w", tag, closeErr)
	}
	return nil
}

// createBuildContext creates a tar archive of the given directory for Docker build context.
//
// createBuildContext code is mostly copied from
// https://github.com/ory/dockertest/blob/927ba364b58256b83edaaf7545fce83e59fc46a4/build.go#L194.
func createBuildContext(contextDir string) (io.ReadCloser, error) {
	info, err := os.Stat(contextDir)
	if err != nil {
		return nil, fmt.Errorf("build context directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("build context path %q is not a directory", contextDir)
	}

	// Create a pipe for streaming the tar archive
	pr, pw := io.Pipe()

	go func() {
		tw := tar.NewWriter(pw)

		// Walk the context directory and add files to tar
		err := filepath.WalkDir(contextDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// Get relative path from context directory
			relPath, err := filepath.Rel(contextDir, path)
			if err != nil {
				return err
			}

			// Skip the context directory itself
			if relPath == "." {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return err
			}

			// Resolve symlink target for tar header
			var link string
			if info.Mode()&os.ModeSymlink != 0 {
				link, err = os.Readlink(path)
				if err != nil {
					return err
				}
			}

			// Skip non-regular files (devices, sockets, named pipes)
			if !info.Mode().IsRegular() && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				return nil
			}

			// Create tar header
			header, err := tar.FileInfoHeader(info, link)
			if err != nil {
				return err
			}

			// Use forward slashes in tar (Docker expects this)
			header.Name = filepath.ToSlash(relPath)

			// Write header
			if err := tw.WriteHeader(header); err != nil {
				return err
			}

			// Write file content for regular files only
			if info.Mode().IsRegular() {
				// #nosec G304 -- path is from filepath.WalkDir of a known build context directory
				file, err := os.Open(path)
				if err != nil {
					return err
				}

				if _, err := io.Copy(tw, file); err != nil {
					_ = file.Close()
					return err
				}
				if err := file.Close(); err != nil {
					return err
				}
			}

			return nil
		})

		// Close tar writer to flush end-of-archive marker
		if closeErr := tw.Close(); closeErr != nil && err == nil {
			err = closeErr
		}

		// Always signal the pipe reader: nil for EOF, non-nil for error
		pw.CloseWithError(err)
	}()

	return pr, nil
}

// drainBuildStream consumes the Docker build JSON stream and returns the first
// error found. Docker embeds build errors (failed RUN commands, syntax errors)
// as {"errorDetail":...} messages in the stream rather than returning them from
// ImageBuild directly.
//
// drainBuildStream code is mostly copied from
// https://github.com/ory/dockertest/blob/927ba364b58256b83edaaf7545fce83e59fc46a4/build.go#L295.
func drainDockerBuildStream(r io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(r)
	for {
		var msg jsonstream.Message
		if err := decoder.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decoding Docker build stream: %w", err)
		}
		if err := writeDockerBuildMessage(output, msg); err != nil {
			return err
		}
		if msg.Error != nil {
			return msg.Error
		}
	}
}

func writeDockerBuildMessage(output io.Writer, msg jsonstream.Message) error {
	if output == nil {
		return nil
	}
	if msg.Stream != "" {
		_, err := io.WriteString(output, msg.Stream)
		return err
	}
	if msg.Error != nil {
		_, err := fmt.Fprintln(output, msg.Error.Message)
		return err
	}
	if msg.Status != "" {
		if msg.ID != "" {
			_, err := fmt.Fprintf(output, "%s: %s\n", msg.ID, msg.Status)
			return err
		}
		_, err := fmt.Fprintln(output, msg.Status)
		return err
	}
	return nil
}

// obi holds configuration for OBI instrumentation.
type obi struct {
	// Env holds additional environment variables to set in the OBI container.
	Env []string
	// SecurityConfigSuffix is the suffix for the security config file to use.
	SecurityConfigSuffix string
	Logs                 io.Writer
}

// instrument starts the OBI container to instrument the target application.
func (o obi) instrument(t *testing.T, net dockertest.Network, configFile string) {
	t.Helper()

	t.Log("Starting OBI container with PID namespace sharing...")
	runOtelDir := filepath.Join(pathOutput, "run-otel")
	require.NoError(t, os.MkdirAll(pathOutput, 0o755), "could not create coverage directory")
	require.NoError(t, os.MkdirAll(runOtelDir, 0o755), "could not create run-otel directory")

	cntName := "obi"

	hostConfig := &container.HostConfig{
		PublishAllPorts: true,
		PortBindings:    portBindings("8999/tcp", "8999"),
		Privileged:      true,
		PidMode:         "host",
		Mounts: []mount.Mount{
			bindMount(filepath.Join(pathRoot, "internal/test/integration/configs"), "/configs"),
			bindMount(filepath.Join(pathRoot, "internal/test/integration/system/sys/kernel/security"+o.SecurityConfigSuffix), "/sys/kernel/security"),
			bindMount(pathOutput, "/coverage"),
			bindMount(runOtelDir, "/var/run/obi"),
		},
	}
	created, err := dockerPool.Client().ContainerCreate(t.Context(), client.ContainerCreateOptions{
		Name: cntName,
		Config: &container.Config{
			Cmd:   []string{"--config=/configs/" + configFile},
			Image: "hatest-obi",
			Env: append([]string{
				"GOCOVERDIR=/coverage",
				`OTEL_EBPF_SHUTDOWN_TIMEOUT=2s`,
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
				"OTEL_EBPF_HOSTNAME=obi",
			}, o.Env...),
			ExposedPorts: exposedPorts("8999/tcp"),
		},
		HostConfig: hostConfig,
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				net.ID(): endpointAliases("obi"),
			},
		},
	})
	require.NoError(t, err, "could not create OBI container")

	_, err = dockerPool.Client().ContainerStart(t.Context(), created.ID, client.ContainerStartOptions{})
	require.NoError(t, err, "could not start OBI container")

	t.Cleanup(func() {
		ctx := context.Background()
		if o.Logs != nil {
			logs, err := dockerPool.Client().ContainerLogs(ctx, created.ID, client.ContainerLogsOptions{
				ShowStderr: true,
				ShowStdout: true,
			})
			if err != nil {
				t.Logf("could not stream logs: %v", err)
			} else {
				if _, err := stdcopy.StdCopy(o.Logs, o.Logs, logs); err != nil {
					t.Logf("could not copy logs: %v", err)
				}
				if err := logs.Close(); err != nil {
					t.Logf("could not close logs stream: %v", err)
				}
			}
		}
		timeout := 4
		if _, err := dockerPool.Client().ContainerStop(ctx, created.ID, client.ContainerStopOptions{Timeout: &timeout}); err != nil {
			t.Logf("could not stop test server container after timeout: %v. Will force removal (you will loose coverage data)", err)
		}
		if _, err := dockerPool.Client().ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
			t.Logf("could not remove OBI container: %v", err)
		}
	})
	t.Log("OBI container started")
}

func createLogOutput(t *testing.T, testCase string) io.Writer {
	t.Helper()
	require.NoError(t, os.MkdirAll(pathOutput, 0o755), "could not create coverage directory")
	out, err := os.Create(filepath.Join(pathOutput, testCase+"-obi.log"))
	require.NoError(t, err, "could not create logs file")
	t.Cleanup(func() {
		if err := out.Close(); err != nil {
			t.Logf("could not close logs file: %v", err)
		}
	})
	return out
}
