// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"debug/elf"
	"net/http"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestRuntimeMetricsPromStripped(t *testing.T) {
	runRuntimeMetricsStripped(t, "prom", runtimeMetricsPromCompatibilityConfig{
		goVersion: "current", hostPort: runtimeMetricsHostPort,
		test: func(t *testing.T) { testRuntimeMetricsGoAtPort(t, runtimeMetricsHostPort) },
	})
}

func TestRuntimeMetricsOTelStripped(t *testing.T) {
	runRuntimeMetricsStripped(t, "otel", runtimeMetricsPromCompatibilityConfig{
		goVersion: "current", hostPort: runtimeMetricsHostPort,
		test: func(t *testing.T) { testRuntimeMetricsGoAtPort(t, runtimeMetricsHostPort) },
	})
}

func TestRuntimeMetricsPromGo117Stripped(t *testing.T) {
	runRuntimeMetricsStripped(t, "prom", runtimeMetricsPromCompatibilityConfig{
		goVersion: "1.17", hostPort: runtimeMetricsGo117HostPort,
		dockerfile: "./internal/test/integration/components/go-runtime-metrics-server/Dockerfile_1.17",
		test:       testRuntimeMetricsGo117,
	})
}

func TestRuntimeMetricsPromGo125Stripped(t *testing.T) {
	runRuntimeMetricsStripped(t, "prom", runtimeMetricsPromCompatibilityConfig{
		goVersion: "1.25", hostPort: runtimeMetricsGo125HostPort,
		builderImage: runtimeMetricsGo125BuilderImage,
		test:         func(t *testing.T) { testRuntimeMetricsGoAtPort(t, runtimeMetricsGo125HostPort) },
	})
}

func runRuntimeMetricsStripped(t *testing.T, exporter string, cfg runtimeMetricsPromCompatibilityConfig) {
	if runtime.GOARCH != "amd64" {
		t.Skip("stripped Go runtime global recovery requires amd64")
	}
	name := "stripped-" + strings.ReplaceAll(cfg.goVersion, ".", "-") + "-" + exporter
	compose, err := docker.ComposeSuite("docker-compose-go-runtime-metrics.yml",
		path.Join(pathOutput, "test-suite-runtime-metrics-"+name+".log"))
	require.NoError(t, err)
	promSuffix := ""
	if exporter == "otel" {
		promSuffix = "-otel"
	}
	compose.Env = append(compose.Env,
		"TEST_SERVICE_PORTS="+cfg.hostPort+":8080",
		"INSTRUMENTER_CONFIG_SUFFIX=-"+exporter,
		"PROM_CONFIG_SUFFIX="+promSuffix,
		"RUNTIME_METRICS_TESTSERVER_IMAGE=hatest-testserver-go-runtime-metrics-"+name,
		"RUNTIME_METRICS_TESTSERVER_LDFLAGS=-s -w",
	)
	if cfg.builderImage != "" {
		compose.Env = append(compose.Env, "RUNTIME_METRICS_TESTSERVER_GO_IMAGE="+cfg.builderImage)
	}
	if cfg.dockerfile != "" {
		compose.Env = append(compose.Env, "RUNTIME_METRICS_TESTSERVER_DOCKERFILE="+cfg.dockerfile)
	}
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	// Inspect the binary actually running in the container, including prebuilt images.
	binary := path.Join(t.TempDir(), "testserver")
	command := exec.Command("docker", "compose", "-f", compose.Path, "cp", "testserver:/testserver", binary)
	command.Env = compose.Env
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	f, err := elf.Open(binary)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	_, err = f.Symbols()
	require.ErrorIs(t, err, elf.ErrNoSymbols)
	require.Nil(t, f.Section(".debug_info"))
	require.Equal(t, elf.EM_X86_64, f.Machine)

	t.Run("Go "+cfg.goVersion+" stripped runtime metrics with "+exporter+" export", cfg.test)
	waitForStrippedRuntimeWeaverExport(t, compose)
	runWeaverValidation(t)
}

func waitForStrippedRuntimeWeaverExport(t *testing.T, compose *docker.Compose) {
	t.Helper()
	command := exec.Command("docker", "compose", "-f", compose.Path, "port", "otelcol", "8888")
	command.Env = compose.Env
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	address := strings.TrimSpace(string(output))
	address = strings.Replace(address, "0.0.0.0:", "127.0.0.1:", 1)
	// Prometheus can observe OBI before the independent OTLP export reaches Weaver.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		response, err := http.Get("http://" + address + "/metrics")
		require.NoError(ct, err)
		defer response.Body.Close()
		require.Equal(ct, http.StatusOK, response.StatusCode)
		parser := expfmt.NewTextParser(model.UTF8Validation)
		metrics, err := parser.TextToMetricFamilies(response.Body)
		require.NoError(ct, err)
		var sent float64
		for name, family := range metrics {
			if !strings.HasPrefix(name, "otelcol_exporter_sent_metric_points") {
				continue
			}
			for _, metric := range family.Metric {
				for _, label := range metric.Label {
					if label.GetName() == "exporter" && label.GetValue() == "otlp/weaver" {
						sent += metric.GetCounter().GetValue()
					}
				}
			}
		}
		assert.Positive(ct, sent, "collector has not delivered runtime metrics to Weaver")
	}, testTimeout, 250*time.Millisecond)
}
