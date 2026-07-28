// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/ory/dockertest/v4"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const (
	goAutoSDKPort            = "8090"
	goAutoSDKProcess         = "goautosdk"
	goAutoSDKMetricsURL      = "http://localhost:8999/internal/metrics"
	goAutoSDKTraceQueryLimit = "256"
)

type goAutoSDKVersion struct {
	version    string
	dockerfile string
	image      string
}

func TestGoAutoSDKActivation(t *testing.T) {
	if KernelLockdownMode() {
		t.Skip("Go Auto SDK activation requires bpf_probe_write_user")
	}

	network := setupDockerNetwork(t)
	setupContainerJaeger(t, network)

	versions := []goAutoSDKVersion{
		{
			version:    "1.33.0",
			dockerfile: "internal/test/integration/components/goautosdk/Dockerfile-1.33",
			image:      "hatest-goautosdk-133",
		},
		{
			version:    "1.44.0",
			dockerfile: "internal/test/integration/components/goautosdk/Dockerfile-1.44",
			image:      "hatest-goautosdk-144",
		},
	}

	for _, version := range versions {
		t.Run("otel-"+version.version, func(t *testing.T) {
			service := "goautosdk-" + strings.ReplaceAll(version.version, ".", "-")
			setupGoAutoSDKServer(t, network, version, service)

			o := obi{
				Env: []string{
					"OTEL_EBPF_EXECUTABLE_PATH=" + goAutoSDKProcess,
					"OTEL_EBPF_OPEN_PORT=" + goAutoSDKPort,
				},
				SecurityConfigSuffix: "_none",
				Logs:                 createLogOutput(t, "go-auto-sdk-"+version.version),
			}
			o.instrument(t, network, "obi-config-go-auto-sdk.yml")

			waitForGoAutoSDKInstrumentation(t)
			waitForGoAutoSDKActivation(t)

			t.Run("rich root and child spans", func(t *testing.T) {
				testGoAutoSDKRichSpans(t, version.version, service)
			})
			t.Run("page boundary span contexts", func(t *testing.T) {
				testGoAutoSDKPageBoundarySpans(t, version.version, service)
			})
			t.Run("oversized payload cleanup", func(t *testing.T) {
				testGoAutoSDKOversizedPayload(t, version.version, service)
			})
		})
	}
}

func setupGoAutoSDKServer(
	t *testing.T,
	network dockertest.Network,
	version goAutoSDKVersion,
	service string,
) {
	t.Helper()

	require.NoError(
		t,
		buildDockerImage(t.Context(), t.Output(), version.image, version.dockerfile),
		"could not build Go Auto SDK %s fixture",
		version.version,
	)

	server, err := dockerPool.Run(
		t.Context(),
		version.image,
		dockertest.WithName(fmt.Sprintf("goautosdk-%s-%d", strings.ReplaceAll(version.version, ".", "-"), time.Now().UnixNano())),
		dockertest.WithEnv([]string{
			"OTEL_TEST_VERSION=" + version.version,
			"OTEL_SERVICE_NAME=" + service,
		}),
		dockertest.WithPortBindings(portBindings(goAutoSDKPort+"/tcp", goAutoSDKPort)),
		dockertest.WithContainerConfig(func(config *container.Config) {
			config.ExposedPorts = exposedPorts(goAutoSDKPort + "/tcp")
		}),
		dockertest.WithoutReuse(),
	)
	require.NoError(t, err, "could not start Go Auto SDK %s fixture", version.version)
	t.Cleanup(func() {
		require.NoError(t, server.Close(context.Background()), "could not remove Go Auto SDK fixture")
	})

	_, err = dockerPool.Client().NetworkConnect(t.Context(), network.ID(), client.NetworkConnectOptions{
		Container: server.ID(),
	})
	require.NoError(t, err, "could not connect Go Auto SDK fixture to test network")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get("http://localhost:" + goAutoSDKPort + "/health")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
	}, testTimeout, 100*time.Millisecond)
}

func waitForGoAutoSDKInstrumentation(t *testing.T) {
	t.Helper()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(goAutoSDKMetricsURL)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		parser := expfmt.NewTextParser(model.UTF8Validation)
		metrics, err := parser.TextToMetricFamilies(resp.Body)
		require.NoError(ct, err)
		instrumented, ok := metrics["obi_instrumented_processes"]
		require.True(ct, ok)

		for _, metric := range instrumented.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "process_name" &&
					label.GetValue() == goAutoSDKProcess &&
					metric.GetGauge().GetValue() == 1 {
					return
				}
			}
		}
		require.Fail(ct, "Go Auto SDK fixture was not instrumented")
	}, testTimeout, 100*time.Millisecond)
}

func waitForGoAutoSDKActivation(t *testing.T) {
	t.Helper()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get("http://localhost:" + goAutoSDKPort + "/activation")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusNoContent, resp.StatusCode)
	}, testTimeout, 100*time.Millisecond)
}

func testGoAutoSDKRichSpans(t *testing.T, version, service string) {
	ti.DoHTTPGet(t, "http://localhost:"+goAutoSDKPort+"/spans", http.StatusOK)

	rootName := autoSDKSpanName("root", version)
	trace := waitForGoAutoSDKTrace(t, service, rootName)

	require.Len(t, trace.Spans, 2, "rich spans must not have synthetic duplicates")
	roots := trace.FindByOperationName(rootName, "producer")
	require.Len(t, roots, 1)
	root := roots[0]
	require.Empty(t, root.References)
	require.NotEmpty(t, root.TraceID)
	require.NotEmpty(t, root.SpanID)
	assert.Empty(t, root.Diff(
		jaeger.Tag{Key: "activation.version", Type: "string", Value: version},
		jaeger.Tag{Key: "activation.root", Type: "bool", Value: true},
		jaeger.Tag{Key: "otel.library.name", Type: "string", Value: "go-auto-sdk-activation-test"},
		jaeger.Tag{Key: "otel.library.version", Type: "string", Value: "v1.0.0"},
	))
	require.Len(t, root.Logs, 1)
	assert.Empty(t, jaeger.Diff([]jaeger.Tag{
		{Key: "event", Type: "string", Value: "root event"},
		{Key: "event.detail", Type: "string", Value: "preserved"},
	}, root.Logs[0].Fields))

	childName := autoSDKSpanName("child", version)
	children := trace.FindByOperationName(childName, "client")
	require.Len(t, children, 1)
	child := children[0]
	require.Equal(t, root.TraceID, child.TraceID)

	parent, ok := trace.ParentOf(&child)
	require.True(t, ok)
	assert.Equal(t, root.SpanID, parent.SpanID)
	assert.Empty(t, child.Diff(
		jaeger.Tag{Key: "activation.answer", Type: "int64", Value: float64(42)},
		jaeger.Tag{Key: "otel.status_code", Type: "string", Value: "ERROR"},
		jaeger.Tag{Key: "otel.status_description", Type: "string", Value: "expected test status"},
	))
	require.Len(t, child.Logs, 1)
	assert.Empty(t, jaeger.Diff([]jaeger.Tag{
		{Key: "event", Type: "string", Value: "exception"},
		{Key: "exception.message", Type: "string", Value: "expected test error"},
		{Key: "error.detail", Type: "string", Value: "preserved"},
	}, child.Logs[0].Fields))
}

func testGoAutoSDKPageBoundarySpans(t *testing.T, version, service string) {
	since := time.Now()
	resp, err := http.Get("http://localhost:" + goAutoSDKPort + "/page-boundary")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	spanAddress := resp.Header.Get("X-Auto-SDK-Span-Address")
	require.NotEmpty(t, spanAddress)

	if version == "1.33.0" {
		waitForGoAutoSDKDeferredContextWrite(t, spanAddress, since)
	}

	rootName := autoSDKSpanName("page-boundary-root", version)
	trace := waitForGoAutoSDKTrace(t, service, rootName)

	require.Len(t, trace.Spans, 2)
	roots := trace.FindByOperationName(rootName, "internal")
	require.Len(t, roots, 1)
	require.NotEmpty(t, roots[0].TraceID)
	require.NotEmpty(t, roots[0].SpanID)
	require.Empty(t, roots[0].References)

	children := trace.FindByOperationName(autoSDKSpanName("page-boundary-child", version), "internal")
	require.Len(t, children, 1)
	require.Equal(t, roots[0].TraceID, children[0].TraceID)
	parent, ok := trace.ParentOf(&children[0])
	require.True(t, ok)
	assert.Equal(t, roots[0].SpanID, parent.SpanID)
}

func waitForGoAutoSDKDeferredContextWrite(t *testing.T, spanAddress string, since time.Time) {
	t.Helper()

	marker := "go auto SDK deferred context span=" + spanAddress
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := fetchOBILogsSince(since)
		require.NoError(ct, err)
		require.Contains(ct, logs, marker)
	}, testTimeout, 100*time.Millisecond)
}

func fetchOBILogsSince(since time.Time) (string, error) {
	logs, err := dockerPool.Client().ContainerLogs(context.Background(), "obi", client.ContainerLogsOptions{
		ShowStderr: true,
		ShowStdout: true,
		Since:      since.Format(time.RFC3339Nano),
	})
	if err != nil {
		return "", err
	}
	defer logs.Close()

	var output bytes.Buffer
	if _, err := stdcopy.StdCopy(&output, &output, logs); err != nil {
		return "", err
	}
	return output.String(), nil
}

func testGoAutoSDKOversizedPayload(t *testing.T, version, service string) {
	ti.DoHTTPGet(t, "http://localhost:"+goAutoSDKPort+"/oversized", http.StatusOK)

	afterName := autoSDKSpanName("after-oversized", version)
	trace := waitForGoAutoSDKTrace(t, service, afterName)
	require.Len(t, trace.Spans, 1)
	after := trace.FindByOperationName(afterName, "internal")
	require.Len(t, after, 1)
	assert.Empty(t, after[0].References, "oversized span state must be cleaned up before the next root span")

	var queryErr error
	absent := assert.Never(t, func() bool {
		var oversized jaeger.TracesQuery
		oversized, queryErr = fetchGoAutoSDKTraces(service, autoSDKSpanName("oversized", version))
		return queryErr != nil || len(oversized.Data) != 0
	}, 2*time.Second, 100*time.Millisecond, "payloads exceeding the 16 KiB bound must be dropped")
	require.NoError(t, queryErr)
	require.True(t, absent)
}

func waitForGoAutoSDKTrace(t *testing.T, service, operation string) jaeger.Trace {
	t.Helper()

	var traces jaeger.TracesQuery
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		traces, err = fetchGoAutoSDKTraces(service, operation)
		require.NoError(ct, err)
		require.Len(ct, traces.Data, 1)
	}, testTimeout, 100*time.Millisecond)

	return traces.Data[0]
}

func fetchGoAutoSDKTraces(service, operation string) (jaeger.TracesQuery, error) {
	params := url.Values{
		"service":   {service},
		"operation": {operation},
		"limit":     {goAutoSDKTraceQueryLimit},
	}
	resp, err := http.Get(jaegerQueryURL + "?" + params.Encode())
	if err != nil {
		return jaeger.TracesQuery{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return jaeger.TracesQuery{}, fmt.Errorf("query Jaeger: status %s", resp.Status)
	}

	var traces jaeger.TracesQuery
	if err := json.NewDecoder(resp.Body).Decode(&traces); err != nil {
		return jaeger.TracesQuery{}, err
	}
	return traces, nil
}

func autoSDKSpanName(name, version string) string {
	return fmt.Sprintf("auto-sdk-%s-%s", name, version)
}
