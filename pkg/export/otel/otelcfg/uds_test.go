// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

func TestUnixSocketEndpoint(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		addr     string
		ok       bool
	}{
		{endpoint: "unix:///var/run/obi.sock", addr: "/var/run/obi.sock", ok: true},
		{endpoint: "unix://@obi", addr: "@obi", ok: true},
		{endpoint: "http://localhost:4318", ok: false},
		{endpoint: "localhost:4317", ok: false},
	} {
		addr, ok := unixSocketEndpoint(tc.endpoint)
		assert.Equal(t, tc.ok, ok, tc.endpoint)
		assert.Equal(t, tc.addr, addr, tc.endpoint)
	}
}

func TestValidateUnixSocketAddr(t *testing.T) {
	require.NoError(t, validateUnixSocketAddr("/var/run/obi.sock"))
	require.NoError(t, validateUnixSocketAddr("@obi"))

	require.Error(t, validateUnixSocketAddr(""))
	require.Error(t, validateUnixSocketAddr("relative/path.sock"))
	require.Error(t, validateUnixSocketAddr("/"+strings.Repeat("a", unixPathMax)))
	require.Error(t, validateUnixSocketAddr("@"+strings.Repeat("a", unixPathMax)))
}

func TestGRPCUnixTarget(t *testing.T) {
	assert.Equal(t, "unix:///var/run/obi.sock", grpcUnixTarget("/var/run/obi.sock"))
	assert.Equal(t, "unix-abstract:obi", grpcUnixTarget("@obi"))
}

func TestUnixMetricsEndpointOptions(t *testing.T) {
	defer RestoreEnvAfterExecution()()

	t.Run("http abstract", func(t *testing.T) {
		opts, err := httpMetricEndpointOptions(&MetricsConfig{MetricsEndpoint: "unix://@obi"})
		require.NoError(t, err)
		assert.Equal(t, OTLPOptions{Endpoint: "localhost", Insecure: true, UnixSocketAddr: "@obi", Headers: map[string]string{}}, opts)
	})

	t.Run("grpc path", func(t *testing.T) {
		opts, err := grpcMetricEndpointOptions(&MetricsConfig{MetricsEndpoint: "unix:///var/run/obi.sock"})
		require.NoError(t, err)
		assert.Equal(t, OTLPOptions{Endpoint: "unix:///var/run/obi.sock", Insecure: true, UnixSocketAddr: "/var/run/obi.sock", Headers: map[string]string{}}, opts)
	})

	t.Run("invalid address", func(t *testing.T) {
		_, err := httpMetricEndpointOptions(&MetricsConfig{MetricsEndpoint: "unix://relative.sock"})
		require.Error(t, err)
	})
}

func TestUnixTracesEndpointOptions(t *testing.T) {
	defer RestoreEnvAfterExecution()()

	t.Run("http abstract", func(t *testing.T) {
		opts, err := HTTPTracesEndpointOptions(&TracesConfig{TracesEndpoint: "unix://@obi"})
		require.NoError(t, err)
		assert.Equal(t, OTLPOptions{Scheme: "http", Endpoint: "localhost", Insecure: true, UnixSocketAddr: "@obi", Headers: map[string]string{}}, opts)
	})

	t.Run("grpc path", func(t *testing.T) {
		opts, err := GRPCTracesEndpointOptions(&TracesConfig{TracesEndpoint: "unix:///var/run/obi.sock"})
		require.NoError(t, err)
		assert.Equal(t, OTLPOptions{Endpoint: "unix:///var/run/obi.sock", Insecure: true, UnixSocketAddr: "/var/run/obi.sock", Headers: map[string]string{}}, opts)
	})
}

func TestUnixSocketMetricsExporter(t *testing.T) {
	defer RestoreEnvAfterExecution()()

	lis, err := net.Listen("unix", "@obi-test-metrics")
	require.NoError(t, err)
	defer lis.Close()

	gotPath := make(chan string, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotPath <- r.URL.Path:
		default:
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Close()

	instancer := MetricsExporterInstancer{Cfg: &MetricsConfig{
		MetricsEndpoint:  "unix://@obi-test-metrics",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
	}}
	exp, err := instancer.Instantiate(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

	require.NoError(t, exp.Export(context.Background(), &metricdata.ResourceMetrics{}))

	select {
	case path := <-gotPath:
		assert.Equal(t, "/v1/metrics", path)
	case <-time.After(5 * time.Second):
		t.Fatal("metrics request not received over unix socket")
	}
}
