// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

func TestHTTPMetricsEndpointOptions(t *testing.T) {
	defer RestoreEnvAfterExecution()()
	mcfg := MetricsConfig{
		CommonEndpoint:  "https://localhost:3131",
		MetricsEndpoint: "https://localhost:3232/v1/metrics",
		Instrumentations: []instrumentations.Instrumentation{
			instrumentations.InstrumentationHTTP,
		},
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testMetricsHTTPOptions(t, OTLPOptions{Endpoint: "localhost:3232", URLPath: "/v1/metrics", Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint: "https://localhost:3131/otlp",
		Instrumentations: []instrumentations.Instrumentation{
			instrumentations.InstrumentationHTTP,
		},
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testMetricsHTTPOptions(t, OTLPOptions{Endpoint: "localhost:3131", URLPath: "/otlp/v1/metrics", Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint:  "https://localhost:3131",
		MetricsEndpoint: "http://localhost:3232",
		Instrumentations: []instrumentations.Instrumentation{
			instrumentations.InstrumentationHTTP,
		},
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testMetricsHTTPOptions(t, OTLPOptions{Endpoint: "localhost:3232", Insecure: true, Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
		Instrumentations: []instrumentations.Instrumentation{
			instrumentations.InstrumentationHTTP,
		},
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testMetricsHTTPOptions(t, OTLPOptions{Endpoint: "localhost:3232", URLPath: "/v1/metrics", SkipTLSVerify: true, Headers: map[string]string{}}, &mcfg)
	})
}

func testMetricsHTTPOptions(t *testing.T, expected OTLPOptions, mcfg *MetricsConfig) {
	defer RestoreEnvAfterExecution()()
	opts, err := httpMetricEndpointOptions(mcfg)
	require.NoError(t, err)
	assert.Equal(t, expected, opts)
}

func TestMissingSchemeInMetricsEndpoint(t *testing.T) {
	defer RestoreEnvAfterExecution()()
	opts, err := httpMetricEndpointOptions(&MetricsConfig{CommonEndpoint: "http://foo:3030", Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP}})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = httpMetricEndpointOptions(&MetricsConfig{CommonEndpoint: "foo:3030", Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP}})
	require.Error(t, err)

	_, err = httpMetricEndpointOptions(&MetricsConfig{CommonEndpoint: "foo", Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP}})
	require.Error(t, err)
}

func TestGRPCMetricsEndpointOptions(t *testing.T) {
	defer RestoreEnvAfterExecution()()
	t.Run("do not accept URLs without a scheme", func(t *testing.T) {
		_, err := grpcMetricEndpointOptions(&MetricsConfig{CommonEndpoint: "foo:3939"})
		require.Error(t, err)
	})

	mcfg := MetricsConfig{
		CommonEndpoint:   "https://localhost:3131",
		MetricsEndpoint:  "https://localhost:3232",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testMetricsGRPCOptions(t, OTLPOptions{Endpoint: "localhost:3232", Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint:   "https://localhost:3131",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testMetricsGRPCOptions(t, OTLPOptions{Endpoint: "localhost:3131", Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint:   "https://localhost:3131",
		MetricsEndpoint:  "http://localhost:3232",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testMetricsGRPCOptions(t, OTLPOptions{Endpoint: "localhost:3232", Insecure: true, Headers: map[string]string{}}, &mcfg)
	})

	mcfg = MetricsConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
		Instrumentations:   []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testMetricsGRPCOptions(t, OTLPOptions{Endpoint: "localhost:3232", SkipTLSVerify: true, Headers: map[string]string{}}, &mcfg)
	})
}

func testMetricsGRPCOptions(t *testing.T, expected OTLPOptions, mcfg *MetricsConfig) {
	defer RestoreEnvAfterExecution()()
	opts, err := grpcMetricEndpointOptions(mcfg)
	require.NoError(t, err)
	assert.Equal(t, expected, opts)
}

func TestMetricsSetupHTTP_Protocol(t *testing.T) {
	testCases := []struct {
		Endpoint               string
		ProtoVal               Protocol
		MetricProtoVal         Protocol
		ExpectedProtoEnv       string
		ExpectedMetricProtoEnv string
	}{
		{ProtoVal: "", MetricProtoVal: "", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "http/protobuf"},
		{ProtoVal: "", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{ProtoVal: "bar", MetricProtoVal: "", ExpectedProtoEnv: "bar", ExpectedMetricProtoEnv: ""},
		{ProtoVal: "bar", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:4317", ProtoVal: "", MetricProtoVal: "", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "grpc"},
		{Endpoint: "http://foo:4317", ProtoVal: "", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:4317", ProtoVal: "bar", MetricProtoVal: "", ExpectedProtoEnv: "bar", ExpectedMetricProtoEnv: ""},
		{Endpoint: "http://foo:4317", ProtoVal: "bar", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:14317", ProtoVal: "", MetricProtoVal: "", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "grpc"},
		{Endpoint: "http://foo:14317", ProtoVal: "", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:14317", ProtoVal: "bar", MetricProtoVal: "", ExpectedProtoEnv: "bar", ExpectedMetricProtoEnv: ""},
		{Endpoint: "http://foo:14317", ProtoVal: "bar", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:4318", ProtoVal: "", MetricProtoVal: "", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "http/protobuf"},
		{Endpoint: "http://foo:4318", ProtoVal: "", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:4318", ProtoVal: "bar", MetricProtoVal: "", ExpectedProtoEnv: "bar", ExpectedMetricProtoEnv: ""},
		{Endpoint: "http://foo:4318", ProtoVal: "bar", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:24318", ProtoVal: "", MetricProtoVal: "", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "http/protobuf"},
		{Endpoint: "http://foo:24318", ProtoVal: "", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
		{Endpoint: "http://foo:24318", ProtoVal: "bar", MetricProtoVal: "", ExpectedProtoEnv: "bar", ExpectedMetricProtoEnv: ""},
		{Endpoint: "http://foo:24318", ProtoVal: "bar", MetricProtoVal: "foo", ExpectedProtoEnv: "", ExpectedMetricProtoEnv: "foo"},
	}
	for _, tc := range testCases {
		t.Run(tc.Endpoint+"/"+string(tc.ProtoVal)+"/"+string(tc.MetricProtoVal), func(t *testing.T) {
			defer RestoreEnvAfterExecution()()
			_, err := httpMetricEndpointOptions(&MetricsConfig{
				CommonEndpoint:   "http://host:3333",
				MetricsEndpoint:  tc.Endpoint,
				Protocol:         tc.ProtoVal,
				MetricsProtocol:  tc.MetricProtoVal,
				Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedProtoEnv, os.Getenv(envProtocol))
			assert.Equal(t, tc.ExpectedMetricProtoEnv, os.Getenv(envMetricsProtocol))
		})
	}
}

func TestMetricSetupHTTP_DoNotOverrideEnv(t *testing.T) {
	t.Run("setting both variables", func(t *testing.T) {
		defer RestoreEnvAfterExecution()()
		t.Setenv(envProtocol, "foo-proto")
		t.Setenv(envMetricsProtocol, "bar-proto")
		_, err := httpMetricEndpointOptions(&MetricsConfig{
			CommonEndpoint: "http://host:3333", Protocol: "foo", MetricsProtocol: "bar", Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
		})
		require.NoError(t, err)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
		assert.Equal(t, "bar-proto", os.Getenv(envMetricsProtocol))
	})
	t.Run("setting only proto env var", func(t *testing.T) {
		defer RestoreEnvAfterExecution()()
		t.Setenv(envProtocol, "foo-proto")
		_, err := httpMetricEndpointOptions(&MetricsConfig{
			CommonEndpoint: "http://host:3333", Protocol: "foo", Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
		})
		require.NoError(t, err)
		_, ok := os.LookupEnv(envMetricsProtocol)
		assert.False(t, ok)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
	})
}

func TestMetricsInterval(t *testing.T) {
	cfg := MetricsConfig{
		OTELIntervalMS: 60_000,
	}
	t.Run("If only OTEL is defined, it uses that value", func(t *testing.T) {
		assert.Equal(t, 60*time.Second, cfg.GetInterval())
	})
	cfg.Interval = 5 * time.Second
	t.Run("Beyla interval takes precedence over OTEL", func(t *testing.T) {
		assert.Equal(t, 5*time.Second, cfg.GetInterval())
	})
}
