// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

func TestHTTPTracesEndpoint(t *testing.T) {
	defer RestoreEnvAfterExecution()()
	tcfg := TracesConfig{
		CommonEndpoint:   "https://localhost:3131",
		TracesEndpoint:   "https://localhost:3232/v1/traces",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testHTTPTracesOptions(t, OTLPOptions{Scheme: "https", Endpoint: "localhost:3232", URLPath: "/v1/traces", Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:   "https://localhost:3131/otlp",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testHTTPTracesOptions(t, OTLPOptions{Scheme: "https", Endpoint: "localhost:3131", BaseURLPath: "/otlp", URLPath: "/otlp/v1/traces", Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:   "https://localhost:3131",
		TracesEndpoint:   "http://localhost:3232",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testHTTPTracesOptions(t, OTLPOptions{Scheme: "http", Endpoint: "localhost:3232", Insecure: true, Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
		Instrumentations:   []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testHTTPTracesOptions(t, OTLPOptions{Scheme: "https", Endpoint: "localhost:3232", URLPath: "/v1/traces", SkipTLSVerify: true, Headers: map[string]string{}}, &tcfg)
	})
}

func testHTTPTracesOptions(t *testing.T, expected OTLPOptions, tcfg *TracesConfig) {
	defer RestoreEnvAfterExecution()()
	opts, err := HTTPTracesEndpointOptions(tcfg)
	require.NoError(t, err)
	assert.Equal(t, expected, opts)
}

func TestMissingSchemeInHTTPTracesEndpoint(t *testing.T) {
	defer RestoreEnvAfterExecution()()
	opts, err := HTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "http://foo:3030", Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL}})
	require.NoError(t, err)
	require.NotEmpty(t, opts)

	_, err = HTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo:3030", Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL}})
	require.Error(t, err)

	_, err = HTTPTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo", Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL}})
	require.Error(t, err)
}

func TestHTTPTracesEndpointHeaders(t *testing.T) {
	type testCase struct {
		Description     string
		Env             map[string]string
		ExpectedHeaders map[string]string
	}
	for _, tc := range []testCase{
		{
			Description:     "No headers",
			ExpectedHeaders: map[string]string{},
		},
		{
			Description:     "defining common OTLP_HEADERS",
			Env:             map[string]string{"OTEL_EXPORTER_OTLP_HEADERS": "Foo=Bar ==,Authorization=Base 2222=="},
			ExpectedHeaders: map[string]string{"Foo": "Bar ==", "Authorization": "Base 2222=="},
		},
		{
			Description:     "defining common OTLP_TRACES_HEADERS",
			Env:             map[string]string{"OTEL_EXPORTER_OTLP_TRACES_HEADERS": "Foo=Bar ==,Authorization=Base 1234=="},
			ExpectedHeaders: map[string]string{"Foo": "Bar ==", "Authorization": "Base 1234=="},
		},
		{
			Description: "OTLP_TRACES_HEADERS takes precedence over OTLP_HEADERS",
			Env: map[string]string{
				"OTEL_EXPORTER_OTLP_HEADERS":        "Foo=Bar ==,Authorization=Base 3210==",
				"OTEL_EXPORTER_OTLP_TRACES_HEADERS": "Authorization=Base 1111==",
			},
			ExpectedHeaders: map[string]string{"Foo": "Bar ==", "Authorization": "Base 1111=="},
		},
	} {
		// mutex to avoid running testcases in parallel so we don't mess up with env vars
		mt := sync.Mutex{}
		t.Run(tc.Description, func(t *testing.T) {
			mt.Lock()
			restore := RestoreEnvAfterExecution()
			defer func() {
				restore()
				mt.Unlock()
			}()
			for k, v := range tc.Env {
				t.Setenv(k, v)
			}

			opts, err := HTTPTracesEndpointOptions(&TracesConfig{
				TracesEndpoint:   "https://localhost:1234/v1/traces",
				Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedHeaders, opts.Headers)
		})
	}
}

func TestGRPCTracesEndpointOptions(t *testing.T) {
	defer RestoreEnvAfterExecution()()
	t.Run("do not accept URLs without a scheme", func(t *testing.T) {
		_, err := GRPCTracesEndpointOptions(&TracesConfig{CommonEndpoint: "foo:3939", Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL}})
		require.Error(t, err)
	})
	tcfg := TracesConfig{
		CommonEndpoint:   "https://localhost:3131",
		TracesEndpoint:   "https://localhost:3232",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}

	t.Run("testing with two endpoints", func(t *testing.T) {
		testTracesGRPCOptions(t, OTLPOptions{Endpoint: "localhost:3232", Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:   "https://localhost:3131",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}

	t.Run("testing with only common endpoint", func(t *testing.T) {
		testTracesGRPCOptions(t, OTLPOptions{Endpoint: "localhost:3131", Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:   "https://localhost:3131",
		TracesEndpoint:   "http://localhost:3232",
		Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}
	t.Run("testing with insecure endpoint", func(t *testing.T) {
		testTracesGRPCOptions(t, OTLPOptions{Endpoint: "localhost:3232", Insecure: true, Headers: map[string]string{}}, &tcfg)
	})

	tcfg = TracesConfig{
		CommonEndpoint:     "https://localhost:3232",
		InsecureSkipVerify: true,
		Instrumentations:   []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
	}

	t.Run("testing with skip TLS verification", func(t *testing.T) {
		testTracesGRPCOptions(t, OTLPOptions{Endpoint: "localhost:3232", SkipTLSVerify: true, Headers: map[string]string{}}, &tcfg)
	})
}

func TestGRPCTracesEndpointHeaders(t *testing.T) {
	type testCase struct {
		Description     string
		Env             map[string]string
		ExpectedHeaders map[string]string
	}
	for _, tc := range []testCase{
		{
			Description:     "No headers",
			ExpectedHeaders: map[string]string{},
		},
		{
			Description:     "defining common OTLP_HEADERS",
			Env:             map[string]string{"OTEL_EXPORTER_OTLP_HEADERS": "Foo=Bar ==,Authorization=Base 2222=="},
			ExpectedHeaders: map[string]string{"Foo": "Bar ==", "Authorization": "Base 2222=="},
		},
		{
			Description:     "defining common OTLP_TRACES_HEADERS",
			Env:             map[string]string{"OTEL_EXPORTER_OTLP_TRACES_HEADERS": "Foo=Bar ==,Authorization=Base 1234=="},
			ExpectedHeaders: map[string]string{"Foo": "Bar ==", "Authorization": "Base 1234=="},
		},
		{
			Description: "OTLP_TRACES_HEADERS takes precedence over OTLP_HEADERS",
			Env: map[string]string{
				"OTEL_EXPORTER_OTLP_HEADERS":        "Foo=Bar ==,Authorization=Base 3210==",
				"OTEL_EXPORTER_OTLP_TRACES_HEADERS": "Authorization=Base 1111==",
			},
			ExpectedHeaders: map[string]string{"Foo": "Bar ==", "Authorization": "Base 1111=="},
		},
	} {
		// mutex to avoid running testcases in parallel so we don't mess up with env vars
		mt := sync.Mutex{}
		t.Run(tc.Description, func(t *testing.T) {
			mt.Lock()
			restore := RestoreEnvAfterExecution()
			defer func() {
				restore()
				mt.Unlock()
			}()
			for k, v := range tc.Env {
				t.Setenv(k, v)
			}

			opts, err := GRPCTracesEndpointOptions(&TracesConfig{
				TracesEndpoint:   "https://localhost:1234/v1/traces",
				Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedHeaders, opts.Headers)
		})
	}
}

func testTracesGRPCOptions(t *testing.T, expected OTLPOptions, tcfg *TracesConfig) {
	defer RestoreEnvAfterExecution()()
	opts, err := GRPCTracesEndpointOptions(tcfg)
	require.NoError(t, err)
	assert.Equal(t, expected, opts)
}

func TestTracesSetupHTTP_Protocol(t *testing.T) {
	testCases := []struct {
		Endpoint              string
		ProtoVal              Protocol
		TraceProtoVal         Protocol
		ExpectedProtoEnv      string
		ExpectedTraceProtoEnv string
	}{
		{ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "http/protobuf"},
		{ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4317", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "grpc"},
		{Endpoint: "http://foo:4317", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4317", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:4317", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:14317", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "grpc"},
		{Endpoint: "http://foo:14317", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:14317", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:14317", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4318", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "http/protobuf"},
		{Endpoint: "http://foo:4318", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:4318", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:4318", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:24318", ProtoVal: "", TraceProtoVal: "", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "http/protobuf"},
		{Endpoint: "http://foo:24318", ProtoVal: "", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
		{Endpoint: "http://foo:24318", ProtoVal: "bar", TraceProtoVal: "", ExpectedProtoEnv: "bar", ExpectedTraceProtoEnv: ""},
		{Endpoint: "http://foo:24318", ProtoVal: "bar", TraceProtoVal: "foo", ExpectedProtoEnv: "", ExpectedTraceProtoEnv: "foo"},
	}
	for _, tc := range testCases {
		t.Run(tc.Endpoint+"/"+string(tc.ProtoVal)+"/"+string(tc.TraceProtoVal), func(t *testing.T) {
			defer RestoreEnvAfterExecution()()
			_, err := HTTPTracesEndpointOptions(&TracesConfig{
				CommonEndpoint:   "http://host:3333",
				TracesEndpoint:   tc.Endpoint,
				Protocol:         tc.ProtoVal,
				TracesProtocol:   tc.TraceProtoVal,
				Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedProtoEnv, os.Getenv(envProtocol))
			assert.Equal(t, tc.ExpectedTraceProtoEnv, os.Getenv(envTracesProtocol))
		})
	}
}

func TestTracesSetupHTTP_DoNotOverrideEnv(t *testing.T) {
	defer RestoreEnvAfterExecution()()
	t.Run("setting both variables", func(t *testing.T) {
		defer RestoreEnvAfterExecution()()
		t.Setenv(envProtocol, "foo-proto")
		t.Setenv(envTracesProtocol, "bar-proto")
		_, err := HTTPTracesEndpointOptions(&TracesConfig{
			CommonEndpoint:   "http://host:3333",
			Protocol:         "foo",
			TracesProtocol:   "bar",
			Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
		})
		require.NoError(t, err)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
		assert.Equal(t, "bar-proto", os.Getenv(envTracesProtocol))
	})
	t.Run("setting only proto env var", func(t *testing.T) {
		defer RestoreEnvAfterExecution()()
		t.Setenv(envProtocol, "foo-proto")
		_, err := HTTPTracesEndpointOptions(&TracesConfig{
			CommonEndpoint:   "http://host:3333",
			Protocol:         "foo",
			Instrumentations: []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
		})
		require.NoError(t, err)
		_, ok := os.LookupEnv(envTracesProtocol)
		assert.False(t, ok)
		assert.Equal(t, "foo-proto", os.Getenv(envProtocol))
	})
}

func TestTracesConfig_Enabled(t *testing.T) {
	assert.True(t, (&TracesConfig{CommonEndpoint: "foo"}).Enabled())
	assert.True(t, (&TracesConfig{TracesEndpoint: "foo"}).Enabled())
}

func TestTracesConfig_Disabled(t *testing.T) {
	assert.False(t, (&TracesConfig{}).Enabled())
}
