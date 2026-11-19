// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestHeadersFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  map[string]string
	}{
		{name: "encoded space", value: "Authorization=Basic%20dXNlcjpwYXNz", want: map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}},
		{name: "encoded delimiters", value: "key=a%2Cb%3Dc%25", want: map[string]string{"key": "a,b=c%"}},
		{name: "literal plus", value: "key=a+b", want: map[string]string{"key": "a+b"}},
		{name: "unencoded space", value: "Authorization=Basic dXNlcjpwYXNz", want: map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}},
		{name: "encoded whitespace", value: "key=%20value%20", want: map[string]string{"key": "value"}},
		{name: "decode once", value: "key=a%2520b", want: map[string]string{"key": "a%20b"}},
		{name: "invalid escape", value: "bad=%zz,good=value", want: map[string]string{"good": "value"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envHeaders, tc.value)
			assert.Equal(t, tc.want, HeadersFromEnv(envHeaders))
		})
	}
}

func TestMetricsExporterEncodedAuthHeader(t *testing.T) {
	for _, headerEnv := range []string{envHeaders, envMetricsHeaders} {
		t.Run(headerEnv, func(t *testing.T) {
			defer RestoreEnvAfterExecution()()
			t.Setenv(envHeaders, "")
			t.Setenv(envMetricsHeaders, "")
			t.Setenv(headerEnv, "Authorization=Basic%20dXNlcjpwYXNz")

			gotHeader := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				header := r.Header.Get("Authorization")
				gotHeader <- header
				if header != "Basic dXNlcjpwYXNz" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			instancer := MetricsExporterInstancer{Cfg: &MetricsConfig{
				MetricsEndpoint: server.URL + "/v1/metrics",
				MetricsProtocol: ProtocolHTTPProtobuf,
			}}
			exp, err := instancer.Instantiate(t.Context())
			require.NoError(t, err)
			defer func() { assert.NoError(t, exp.Shutdown(t.Context())) }()

			require.NoError(t, exp.Export(t.Context(), &metricdata.ResourceMetrics{}))
			select {
			case header := <-gotHeader:
				assert.Equal(t, "Basic dXNlcjpwYXNz", header)
			case <-time.After(testTimeout):
				t.Fatal("no export request received")
			}
		})
	}
}
