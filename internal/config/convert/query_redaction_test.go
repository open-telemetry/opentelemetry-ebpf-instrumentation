// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

func TestHTTPQueryParameterRedactionConversion(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, http string
		want       []string
	}{
		{name: "omitted", http: "{}"},
		{name: "empty parent", http: "{query_parameters: {}}"},
		{name: "null parent", http: "{query_parameters: null}"},
		{name: "null list", http: "{query_parameters: {redaction: null}}"},
		{name: "empty list", http: "{query_parameters: {redaction: []}}", want: []string{}},
		{name: "explicit list", http: "{query_parameters: {redaction: [customer_secret, token]}}", want: []string{"customer_secret", "token"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := test.want
			if want == nil {
				want = attributes.DefaultSensitiveQueryParams
			}
			for _, parsed := range []bool{false, true} {
				input := []byte("version: '2.0'\ninstrumentation: {http: " + test.http + "}\n")
				ext, err := schema.ParseReceiverYAML(input)
				require.NoError(t, err)
				if !parsed {
					// Discard the source so the programmatic partial adapter is exercised.
					ext = &schema.Extension{Version: ext.Version, Capture: ext.Capture}
				}
				cfg, err := V2ToRuntime(ext)
				require.NoError(t, err)
				require.Equal(t, want, cfg.Attributes.SensitiveQueryParams.Effective())
				_, exported := RuntimeToV2(cfg)
				data, err := yaml.Marshal(exported)
				require.NoError(t, err)
				var roundTrip schema.Extension
				require.NoError(t, yaml.Unmarshal(data, &roundTrip))
				got, err := V2ToRuntime(&roundTrip)
				require.NoError(t, err)
				require.Equal(t, want, got.Attributes.SensitiveQueryParams.Effective())
			}
		})
	}
}

func TestHTTPQueryParameterRedactionLegacyRoundTrip(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.Attributes.SensitiveQueryParams = attributes.SensitiveQueryParamsConfig{
		Add:    []string{"customer_secret", "token", "customer_secret"},
		Remove: []string{"token", "session", "unknown"},
	}
	want := slices.Clone(cfg.Attributes.SensitiveQueryParams.Effective())
	_, ext := RuntimeToV2(&cfg)
	require.Equal(t, want, []string(*ext.Capture.Instrumentation.HTTP.QueryParameters.Redaction))
	got, err := V2ToRuntime(ext)
	require.NoError(t, err)
	require.Equal(t, want, got.Attributes.SensitiveQueryParams.Effective())
	require.Contains(t, got.Attributes.SensitiveQueryParams.Effective(), "token")
	require.NotContains(t, got.Attributes.SensitiveQueryParams.Effective(), "session")
}
