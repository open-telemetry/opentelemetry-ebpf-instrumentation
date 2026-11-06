// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestHTTPQueryParameterRedactionYAML(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, params string
		want         *Redaction
		wantErr      string
	}{
		{name: "empty parent", params: "{}"},
		{name: "null parent", params: "null"},
		{name: "null policy", params: "{redaction: null}"},
		{name: "empty policy", params: "{redaction: {}}", want: new(Redaction{})},
		{name: "null fields", params: "{redaction: {names: null, replacement: null}}", want: new(Redaction{})},
		{name: "empty names", params: "{redaction: {names: []}}", want: new(Redaction{Names: new([]string{})})},
		{name: "explicit names", params: "{redaction: {names: [token, customer_secret]}}", want: new(Redaction{Names: new([]string{"token", "customer_secret"})})},
		{name: "quoted scalar names", params: "{redaction: {names: ['123', 'true']}}", want: new(Redaction{Names: new([]string{"123", "true"})})},
		{name: "custom replacement", params: "{redaction: {replacement: '[hidden]'}}", want: new(Redaction{Replacement: new("[hidden]")})},
		{name: "empty replacement", params: "{redaction: {replacement: ''}}", want: new(Redaction{Replacement: new("")})},
		{name: "complete policy", params: "{redaction: {names: [token], replacement: hidden}}", want: new(Redaction{Names: new([]string{"token"}), Replacement: new("hidden")})},
		{name: "name aliases", params: "{redaction: {names: [&key token, *key]}}", want: new(Redaction{Names: new([]string{"token", "token"})})},
		{name: "number alias", params: "{redaction: {names: [&key 123, *key]}}", wantErr: "redaction.names[0] must be a string"},
		{name: "merged policy", params: "{redaction: {<<: {names: [token], replacement: hidden}}}", want: new(Redaction{Names: new([]string{"token"}), Replacement: new("hidden")})},
		{name: "merged number name", params: "{redaction: {<<: {names: [123]}}}", wantErr: "redaction.names[0] must be a string"},
		{name: "merged number replacement", params: "{redaction: {<<: {replacement: 123}}}", wantErr: "redaction.replacement must be a string"},
		{name: "scalar policy", params: "{redaction: token}", wantErr: "redaction must be an object"},
		{name: "list policy", params: "{redaction: [token]}", wantErr: "redaction must be an object"},
		{name: "scalar names", params: "{redaction: {names: token}}", wantErr: "redaction.names must be a list of strings"},
		{name: "number name", params: "{redaction: {names: [123]}}", wantErr: "redaction.names[0] must be a string"},
		{name: "boolean name", params: "{redaction: {names: [true]}}", wantErr: "redaction.names[0] must be a string"},
		{name: "null name", params: "{redaction: {names: [null]}}", wantErr: "redaction.names[0] must be a string"},
		{name: "number replacement", params: "{redaction: {replacement: 123}}", wantErr: "redaction.replacement must be a string"},
		{name: "boolean replacement", params: "{redaction: {replacement: true}}", wantErr: "redaction.replacement must be a string"},
		{name: "unknown policy field", params: "{redaction: {add: [token]}}", wantErr: "field add not found"},
		{name: "unknown field", params: "{redactions: [token]}", wantErr: "field redactions not found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			receiver := "version: '2.0'\ninstrumentation: {http: {query_parameters: " + test.params + "}}\n"
			standalone := "file_format: '1.0'\nextensions: {obi: {version: '2.0', capture: {instrumentation: {http: {query_parameters: " + test.params + "}}}}}\n"
			for mode, input := range map[string]string{"receiver": receiver, "standalone": standalone} {
				t.Run(mode, func(t *testing.T) {
					var ext *Extension
					var err error
					if mode == "receiver" {
						ext, err = ParseReceiverYAML([]byte(input))
					} else {
						_, ext, err = ParseStandaloneYAML([]byte(input))
					}
					if test.wantErr != "" {
						require.ErrorContains(t, err, test.wantErr)
						return
					}
					require.NoError(t, err)
					require.Equal(t, test.want, ext.Capture.Instrumentation.HTTP.QueryParameters.Redaction)
					data, err := yaml.Marshal(ext.Capture.Instrumentation.HTTP.QueryParameters)
					require.NoError(t, err)
					var roundTrip HTTPQueryParameters
					require.NoError(t, yaml.Unmarshal(data, &roundTrip))
					require.Equal(t, test.want, roundTrip.Redaction)
				})
			}
		})
	}
}
