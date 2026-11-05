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
		{name: "null list", params: "{redaction: null}"},
		{name: "empty list", params: "{redaction: []}", want: new(Redaction{})},
		{name: "explicit list", params: "{redaction: [token, customer_secret]}", want: new(Redaction{"token", "customer_secret"})},
		{name: "quoted scalar names", params: "{redaction: ['123', 'true']}", want: new(Redaction{"123", "true"})},
		{name: "scalar", params: "{redaction: token}", wantErr: "redaction must be a list of strings"},
		{name: "object", params: "{redaction: {add: [token]}}", wantErr: "redaction must be a list of strings"},
		{name: "number", params: "{redaction: [123]}", wantErr: "redaction[0] must be a string"},
		{name: "boolean", params: "{redaction: [true]}", wantErr: "redaction[0] must be a string"},
		{name: "null entry", params: "{redaction: [null]}", wantErr: "redaction[0] must be a string"},
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
