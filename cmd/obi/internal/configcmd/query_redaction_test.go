// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configcmd

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

func TestQueryParameterRedactionMigration(t *testing.T) {
	for _, legacy := range []string{
		"{}",
		"{add: [customer_secret]}",
		"{remove: [token, session]}",
		"{add: [token, customer_secret, customer_secret], remove: [token, session, unknown]}",
		"{add: [], remove: []}",
		"{remove: [" + strings.Join(attributes.DefaultSensitiveQueryParams, ", ") + "]}",
	} {
		for _, mode := range []validationMode{validationModeStandalone, validationModeReceiver} {
			t.Run(string(mode)+legacy, func(t *testing.T) {
				input := "open_port: '8080'\nattributes:\n  sensitive_query_params: " + legacy + "\n"
				if mode == validationModeStandalone {
					input += "otel_traces_export:\n  endpoint: http://localhost:4317\n"
				}
				before, _, err := loadV1ConfigForMode([]byte(input), mode, false)
				require.NoError(t, err)
				output, _, err := migrateConfigForMode([]byte(input), mode)
				require.NoError(t, err)
				require.NotContains(t, string(output), "sensitive_query_params:")
				var ext *schema.Extension
				if mode == validationModeStandalone {
					_, ext, err = schema.ParseStandaloneYAML(output)
				} else {
					ext, err = schema.ParseReceiverYAML(output)
					require.NotContains(t, string(output), "enrich:")
				}
				require.NoError(t, err)
				require.NotNil(t, ext.Capture.Instrumentation.HTTP.QueryParameters.Redaction.Names)
				require.Nil(t, ext.Capture.Instrumentation.HTTP.QueryParameters.Redaction.Replacement)
				after, err := convert.V2ToRuntime(ext)
				require.NoError(t, err)
				require.Equal(t, before.Attributes.SensitiveQueryParams.Effective(), after.Attributes.SensitiveQueryParams.Effective())
				require.NoError(t, validateConfig(output, mode))
			})
		}
	}
}

func TestMigrationDetectsChangedEffectiveRedaction(t *testing.T) {
	input := []byte("attributes: {sensitive_query_params: {add: [customer_secret], remove: [session]}}\n")
	before, _, err := loadV1ConfigForMode(input, validationModeReceiver, false)
	require.NoError(t, err)
	after := *before
	after.Attributes.SensitiveQueryParams = attributes.SensitiveQueryParamsConfig{}
	paths, err := changedInputFields(input, before, &after)
	require.NoError(t, err)
	require.Contains(t, paths, "attributes.sensitive_query_params")

	after.Attributes.SensitiveQueryParams = attributes.SensitiveQueryParamsConfig{
		Remove: slices.Clone(attributes.DefaultSensitiveQueryParams),
		Add:    before.Attributes.SensitiveQueryParams.Effective(),
	}
	paths, err = changedInputFields(input, before, &after)
	require.NoError(t, err)
	require.Empty(t, paths)
}
