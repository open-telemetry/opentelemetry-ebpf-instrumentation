// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configcmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
)

func TestReceiverCaptureAttributesMigration(t *testing.T) {
	for _, selection := range []string{
		"traces: {include: [service.peer.name]}",
		"traces: {include: [service.peer.name], exclude: [service.peer.name]}",
		"'*': {include: ['*']}",
		"'*': {include: ['*']}, traces: {exclude: [service.peer.name]}",
		"http_server_request_duration_seconds: {exclude: [http.route]}",
	} {
		t.Run(selection, func(t *testing.T) {
			input := []byte("open_port: '8080'\nattributes:\n  select: {" + selection + "}\n")
			before, _, err := loadV1ConfigForMode(input, validationModeReceiver, false)
			require.NoError(t, err)
			output, _, err := migrateConfigForMode(input, validationModeReceiver)
			require.NoError(t, err)
			require.NotContains(t, string(output), "enrich:")
			ext, err := schema.ParseReceiverYAML(output)
			require.NoError(t, err)
			after, err := convert.V2ToRuntime(ext)
			require.NoError(t, err)
			require.Equal(t, before.Attributes.Select, after.Attributes.Select)
		})
	}
}

func TestReceiverCaptureAttributesMigrationDoesNotDropResourceSelection(t *testing.T) {
	_, _, err := migrateConfigForMode([]byte("open_port: '8080'\nattributes:\n  select:\n    resource:\n      exclude: [host.name]\n"), validationModeReceiver)
	require.ErrorContains(t, err, "attributes.select.resource")
}
