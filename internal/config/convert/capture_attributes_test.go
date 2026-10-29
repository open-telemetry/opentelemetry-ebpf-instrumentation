// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestV2AttributeSelectionCompatibility(t *testing.T) {
	for _, selection := range []string{
		"{}",
		"{traces: {include: [service.peer.name]}}",
		"{traces: {exclude: [url.query]}}",
		"{traces: {include: [service.peer.name], exclude: [service.peer.name]}}",
		"{'*': {include: ['*']}}",
		"{'*': {include: ['*']}, traces: {exclude: [service.peer.name]}}",
		"{http_server_request_duration_seconds: {exclude: [http.route]}}",
		"{traces: {include: [gen_ai.*]}}",
		"{traces: {include: [gen_ai.tool.call.arguments]}}",
		"{unknown_metric: {include: [unknown_attribute]}}",
	} {
		t.Run(selection, func(t *testing.T) {
			prefix := "file_format: '1.0'\nextensions:\n  obi:\n    version: '2.0'\n"
			_, old, err := schema.ParseStandaloneYAML([]byte(prefix + "    enrich:\n      attributes:\n        select: " + selection + "\n"))
			require.NoError(t, err)
			before, err := V2ToRuntime(old)
			require.NoError(t, err)
			_, canonical, err := schema.ParseStandaloneYAML([]byte(prefix + "    capture:\n      attributes:\n        select: " + selection + "\n"))
			require.NoError(t, err)
			after, err := V2ToRuntime(canonical)
			require.NoError(t, err)
			require.Equal(t, before, after)
			document, output := RuntimeToV2(before)
			require.Empty(t, output.Enrich.Attributes.Select)
			data, err := yaml.Marshal(document)
			require.NoError(t, err)
			parsed, _, err := schema.ParseStandaloneYAML(data)
			require.NoError(t, err)
			roundTrip, err := DocumentToRuntime(parsed)
			require.NoError(t, err)
			require.Equal(t, before.Attributes.Select, roundTrip.Attributes.Select)
		})
	}
}

func TestV2CaptureAttributeSelection(t *testing.T) {
	ext, err := schema.ParseReceiverYAML([]byte(`version: "2.0"
attributes:
  select:
    traces:
      include: [service.peer.name]
    http.server.request.duration:
      exclude: [http.route]
`))
	require.NoError(t, err)
	cfg, err := V2ToRuntime(ext)
	require.NoError(t, err)
	selector, err := attributes.NewAttrSelector(attributes.GroupHTTPRoutes, &attributes.SelectorConfig{SelectionCfg: cfg.Attributes.Select})
	require.NoError(t, err)
	require.Equal(t, []attr.Name{attr.ServicePeerName}, selector.For(attributes.Traces))
	require.NotContains(t, selector.For(attributes.HTTPServerDuration), attr.HTTPRoute)
	require.Contains(t, selector.For(attributes.HTTPServerDuration), attr.HTTPRequestMethod)

	baseline, err := schema.ParseReceiverYAML([]byte(`version: "2.0"`))
	require.NoError(t, err)
	before, err := V2ToRuntime(baseline)
	require.NoError(t, err)
	require.Equal(t, before.NameResolver, cfg.NameResolver)
	require.Equal(t, before.Attributes.Kubernetes, cfg.Attributes.Kubernetes)
	require.Equal(t, before.CloudMetadata, cfg.CloudMetadata)
	require.Equal(t, before.EBPF.PayloadExtraction, cfg.EBPF.PayloadExtraction)
}

func TestV2AttributeSelectionConflicts(t *testing.T) {
	for _, test := range []struct {
		name, capture, legacy, wantError string
	}{
		{"resource separate", "{traces: {include: [service.peer.name]}}", "{resource: {exclude: [host.name]}}", ""},
		{"resource in capture", "{resource: {exclude: [host.name]}}", "{}", "capture.attributes.select.resource"},
		{"duplicate traces", "{traces: {include: [service.peer.name]}}", "{traces: {include: [service.peer.name]}}", "cannot both be configured"},
		{"different signals", "{traces: {include: [service.peer.name]}}", "{http.server.request.duration: {exclude: [http.route]}}", "cannot both be configured"},
		{"legacy wildcard", "{traces: {include: [service.peer.name]}}", "{'*': {include: ['*']}}", "cannot both be configured"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, ext, err := schema.ParseStandaloneYAML([]byte("file_format: '1.0'\nextensions:\n  obi:\n    version: '2.0'\n    capture:\n      attributes:\n        select: " + test.capture + "\n    enrich:\n      attributes:\n        select: " + test.legacy + "\n"))
			require.NoError(t, err)
			cfg, err := V2ToRuntime(ext)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			require.Contains(t, cfg.Attributes.Select, attributes.Resource.Section)
			require.Contains(t, cfg.Attributes.Select, attributes.Traces.Section)
		})
	}
}
