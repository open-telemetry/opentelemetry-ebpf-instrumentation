// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestGoRuntimeOptionsYAML(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name             string
		runtimes         string
		disableNamespace bool
		disabled         bool
	}{
		{name: "omitted", runtimes: "{}"},
		{name: "empty Go section", runtimes: "{go: {}}"},
		{name: "namespace disabled", runtimes: "{go: {infer_service_namespace: false}}", disableNamespace: true},
		{name: "enabled", runtimes: "{go: {channel_links: true}}"},
		{name: "disabled", runtimes: "{go: {channel_links: false}}", disabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, standalone, err := schema.ParseStandaloneYAML([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      runtimes: ` + test.runtimes + "\n"))
			require.NoError(t, err)

			receiver, err := schema.ParseReceiverYAML([]byte("version: \"2.0\"\nruntimes: " + test.runtimes + "\n"))
			require.NoError(t, err)

			for _, ext := range []*schema.Extension{standalone, receiver} {
				got, err := V2ToRuntime(ext)
				require.NoError(t, err)
				require.Equal(t, test.disabled, got.EBPF.DisableGoChannelLinks)
				require.Equal(t, test.disableNamespace, got.Discovery.DisableGoServiceNamespaceInference)
				_, exported := RuntimeToV2(got)
				require.Equal(t, !test.disableNamespace, *exported.Capture.Runtimes.Go.InferServiceNamespace)
				require.Equal(t, obi.DefaultConfig.Discovery.SkipGoSpecificTracers, got.Discovery.SkipGoSpecificTracers)
			}
		})
	}
}

func TestGoChannelLinksProgrammaticConfig(t *testing.T) {
	t.Parallel()

	for _, enabled := range []bool{false, true} {
		for _, complete := range []bool{false, true} {
			ext := &schema.Extension{Version: schema.SupportedVersion}
			if complete {
				_, ext = RuntimeToV2(nil)
			}
			ext.Capture.Runtimes.Go.ChannelLinks = &enabled

			got, err := V2ToRuntime(ext)
			require.NoError(t, err)
			require.Equal(t, !enabled, got.EBPF.DisableGoChannelLinks)

			_, exported := RuntimeToV2(got)
			require.NotNil(t, exported.Capture.Runtimes.Go.ChannelLinks)
			require.Equal(t, enabled, *exported.Capture.Runtimes.Go.ChannelLinks)
		}
	}

	got, err := V2ToRuntime(&schema.Extension{Version: schema.SupportedVersion})
	require.NoError(t, err)
	require.False(t, got.EBPF.DisableGoChannelLinks)
}
