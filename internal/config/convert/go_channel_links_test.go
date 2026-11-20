// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestGoChannelLinksYAML(t *testing.T) {
	t.Parallel()

	enabled, disabled := true, false
	for _, test := range []struct {
		name     string
		runtimes string
		want     *bool
	}{
		// unset keeps nil: whether the probes attach then depends on trace export
		{name: "omitted", runtimes: "{}"},
		{name: "empty Go section", runtimes: "{go: {}}"},
		{name: "enabled", runtimes: "{go: {channel_links: true}}", want: &enabled},
		{name: "disabled", runtimes: "{go: {channel_links: false}}", want: &disabled},
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
				require.Equal(t, test.want, got.EBPF.GoChannelLinks)
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
			docValue := enabled
			ext.Capture.Runtimes.Go.ChannelLinks = &docValue

			got, err := V2ToRuntime(ext)
			require.NoError(t, err)
			require.NotNil(t, got.EBPF.GoChannelLinks)
			require.Equal(t, enabled, *got.EBPF.GoChannelLinks)

			// import copies the value: writing through the document's pointer does not change it
			*ext.Capture.Runtimes.Go.ChannelLinks = !enabled
			require.Equal(t, enabled, *got.EBPF.GoChannelLinks)

			_, exported := RuntimeToV2(got)
			require.NotNil(t, exported.Capture.Runtimes.Go.ChannelLinks)
			require.Equal(t, enabled, *exported.Capture.Runtimes.Go.ChannelLinks)

			// export copies the value too
			*got.EBPF.GoChannelLinks = !enabled
			require.Equal(t, enabled, *exported.Capture.Runtimes.Go.ChannelLinks)
		}
	}

	got, err := V2ToRuntime(&schema.Extension{Version: schema.SupportedVersion})
	require.NoError(t, err)
	require.Nil(t, got.EBPF.GoChannelLinks)

	// an unset value round-trips as omitted, not as an explicit true
	_, exported := RuntimeToV2(got)
	require.Nil(t, exported.Capture.Runtimes.Go.ChannelLinks)
}
