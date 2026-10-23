// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestFridaV2Configuration(t *testing.T) {
	t.Parallel()
	_, extension, err := schema.ParseStandaloneYAML([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      runtimes:
        frida:
          enabled: true
          library: /opt/obi-frida/libfrida-core.so
`))
	require.NoError(t, err)
	config, err := V2ToRuntime(extension)
	require.NoError(t, err)
	require.Equal(t, obi.FridaConfig{Enabled: true, Library: "/opt/obi-frida/libfrida-core.so"}, config.Frida)

	_, exported := RuntimeToV2(config)
	require.Equal(t, extension.Capture.Runtimes.Frida, exported.Capture.Runtimes.Frida)
	exported.Capture.Runtimes.Frida.Enabled = false
	disabled, err := V2ToRuntime(exported)
	require.NoError(t, err)
	require.False(t, disabled.Frida.Enabled)

	data, err := yaml.Marshal(config)
	require.NoError(t, err)
	require.NotContains(t, string(data), "frida:")
}
