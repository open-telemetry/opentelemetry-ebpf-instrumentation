// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configload

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

const v2Header = `file_format: "1.0"
extensions:
  obi:
    version: "2.0"
`

func sources(contents ...string) []Source {
	result := make([]Source, 0, len(contents))
	for i, data := range contents {
		result = append(result, Source{Path: string(rune('a'+i)) + ".yml", Data: []byte(data)})
	}
	return result
}

func TestLoadSourcesWithoutSourcesLoadsV1Defaults(t *testing.T) {
	cfg, version, err := LoadSources(nil)

	require.NoError(t, err)
	require.Equal(t, VersionV1, version)
	require.Equal(t, obi.DefaultConfig.ChannelBufferLen, cfg.ChannelBufferLen)
}

func TestLoadSourcesV1Layers(t *testing.T) {
	cfg, version, err := LoadSources(sources(`
channel_buffer_len: 111
log_format: json
name_resolver:
  cache_len: 50
`, `
channel_buffer_len: 222
name_resolver:
  sources: [k8s]
`, `
channel_buffer_len: 333
`))

	require.NoError(t, err)
	require.Equal(t, VersionV1, version)
	require.Equal(t, 333, cfg.ChannelBufferLen)
	require.Equal(t, obi.LogFormatJSON, cfg.LogFormat)
	require.Equal(t, 50, cfg.NameResolver.CacheLen)
	require.Equal(t, []transform.Source{transform.SourceK8s}, cfg.NameResolver.Sources)
	require.Equal(t, []transform.Source{transform.SourceK8s, transform.SourceECS}, obi.DefaultConfig.NameResolver.Sources,
		"overriding a pointer field must not modify the defaults it was loaded from")
}

func TestLoadSourcesV2Layers(t *testing.T) {
	cfg, version, err := LoadSources(sources(v2Header+`
    capture:
      policy:
        default_action: exclude
      rules:
        - action: include
          match:
            process:
              open_ports: 8080
      channels:
        buffer_len: 123
`, v2Header+`
    daemon:
      logging:
        format: json
`))

	require.NoError(t, err)
	require.Equal(t, VersionV2, version)
	require.Equal(t, 123, cfg.ChannelBufferLen)
	require.Equal(t, obi.LogFormatJSON, cfg.LogFormat)
	require.Len(t, cfg.Discovery.Instrument, 1)
	require.True(t, cfg.Discovery.Instrument[0].OpenPorts.Matches(8080))
}

func TestLoadSourcesMixedVersions(t *testing.T) {
	t.Run("v2 over v1", func(t *testing.T) {
		cfg, version, err := LoadSources(sources(`
channel_buffer_len: 111
log_format: json
`, v2Header+`
    capture:
      channels:
        buffer_len: 222
`))

		require.NoError(t, err)
		require.Equal(t, VersionV1, version, "the first source sets the version")
		require.Equal(t, 222, cfg.ChannelBufferLen)
		require.Equal(t, obi.LogFormatJSON, cfg.LogFormat)
		require.Equal(t, obi.DefaultConfig.NameResolver.Sources, cfg.NameResolver.Sources,
			"v2 defaults must not override v1 settings")
	})

	t.Run("v1 over v2", func(t *testing.T) {
		cfg, version, err := LoadSources(sources(v2Header+`
    capture:
      policy:
        default_action: exclude
      rules:
        - action: include
          match:
            process:
              open_ports: 8080
`, `
log_level: DEBUG
`))

		require.NoError(t, err)
		require.Equal(t, VersionV2, version)
		require.Equal(t, obi.LogLevelDebug, cfg.LogLevel)
		require.Len(t, cfg.Discovery.Instrument, 1)
		require.Contains(t, cfg.NameResolver.Sources, transform.SourceRoute53,
			"v1 defaults must not override v2 defaults")
	})
}

func TestLoadSourcesCopiesFunctionsDefinedByLayer(t *testing.T) {
	cfg, _, err := LoadSources(sources(`
log_format: json
`, `file_format: "1.0"
tracer_provider:
  processors:
    - batch:
        exporter:
          otlp_http:
            endpoint: https://traces.example/v1/traces
            headers:
              - name: authorization
                value: trace-token
extensions:
  obi:
    version: "2.0"
`))

	require.NoError(t, err)
	require.Equal(t, "https://traces.example/v1/traces", cfg.Traces.TracesEndpoint)
	require.NotNil(t, cfg.Traces.InjectHeaders)
	headers := map[string]string{}
	cfg.Traces.InjectHeaders(headers)
	require.Equal(t, "trace-token", headers["authorization"])
}

func TestLoadSourcesExplicitDefaultWins(t *testing.T) {
	v1Base := "channel_buffer_len: 111"
	v2Base := v2Header + "    capture: {channels: {buffer_len: 111}}"
	v1Reset := "channel_buffer_len: 50"
	v2Reset := v2Header + "    capture: {channels: {buffer_len: 50}}"
	for name, files := range map[string][]string{
		"v1":          {v1Base, v1Reset},
		"v2":          {v2Base, v2Reset},
		"v1 over v2":  {v2Base, v1Reset},
		"v2 over v1":  {v1Base, v2Reset},
		"alternating": {v1Base, v2Base, v1Reset},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _, err := LoadSources(sources(files...))
			require.NoError(t, err)
			require.Equal(t, obi.DefaultConfig.ChannelBufferLen, cfg.ChannelBufferLen)
		})
	}
}

func TestLoadSourcesPreservesOmittedScalar(t *testing.T) {
	cfg, _, err := LoadSources(sources("service_name: 001", "log_level: DEBUG"))
	require.NoError(t, err)
	require.Equal(t, "001", cfg.ServiceName)
}

func TestLoadSourcesRejectsIncompatibleSetting(t *testing.T) {
	for _, tc := range []struct{ base, overlay, path string }{
		{"log_format: json", v2Header + "    capture: {instrumentation: {http: {enabled: {metrics: false}}}}", "extensions.obi.capture.instrumentation.http.enabled.metrics"},
		{v2Header, "attributes: {select: {'*': {include: [http.route]}}}", "attributes.select"},
	} {
		cfg, _, err := LoadSources(sources(tc.base, tc.overlay))
		require.Nil(t, cfg)
		require.ErrorContains(t, err, "b.yml: "+tc.path)
	}
}

func TestLoadSourcesReportsFailingSource(t *testing.T) {
	_, version, err := LoadSources(sources(`
log_format: json
`, v2Header+`
    capture:
      channels:
        buffer_length: 123
`))

	require.Error(t, err)
	require.Empty(t, version)
	require.ErrorContains(t, err, "b.yml")
	require.ErrorContains(t, err, "buffer_length")
}
