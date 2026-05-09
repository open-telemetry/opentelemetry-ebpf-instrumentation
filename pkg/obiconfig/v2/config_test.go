// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseYAMLStandalone(t *testing.T) {
	t.Parallel()

	doc, cfg, err := ParseYAML([]byte(`
file_format: "1.0"
tracer_provider:
  sampler:
    obi_rule_based:
      fallback:
        name: parentbased_always_on
      rules:
        - match:
            resource_attributes:
              service.name: frontend
          action:
            name: always_off
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: include
`), DeploymentModeStandalone)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.NotNil(t, cfg)
	require.Equal(t, SupportedVersion, cfg.Version)
	require.NotNil(t, nestedMap(doc.TracerProvider, "sampler", "obi_rule_based"))
}

func TestParseYAMLReceiver(t *testing.T) {
	t.Parallel()

	doc, cfg, err := ParseYAML([]byte(`
version: "2.0"
policy:
  default_action: include
instrumentation: {}
`), DeploymentModeReceiver)
	require.NoError(t, err)
	require.Nil(t, doc)
	require.NotNil(t, cfg)
	require.Equal(t, SupportedVersion, cfg.Version)
}

func TestReceiverRejectsStandaloneSections(t *testing.T) {
	t.Parallel()

	_, _, err := ParseYAML([]byte(`
version: "2.0"
policy:
  default_action: include
daemon:
  logging:
    level: INFO
`), DeploymentModeReceiver)
	require.Error(t, err)

	var notAllowed *SectionNotAllowedError
	require.True(t, errors.As(err, &notAllowed))
	require.Equal(t, "daemon", notAllowed.Section)
	require.Contains(t, err.Error(), "standalone mode")
}

func TestUnsupportedVersion(t *testing.T) {
	t.Parallel()

	_, _, err := ParseYAML([]byte(`
version: "3.0"
`), DeploymentModeReceiver)
	require.Error(t, err)

	var unsupported *UnsupportedVersionError
	require.True(t, errors.As(err, &unsupported))
	require.Equal(t, "3.0", unsupported.Version)
}

func TestDetectV1Shape(t *testing.T) {
	t.Parallel()

	_, _, err := ParseYAML([]byte(`
ebpf: {}
discovery: {}
`), DeploymentModeStandalone)
	require.Error(t, err)

	var notV2 *NotV2Error
	require.True(t, errors.As(err, &notV2))
}
