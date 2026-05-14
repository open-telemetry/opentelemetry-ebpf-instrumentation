// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
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
	require.ErrorAs(t, err, &notAllowed)
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
	require.ErrorAs(t, err, &unsupported)
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
	require.ErrorAs(t, err, &notV2)
}

func TestParseYAMLDiscoveryPIDAndPortRules(t *testing.T) {
	t.Parallel()

	_, cfg, err := ParseYAML([]byte(`
version: "2.0"
rules:
  - action: include
    match:
      process:
        open_ports: 8080,8443-8444
  - action: exclude
    match:
      process:
        target_pids: [99, 100]
`), DeploymentModeReceiver)
	require.NoError(t, err)
	require.Len(t, cfg.Capture.Rules, 2)
	require.Equal(t, "8080,8443-8444", nestedMap(cfg.Capture.Rules[0].Match, "process")["open_ports"])
	require.Equal(t, []any{99, 100}, nestedMap(cfg.Capture.Rules[1].Match, "process")["target_pids"])
}
