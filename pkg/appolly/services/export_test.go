// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestYAMLMarshal_Exports(t *testing.T) {
	type tc struct {
		Exports ExportModes
	}
	t.Run("nil value", func(t *testing.T) {
		yamlOut, err := yaml.Marshal(&tc{
			Exports: ExportModes{},
		})
		require.NoError(t, err)
		assert.YAMLEq(t, `exports: null`, string(yamlOut))
	})
	t.Run("empty value", func(t *testing.T) {
		yamlOut, err := yaml.Marshal(&tc{
			Exports: ExportModes{blockSignal: blockAll},
		})
		require.NoError(t, err)
		assert.YAMLEq(t, `exports: []`, string(yamlOut))
	})
	t.Run("some value", func(t *testing.T) {
		yamlOut, err := yaml.Marshal(&tc{
			Exports: ExportModes{blockSignal: ^blockMetrics},
		})
		require.NoError(t, err)
		assert.YAMLEq(t, `exports: ["metrics"]`, string(yamlOut))
	})
	t.Run("all values", func(t *testing.T) {
		yamlOut, err := yaml.Marshal(&tc{
			Exports: ExportModes{blockSignal: ^(blockMetrics | blockTraces)},
		})
		require.NoError(t, err)

		var exports struct {
			Exports []string `yaml:"exports"`
		}
		require.NoError(t, yaml.Unmarshal(yamlOut, &exports))
		assert.ElementsMatch(t, []string{"metrics", "traces"}, exports.Exports)
	})
}

func TestYAMLUnmarshal_Exports(t *testing.T) {
	type tc struct {
		Exports ExportModes
	}
	t.Run("undefined value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(``), &tc)
		require.NoError(t, err)
		assert.True(t, tc.Exports.CanExportMetrics())
		assert.True(t, tc.Exports.CanExportTraces())
	})
	t.Run("nil value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: null`), &tc)
		require.NoError(t, err)
		assert.True(t, tc.Exports.CanExportMetrics())
		assert.True(t, tc.Exports.CanExportTraces())
	})
	t.Run("empty value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: []`), &tc)
		require.NoError(t, err)
		assert.NotNil(t, tc.Exports)
		assert.False(t, tc.Exports.CanExportMetrics())
		assert.False(t, tc.Exports.CanExportTraces())
	})
	t.Run("metrics value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: ["metrics"]`), &tc)
		require.NoError(t, err)
		assert.True(t, tc.Exports.CanExportMetrics())
		assert.False(t, tc.Exports.CanExportTraces())
	})
	t.Run("traces value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: ["traces"]`), &tc)
		require.NoError(t, err)
		assert.False(t, tc.Exports.CanExportMetrics())
		assert.True(t, tc.Exports.CanExportTraces())
	})
	t.Run("metrics and traces value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: ["metrics", "traces"]`), &tc)
		require.NoError(t, err)
		assert.True(t, tc.Exports.CanExportMetrics())
		assert.True(t, tc.Exports.CanExportTraces())
	})
}

func TestPragmaticExports(t *testing.T) {
	modes := NewExportModes()

	assert.False(t, modes.CanExportTraces())
	assert.False(t, modes.CanExportMetrics())

	modes.AllowTraces()

	assert.True(t, modes.CanExportTraces())

	modes.AllowMetrics()

	assert.True(t, modes.CanExportMetrics())
}
