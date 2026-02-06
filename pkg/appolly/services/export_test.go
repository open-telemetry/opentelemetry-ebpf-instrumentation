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
			Exports: ExportModes{blockSignal: ^(blockMetrics | blockTraces | blockLogs)},
		})
		require.NoError(t, err)

		var exports struct {
			Exports []string `yaml:"exports"`
		}
		require.NoError(t, yaml.Unmarshal(yamlOut, &exports))
		assert.ElementsMatch(t, []string{"metrics", "traces", "logs"}, exports.Exports)
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
		assert.True(t, tc.Exports.CanExportMetrics(), "should allow exporting metrics")
		assert.True(t, tc.Exports.CanExportTraces(), "should allow exporting traces")
		assert.True(t, tc.Exports.CanExportLogs(), "should allow exporting logs")
	})
	t.Run("nil value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: null`), &tc)
		require.NoError(t, err)
		assert.True(t, tc.Exports.CanExportMetrics(), "should allow exporting metrics")
		assert.True(t, tc.Exports.CanExportTraces(), "should allow exporting traces")
		assert.True(t, tc.Exports.CanExportLogs(), "should allow exporting logs")
	})
	t.Run("empty value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: []`), &tc)
		require.NoError(t, err)
		assert.NotNil(t, tc.Exports)
		assert.False(t, tc.Exports.CanExportMetrics(), "should not allow exporting metrics")
		assert.False(t, tc.Exports.CanExportTraces(), "should not allow exporting traces")
		assert.False(t, tc.Exports.CanExportLogs(), "should not allow exporting logs")
	})
	t.Run("metrics value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: ["metrics"]`), &tc)
		require.NoError(t, err)
		assert.True(t, tc.Exports.CanExportMetrics(), "should allow exporting metrics")
		assert.False(t, tc.Exports.CanExportTraces(), "should not allow exporting traces")
		assert.False(t, tc.Exports.CanExportLogs(), "should not allow exporting logs")
	})
	t.Run("traces value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: ["traces"]`), &tc)
		require.NoError(t, err)
		assert.False(t, tc.Exports.CanExportMetrics(), "should not allow exporting metrics")
		assert.True(t, tc.Exports.CanExportTraces(), "should allow exporting traces")
		assert.False(t, tc.Exports.CanExportLogs(), "should not allow exporting logs")
	})
	t.Run("logs value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: ["logs"]`), &tc)
		require.NoError(t, err)
		assert.False(t, tc.Exports.CanExportMetrics(), "should not allow exporting metrics")
		assert.False(t, tc.Exports.CanExportTraces(), "should not allow exporting traces")
		assert.True(t, tc.Exports.CanExportLogs(), "should allow exporting logs")
	})
	t.Run("metrics and traces value", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: ["metrics", "traces"]`), &tc)
		require.NoError(t, err)
		assert.True(t, tc.Exports.CanExportMetrics(), "should allow exporting metrics")
		assert.True(t, tc.Exports.CanExportTraces(), "should allow exporting traces")
		assert.False(t, tc.Exports.CanExportLogs(), "should not allow exporting logs")
	})
	t.Run("all values", func(t *testing.T) {
		var tc tc
		err := yaml.Unmarshal([]byte(`exports: ["metrics", "traces", "logs"]`), &tc)
		require.NoError(t, err)
		assert.True(t, tc.Exports.CanExportMetrics(), "should allow exporting metrics")
		assert.True(t, tc.Exports.CanExportTraces(), "should allow exporting traces")
		assert.True(t, tc.Exports.CanExportLogs(), "should allow exporting logs")
	})
}

func TestPragmaticExports(t *testing.T) {
	modes := NewExportModes()

	assert.False(t, modes.CanExportTraces(), "should not allow exporting traces by default")
	assert.False(t, modes.CanExportMetrics(), "should not allow exporting metrics by default")
	assert.False(t, modes.CanExportLogs(), "should not allow exporting logs by default")

	modes.AllowTraces()

	assert.True(t, modes.CanExportTraces(), "should allow exporting traces after calling AllowTraces")
	assert.False(t, modes.CanExportMetrics(), "should not allow exporting metrics after calling AllowTraces")
	assert.False(t, modes.CanExportLogs(), "should not allow exporting logs after calling AllowTraces")

	modes.AllowMetrics()

	assert.True(t, modes.CanExportTraces(), "should allow exporting traces after calling AllowTraces and AllowMetrics")
	assert.True(t, modes.CanExportMetrics(), "should allow exporting metrics after calling AllowMetrics")
	assert.False(t, modes.CanExportLogs(), "should not allow exporting logs after calling AllowTraces and AllowMetrics")

	modes.AllowLogs()

	assert.True(t, modes.CanExportTraces(), "should allow exporting traces after calling AllowTraces, AllowMetrics, and AllowLogs")
	assert.True(t, modes.CanExportMetrics(), "should allow exporting metrics after calling AllowMetrics and AllowLogs")
	assert.True(t, modes.CanExportLogs(), "should allow exporting logs after calling AllowLogs")
}
