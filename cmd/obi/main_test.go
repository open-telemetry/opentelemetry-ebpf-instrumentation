// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigPrefersV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config-v2.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: include
      channels:
        buffer_len: 123
`), 0o600))

	cfg := loadConfig(&path)
	require.Equal(t, 123, cfg.ChannelBufferLen)
}

func TestLoadConfigFallsBackToLegacy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config-v1.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`{}`), 0o600))

	cfg := loadConfig(&path)
	require.Equal(t, 50, cfg.ChannelBufferLen)
}
