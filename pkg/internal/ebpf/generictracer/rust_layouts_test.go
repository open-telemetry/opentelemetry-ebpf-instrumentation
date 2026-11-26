// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/rustabi"
)

func TestGenerateRustOffsets(t *testing.T) {
	path, output := os.Getenv("OBI_RUST_OFFSET_BINARY"), os.Getenv("OBI_RUST_OFFSET_OUTPUT")
	if path == "" || output == "" {
		t.Skip("set the build-time Rust offset input and output paths")
	}
	profile, err := rustabi.Inspect(path)
	require.NoError(t, err)
	database, err := rustabi.Load(output)
	require.NoError(t, err)
	database.Add(profile)
	require.NoError(t, database.Write(output))
}
