// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/tools"
)

func TestFindIoEOF_Unstripped(t *testing.T) {
	elfFile := compileELF(
		tools.ProjectDir() + "/pkg/internal/ebpf/gotracer/testdata/grpcclient_nested/main.go",
	)
	t.Cleanup(func() { require.NoError(t, elfFile.Close()) })

	syms, err := elfFile.Symbols()
	require.NoError(t, err)
	var expected uint64
	for _, s := range syms {
		if s.Name == "io.EOF" {
			expected = s.Value
			break
		}
	}
	require.NotZero(t, expected, "symbol io.EOF should exist in unstripped binary")

	impls, err := findInterfaceImpls(elfFile)
	require.NoError(t, err)
	assert.Equal(t, expected, impls["io.EOF"])

	directEOF, err := findIoEOF(elfFile)
	require.NoError(t, err)
	assert.Equal(t, expected, directEOF)
}

func TestFindIoEOF_Stripped(t *testing.T) {
	elfFile := compileELF(
		tools.ProjectDir()+"/pkg/internal/ebpf/gotracer/testdata/grpcclient_nested/main.go",
		"-ldflags", "-s -w",
	)
	t.Cleanup(func() { require.NoError(t, elfFile.Close()) })

	impls, err := findInterfaceImpls(elfFile)
	require.NoError(t, err)
	assert.NotZero(t, impls["io.EOF"], "io.EOF should be discovered in stripped binary")

	directEOF, err := findIoEOF(elfFile)
	require.NoError(t, err)
	assert.Equal(t, impls["io.EOF"], directEOF)
}
