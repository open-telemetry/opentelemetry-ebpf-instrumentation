// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestInstrumentationPointsFindsFramerPaddingBoundary(t *testing.T) {
	const source = `package main

import (
	"io"

	"golang.org/x/net/http2"
)

func main() {
	f := http2.NewFramer(io.Discard, nil)
	_ = f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true})
}
`
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "main.go")
	binaryPath := filepath.Join(dir, "fixture")
	require.NoError(t, os.WriteFile(sourcePath, []byte(source), 0o600))
	command := exec.Command("go", "build", "-o", binaryPath, sourcePath)
	command.Env = append(os.Environ(), "GOCACHE="+filepath.Join(dir, "gocache"))
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))

	file, err := elf.Open(binaryPath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })

	const symbol = "golang.org/x/net/http2.(*Framer).WriteHeaders"
	offsets, err := instrumentationPoints(file, []string{symbol})
	require.NoError(t, err)
	require.Contains(t, offsets, symbol)
	require.NotZero(t, offsets[symbol][0].PadStart)
	require.Greater(t, offsets[symbol][0].PadStart, offsets[symbol][0].Start)
	require.GreaterOrEqual(t, offsets[symbol][0].PadOffset, uint64(34))
	require.Less(t, offsets[symbol][0].PadOffset, uint64(512))

	var params http2.HeadersFrameParam
	require.Equal(t, uintptr(34), unsafe.Offsetof(params.PadLength))
	require.Equal(t, uintptr(33), unsafe.Offsetof(params.EndHeaders))
	require.Equal(t, unsafe.Offsetof(params.BlockFragment)+unsafe.Sizeof(uintptr(0)), uintptr(16))
}
