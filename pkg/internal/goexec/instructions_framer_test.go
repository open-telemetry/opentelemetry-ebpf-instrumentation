// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestInstrumentationPointsFindsFramerPaddingBoundary(t *testing.T) {
	const source = `package main

import (
	"io"
	"net/http"

	"golang.org/x/net/http2"
)

func main() {
	f := http2.NewFramer(io.Discard, nil)
	_ = f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true})
	p := &http.Protocols{}
	p.SetHTTP2(true)
	t := &http.Transport{Protocols: p}
	_, _ = t.RoundTrip(&http.Request{})
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

	implementations := [][2]string{
		{
			"golang.org/x/net/http2.(*Framer).WriteHeaders",
			"golang.org/x/net/http2.(*Framer).endWrite",
		},
		{
			"net/http.(*http2Framer).WriteHeaders",
			"net/http.(*http2Framer).endWrite",
		},
	}
	var symbols []string
	for _, implementation := range implementations {
		symbols = append(symbols, implementation[:]...)
	}
	offsets, err := instrumentationPoints(file, symbols)
	require.NoError(t, err)
	foundImplementations := 0
	for _, implementation := range implementations {
		writeHeaders := offsets[implementation[0]]
		endWrite := offsets[implementation[1]]
		if len(writeHeaders) == 0 && len(endWrite) == 0 {
			continue
		}
		require.NotEmpty(t, writeHeaders)
		require.NotEmpty(t, endWrite)
		for _, writeOffset := range writeHeaders {
			require.NotZero(t, writeOffset.Start)
			require.Greater(t, writeOffset.PadStart, writeOffset.Start)
			require.GreaterOrEqual(t, writeOffset.PadOffset, uint64(34))
			require.Less(t, writeOffset.PadOffset, uint64(512))

			called := false
			for _, endOffset := range endWrite {
				called = called || slices.Contains(writeOffset.CallTargets, endOffset.Start)
			}
			require.True(t, called)
		}
		foundImplementations++
	}
	require.Positive(t, foundImplementations)

	var params http2.HeadersFrameParam
	require.Equal(t, uintptr(34), unsafe.Offsetof(params.PadLength))
}
