// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRustExecutableAnalysisSharedPerFileVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executable")
	require.NoError(t, os.WriteFile(path, []byte("not an ELF"), 0o755))
	cache := newRustExecutableCache()

	open := func() *os.File {
		f, err := os.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })
		return f
	}

	first := analyzeRustExecutable(cache, open())
	require.Error(t, first.err, "a file that is not an ELF executable cannot be analyzed")

	// Concurrent attaches of one binary, each with its own descriptor, share one analysis.
	files := make([]*os.File, 8)
	for i := range files {
		files[i] = open()
	}

	results := make([]*rustExecutable, len(files))
	var wg sync.WaitGroup
	for i, f := range files {
		wg.Go(func() { results[i] = analyzeRustExecutable(cache, f) })
	}
	wg.Wait()

	for _, result := range results {
		require.Same(t, first, result)
	}

	// Rewriting the file in place keeps its inode but changes its version.
	require.NoError(t, os.WriteFile(path, []byte("a different and longer file"), 0o755))
	require.NotSame(t, first, analyzeRustExecutable(cache, open()), "a rewritten file is analyzed again")
}
