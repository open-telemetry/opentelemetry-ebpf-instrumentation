// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package harvest

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkJSFilesSkipsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.js"), []byte(""), 0o644))

	require.NoError(t, syscall.Mkfifo(filepath.Join(dir, "pipe.js"), 0o600))

	socketPath := filepath.Join(dir, "socket.js")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "target.txt"), []byte(""), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(dir, "target.txt"), filepath.Join(dir, "link.js")))

	var files []string
	err = WalkJSFiles(dir, func(path string) error {
		files = append(files, filepath.Base(path))
		return nil
	})

	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"app.js"}, files)
}
