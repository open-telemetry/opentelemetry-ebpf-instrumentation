// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rustcontext

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRustContextPropagationMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Rust compilers and privileged Docker")
	}
	root, err := filepath.Abs("../../../..")
	require.NoError(t, err)
	work := os.Getenv("OBI_RUST_WORK_DIR")
	if work == "" {
		work = t.TempDir()
	}
	arguments := []string{filepath.Join(root, "scripts/test-rust-context.py"), "--work-dir", work, "--protocols", "--live", "--container", "--fallbacks", "--jobs", "3"}
	if compiler := os.Getenv("OBI_RUST_TOOLCHAIN"); compiler != "" {
		arguments = append(arguments, "--toolchain", compiler)
	}
	if os.Getenv("OBI_RUST_OFFLINE") != "" {
		arguments = append(arguments, "--offline")
	}
	output := filepath.Join(root, "testoutput")
	require.NoError(t, os.MkdirAll(output, 0o755))
	log, err := os.Create(filepath.Join(output, "rust-context-"+os.Getenv("OBI_RUST_TOOLCHAIN")+".log"))
	require.NoError(t, err)
	defer log.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", arguments...)
	command.Dir = root
	command.Stdout = io.MultiWriter(os.Stdout, log)
	command.Stderr = command.Stdout
	require.NoError(t, command.Run(), "see %s", log.Name())
}
