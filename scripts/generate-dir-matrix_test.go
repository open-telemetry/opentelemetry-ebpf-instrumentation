// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type dirMatrix struct {
	Include []struct {
		ID       int    `json:"id"`
		Basename string `json:"basename"`
	} `json:"include"`
}

func TestGenerateDirMatrixIncludesSortedBasenames(t *testing.T) {
	searchDir := t.TempDir()
	mustWriteTestFile(t, searchDir, "-dash")
	mustWriteTestFile(t, searchDir, "zeta")
	mustWriteTestFile(t, searchDir, "alpha")
	mustWriteTestFile(t, searchDir, "safe-name_1")

	stdout, stderr, err := runGenerateDirMatrix(t, searchDir, "")
	if err != nil {
		t.Fatalf("generate-dir-matrix.sh failed: %v\nstderr:\n%s", err, stderr)
	}

	var matrix dirMatrix
	if err := json.Unmarshal([]byte(stdout), &matrix); err != nil {
		t.Fatalf("failed to parse matrix json %q: %v", stdout, err)
	}

	if len(matrix.Include) != 4 {
		t.Fatalf("expected 4 matrix entries, got %d", len(matrix.Include))
	}

	if matrix.Include[0].Basename != "-dash" || matrix.Include[1].Basename != "alpha" || matrix.Include[2].Basename != "safe-name_1" || matrix.Include[3].Basename != "zeta" {
		t.Fatalf("unexpected basenames: %+v", matrix.Include)
	}
}

func TestGenerateDirMatrixRejectsUnsafeBasename(t *testing.T) {
	for _, basename := range []string{"evil name", "evil;touch_pwn"} {
		t.Run(basename, func(t *testing.T) {
			searchDir := t.TempDir()
			mustWriteTestFile(t, searchDir, basename)

			_, stderr, err := runGenerateDirMatrix(t, searchDir, "")
			if err == nil {
				t.Fatal("expected generate-dir-matrix.sh to reject an unsafe basename")
			}

			if !strings.Contains(stderr, "Invalid test directory basename") {
				t.Fatalf("expected validation error, got stderr:\n%s", stderr)
			}
		})
	}
}

func runGenerateDirMatrix(t *testing.T, searchDir, excludePattern string) (string, string, error) {
	t.Helper()

	cmd := exec.Command("bash", "./generate-dir-matrix.sh", searchDir, excludePattern)
	cmd.Dir = "."

	stdout, err := cmd.Output()
	if err == nil {
		return string(stdout), "", nil
	}

	var stderr string
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		stderr = string(exitErr.Stderr)
	}

	return string(stdout), stderr, err
}

func mustWriteTestFile(t *testing.T, rootDir, packageDir string) {
	t.Helper()

	dir := filepath.Join(rootDir, packageDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to create %s: %v", dir, err)
	}

	filePath := filepath.Join(dir, "sample_test.go")
	if err := os.WriteFile(filePath, []byte("package sample\n"), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", filePath, err)
	}
}
