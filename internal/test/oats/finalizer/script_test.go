// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFinalizeWeaverExitStatus(t *testing.T) {
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}

	tests := []struct {
		name          string
		helperStatus  int
		composeStatus int
		wantStatus    int
	}{
		{name: "both succeed", wantStatus: 0},
		{name: "compose fails", composeStatus: 23, wantStatus: 23},
		{name: "helper fails", helperStatus: 7, wantStatus: 7},
		{name: "both fail", helperStatus: 7, composeStatus: 23, wantStatus: 7},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			oatsDir := filepath.Join(root, "internal", "test", "oats")
			if err := os.MkdirAll(oatsDir, 0o755); err != nil {
				t.Fatal(err)
			}
			script, err := os.ReadFile(filepath.Join("..", "finalize-weaver.sh"))
			if err != nil {
				t.Fatal(err)
			}
			scriptPath := filepath.Join(oatsDir, "finalize-weaver.sh")
			if err := os.WriteFile(scriptPath, script, 0o755); err != nil {
				t.Fatal(err)
			}

			helperPath := filepath.Join(root, ".tools", "oats", "weaver-finalizer")
			if err := os.MkdirAll(filepath.Dir(helperPath), 0o755); err != nil {
				t.Fatal(err)
			}
			markerPath := filepath.Join(root, "helper-completed")
			helper := fmt.Sprintf("#!/bin/sh\nprintf 'helper diagnostics\\n'\ntouch \"$OATS_HELPER_MARKER\"\nexit %d\n", test.helperStatus)
			if err := os.WriteFile(helperPath, []byte(helper), 0o755); err != nil {
				t.Fatal(err)
			}

			binDir := filepath.Join(root, "bin")
			if err := os.MkdirAll(binDir, 0o755); err != nil {
				t.Fatal(err)
			}
			docker := fmt.Sprintf("#!/bin/sh\n[ \"$1 $2 $3\" = \"compose logs --no-color\" ] || exit 90\n[ -f \"$OATS_HELPER_MARKER\" ] || exit 91\nprintf 'compose output\\n'\nexit %d\n", test.composeStatus)
			if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte(docker), 0o755); err != nil {
				t.Fatal(err)
			}

			cwd := filepath.Join(root, "suite")
			if err := os.MkdirAll(cwd, 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bashPath, scriptPath)
			cmd.Dir = cwd
			cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "COMPOSE_PROJECT_NAME=test-project", "OATS_ARTIFACT_DIR=", "OATS_HELPER_MARKER="+markerPath)
			output, runErr := cmd.CombinedOutput()
			status := 0
			if exitErr, ok := errors.AsType[*exec.ExitError](runErr); ok {
				status = exitErr.ExitCode()
			} else if runErr != nil {
				t.Fatalf("run finalizer: %v", runErr)
			}
			if status != test.wantStatus {
				t.Fatalf("exit status = %d, want %d; output: %s", status, test.wantStatus, output)
			}

			artifactDir := filepath.Join(cwd, "build", "test-project")
			composeLog, err := os.ReadFile(filepath.Join(artifactDir, "compose.log"))
			if err != nil || !strings.Contains(string(composeLog), "compose output") {
				t.Fatalf("compose.log = %q, error = %v", composeLog, err)
			}
			validationLog, err := os.ReadFile(filepath.Join(artifactDir, "weaver-validation.log"))
			if err != nil || !strings.Contains(string(validationLog), "helper diagnostics") {
				t.Fatalf("weaver-validation.log = %q, error = %v", validationLog, err)
			}
			if test.composeStatus != 0 && !strings.Contains(string(output), "failed to collect OATS Compose logs") {
				t.Fatalf("missing Compose failure warning in output: %s", output)
			}
			if test.helperStatus != 0 && !strings.Contains(string(output), "Weaver finalization failed") {
				t.Fatalf("missing Weaver failure diagnostic in output: %s", output)
			}
		})
	}
}
