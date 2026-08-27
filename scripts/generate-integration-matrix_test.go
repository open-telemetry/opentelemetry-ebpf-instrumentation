// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

type integrationMatrix struct {
	Include []struct {
		TestPattern string `json:"test_pattern"`
	} `json:"include"`
}

func TestGenerateIntegrationMatrixIsCompleteUniqueAndDeterministic(t *testing.T) {
	searchDir := t.TempDir()
	mustWriteIntegrationTestFile(t, searchDir, "z [*]_test.go", "TestZulu", "TestAlpha")
	mustWriteIntegrationTestFile(t, searchDir, "a_test.go", "TestCharlie", "TestBravo")
	weightsFile := mustWriteWeightsFile(t, `{"_default": 1}`)
	var first string
	for run := range 5 {
		stdout, stderr, err := runGenerateIntegrationMatrix(t, searchDir, "3", "", weightsFile, "")
		if err != nil {
			t.Fatalf("run %d failed: %v\nstderr:\n%s", run, err, stderr)
		}
		if run == 0 {
			first = stdout
		} else if stdout != first {
			t.Fatalf("run %d was not byte-stable:\nfirst: %s\ncurrent: %s", run, first, stdout)
		}
	}
	got := matrixTestNames(t, first)
	want := []string{"TestAlpha", "TestBravo", "TestCharlie", "TestZulu"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("matrix union differs: got %v, want %v", got, want)
	}
}

func TestGenerateIntegrationMatrixUsesLongestProcessingTimeWeights(t *testing.T) {
	searchDir := t.TempDir()
	mustWriteIntegrationTestFile(t, searchDir, "sample_test.go", "TestDelta", "TestCharlie", "TestBravo", "TestAlpha")
	weightsFile := mustWriteWeightsFile(t, `{"_default":1,"TestAlpha":1e100,"TestBravo":20,"TestCharlie":19,"TestDelta":1}`)
	stdout, stderr, err := runGenerateIntegrationMatrix(t, searchDir, "2", "", weightsFile, "")
	if err != nil {
		t.Fatalf("generator failed: %v\nstderr:\n%s", err, stderr)
	}
	matrix := parseIntegrationMatrix(t, stdout)
	want := []string{"TestAlpha", "TestBravo|TestCharlie|TestDelta"}
	got := []string{matrix.Include[0].TestPattern, matrix.Include[1].TestPattern}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected weighted allocation: got %v, want %v", got, want)
	}
}

func TestGenerateIntegrationMatrixRejectsInvalidWeights(t *testing.T) {
	for _, contents := range []string{"", " \n", `{} {}`, `not-json`, `{"_default":false}`, `{"_default":-1}`, `{"TestAlpha":"heavy"}`} {
		searchDir := t.TempDir()
		mustWriteIntegrationTestFile(t, searchDir, "sample_test.go", "TestAlpha")
		_, stderr, err := runGenerateIntegrationMatrix(t, searchDir, "2", "", mustWriteWeightsFile(t, contents), "")
		if err == nil || !strings.Contains(stderr, "invalid weights file") {
			t.Fatalf("weights %q: got err=%v stderr=%q", contents, err, stderr)
		}
	}
}

func TestGenerateIntegrationMatrixHandlesInputBoundaries(t *testing.T) {
	t.Run("empty directory", func(t *testing.T) {
		_, stderr, err := runGenerateIntegrationMatrix(t, t.TempDir(), "2", "", "", "")
		if err == nil || !strings.Contains(stderr, "No test files found") {
			t.Fatalf("expected empty input error, got err=%v stderr=%q", err, stderr)
		}
	})
	t.Run("custom pattern", func(t *testing.T) {
		searchDir := t.TempDir()
		mustWriteIntegrationTestFile(t, searchDir, "sample_test.go", "TestAlpha", "TestBeta", "TestGamma")
		stdout, stderr, err := runGenerateIntegrationMatrix(t, searchDir, "2", "(TestAlpha|TestGamma)", "", "")
		if err != nil {
			t.Fatalf("generator failed: %v\nstderr:\n%s", err, stderr)
		}
		if got, want := matrixTestNames(t, stdout), []string{"TestAlpha", "TestGamma"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("custom pattern selected %v, want %v", got, want)
		}
	})
	t.Run("custom pattern without matches", func(t *testing.T) {
		searchDir := t.TempDir()
		mustWriteIntegrationTestFile(t, searchDir, "sample_test.go", "TestAlpha")
		_, stderr, err := runGenerateIntegrationMatrix(t, searchDir, "2", "TestMissing", "", "")
		if err == nil || !strings.Contains(stderr, "No tests matching 'TestMissing'") {
			t.Fatalf("expected no matches error, got err=%v stderr=%q", err, stderr)
		}
	})
	t.Run("more partitions than tests", func(t *testing.T) {
		searchDir := t.TempDir()
		mustWriteIntegrationTestFile(t, searchDir, "sample_test.go", "TestAlpha", "TestBeta")
		for _, partitions := range []string{"100000", "18446744073709551616"} {
			stdout, stderr, err := runGenerateIntegrationMatrix(t, searchDir, partitions, "", "", "")
			if err != nil {
				t.Fatalf("partitions %s failed: %v\nstderr:\n%s", partitions, err, stderr)
			}
			matrix := parseIntegrationMatrix(t, stdout)
			if len(matrix.Include) != 2 || !reflect.DeepEqual(matrixTestNames(t, stdout), []string{"TestAlpha", "TestBeta"}) {
				t.Fatalf("partitions %s produced %+v", partitions, matrix.Include)
			}
		}
	})
}

func TestGenerateIntegrationMatrixRejectsInvalidArguments(t *testing.T) {
	searchDir := t.TempDir()
	mustWriteIntegrationTestFile(t, searchDir, "sample_test.go", "TestAlpha")
	for _, partitions := range []string{"0", "-1", "many"} {
		_, stderr, err := runGenerateIntegrationMatrix(t, searchDir, partitions, "", "", "")
		if err == nil || !strings.Contains(stderr, "partitions must be a positive integer") {
			t.Fatalf("partitions %q: expected validation error, got err=%v stderr=%q", partitions, err, stderr)
		}
	}
	for _, pattern := range []string{"TestAlpha\n.*", "TestAlpha\r.*"} {
		_, stderr, err := runGenerateIntegrationMatrix(t, searchDir, "2", pattern, "", "")
		if err == nil || !strings.Contains(stderr, "test pattern must not contain") {
			t.Fatalf("pattern %q: got err=%v stderr=%q", pattern, err, stderr)
		}
	}
}

func TestGenerateIntegrationMatrixFailsClosedOnToolErrors(t *testing.T) {
	tests := []struct{ command, script, want string }{
		{"awk", "", "missing required commands: awk"},
		{"sort", "#!/bin/bash\n/usr/bin/head -c 1\nexit 17\n", "failed to discover test files"},
		{"grep", "#!/bin/bash\nprintf '%s\\n' 'func TestPartial(t *testing.T) {}'\nexit 2\n", "failed to extract test names"},
	}
	for _, tc := range tests {
		searchDir, binDir := t.TempDir(), t.TempDir()
		mustWriteIntegrationTestFile(t, searchDir, "sample_test.go", "TestAlpha")
		for _, name := range []string{"awk", "find", "grep", "sed", "sort", "tr"} {
			path := filepath.Join(binDir, name)
			if name == tc.command {
				if tc.script != "" {
					if err := os.WriteFile(path, []byte(tc.script), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				continue
			}
			target, err := exec.LookPath(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}
		stdout, stderr, err := runGenerateIntegrationMatrix(t, searchDir, "2", "", "", binDir)
		if err == nil || stdout != "" || !strings.Contains(stderr, tc.want) {
			t.Fatalf("%s: stdout=%q err=%v stderr=%q", tc.command, stdout, err, stderr)
		}
	}
}

func runGenerateIntegrationMatrix(t *testing.T, searchDir, partitions, pattern, weightsFile, path string) (string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/bash", "./generate-integration-matrix.sh", searchDir, partitions, pattern)
	cmd.Dir = "."
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "OBI_INTEGRATION_TEST_WEIGHTS_FILE=") || path != "" && strings.HasPrefix(variable, "PATH=") {
			continue
		}
		cmd.Env = append(cmd.Env, variable)
	}
	if weightsFile == "" {
		weightsFile = filepath.Join(searchDir, "missing-weights.json")
	}
	cmd.Env = append(cmd.Env, "OBI_INTEGRATION_TEST_WEIGHTS_FILE="+weightsFile)
	if path != "" {
		cmd.Env = append(cmd.Env, "PATH="+path)
	}
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

func parseIntegrationMatrix(t *testing.T, stdout string) integrationMatrix {
	t.Helper()
	var matrix integrationMatrix
	if err := json.Unmarshal([]byte(stdout), &matrix); err != nil {
		t.Fatalf("failed to parse matrix JSON %q: %v", stdout, err)
	}
	return matrix
}

func matrixTestNames(t *testing.T, stdout string) []string {
	t.Helper()
	matrix := parseIntegrationMatrix(t, stdout)
	seen := map[string]bool{}
	var names []string
	for _, shard := range matrix.Include {
		for name := range strings.SplitSeq(shard.TestPattern, "|") {
			if seen[name] {
				t.Fatalf("test %s appears more than once", name)
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func mustWriteIntegrationTestFile(t *testing.T, rootDir, name string, testNames ...string) {
	t.Helper()
	contents := "package fixture\n\nfunc " + strings.Join(testNames, "(t *testing.T) {}\n\nfunc ") + "(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(rootDir, name), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustWriteWeightsFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "weights.json")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
