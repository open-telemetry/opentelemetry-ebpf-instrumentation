// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestShardRerunsOnlyUnresolvedTests(t *testing.T) {
	cfg := testConfig(t)
	commandLog := fakeGo(t, reportEvents("TestAlpha", "pass", "TestBeta", "fail", "TestGamma", "skip"), "1")
	if err := runShard(cfg); err == nil {
		t.Fatal("expected first attempt to fail")
	}
	advanceAttempt(t, &cfg)
	coverage := filepath.Join(cfg.previousDir, "attempt-1", "covcounters.fixture")
	if err := os.WriteFile(coverage, []byte("previous coverage"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_REPORT", reportEvents("TestBeta", "pass"))
	t.Setenv("FAKE_EXIT", "0")
	if err := runShard(cfg); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "-run=^(TestBeta)$\n") || strings.Contains(string(args), "TestAlpha") {
		t.Fatalf("rerun selected unexpected tests: %s", args)
	}
	data, err := os.ReadFile(filepath.Join(cfg.coverageDir, "covcounters.fixture"))
	if err != nil || string(data) != "previous coverage" {
		t.Fatalf("did not restore coverage: %q, %v", data, err)
	}
	state := readCheckpoint(t, cfg.stateDir)
	if !state.Reusable || state.Results["TestAlpha"] != "pass" || state.Results["TestBeta"] != "pass" || state.Results["TestGamma"] != "skip" {
		t.Fatalf("did not preserve cumulative results: %+v", state)
	}

	advanceAttempt(t, &cfg)
	if err := os.Remove(commandLog); err != nil {
		t.Fatal(err)
	}
	if err := runShard(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(commandLog); !os.IsNotExist(err) {
		t.Fatal("reran tests after all tests had completed")
	}
}

func TestLoadCheckpointDownloadLayouts(t *testing.T) {
	for _, layout := range []string{"single artifact", "multiple artifacts"} {
		t.Run(layout, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.attempt = 11
			state := checkpoint{
				Version: checkpointVersion, Scope: cfg.scope, Attempt: 10, Reusable: true,
				Results: map[string]string{"TestAlpha": "pass", "TestBeta": "fail", "TestGamma": "skip"},
			}
			previous := cfg.previousDir
			if layout == "multiple artifacts" {
				older := state
				older.Attempt = 2
				older.Results = map[string]string{"TestAlpha": "fail", "TestBeta": "fail", "TestGamma": "skip"}
				if err := saveCheckpoint(filepath.Join(previous, "attempt-2"), older); err != nil {
					t.Fatal(err)
				}
				previous = filepath.Join(previous, "attempt-10")
			}
			if err := saveCheckpoint(previous, state); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(previous, "covcounters.fixture"), []byte("previous coverage"), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := loadCheckpoint(cfg, []string{"TestAlpha", "TestBeta", "TestGamma"})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, state) {
				t.Fatalf("got %+v, want %+v", got, state)
			}
			data, err := os.ReadFile(filepath.Join(cfg.coverageDir, "covcounters.fixture"))
			if err != nil || string(data) != "previous coverage" {
				t.Fatalf("did not restore coverage from the selected checkpoint: %q, %v", data, err)
			}
		})
	}
}

func TestShardResumesAfterOtherShardAttempts(t *testing.T) {
	cfg := testConfig(t)
	commandLog := fakeGo(t, reportEvents("TestAlpha", "pass", "TestBeta", "fail", "TestGamma", "skip"), "1")
	if err := runShard(cfg); err == nil {
		t.Fatal("expected first attempt to fail")
	}
	advanceAttempt(t, &cfg)
	cfg.attempt = 4
	if err := os.WriteFile(filepath.Join(cfg.previousDir, "attempt-1", "covcounters.fixture"), []byte("previous coverage"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_REPORT", reportEvents("TestBeta", "pass"))
	t.Setenv("FAKE_EXIT", "0")
	if err := runShard(cfg); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(commandLog)
	if err != nil || !strings.Contains(string(args), "-run=^(TestBeta)$\n") {
		t.Fatalf("did not resume across attempts without a shard checkpoint: %s, %v", args, err)
	}
	data, err := os.ReadFile(filepath.Join(cfg.coverageDir, "covcounters.fixture"))
	if err != nil || string(data) != "previous coverage" {
		t.Fatalf("did not restore coverage: %q, %v", data, err)
	}
}

func TestShardFallsBackToFullRun(t *testing.T) {
	for _, reason := range []string{"missing", "corrupt", "different commit", "different shard", "different arch", "different run", "different pattern", "unsafe latest", "future attempt", "invalid result", "missing test"} {
		t.Run(reason, func(t *testing.T) {
			cfg := testConfig(t)
			state := checkpoint{
				Version: checkpointVersion, Scope: cfg.scope, Attempt: 2, Reusable: true,
				Results: map[string]string{"TestAlpha": "pass", "TestBeta": "fail", "TestGamma": "skip"},
			}
			cfg.attempt = 3
			switch reason {
			case "unsafe latest":
				state.Attempt = 1
			case "different commit":
				state.Scope.Commit = "other-commit"
			case "different shard":
				state.Scope.Shard = "other-shard"
			case "different arch":
				state.Scope.Arch = "arm64"
			case "different run":
				state.Scope.RunID = "other-run"
			case "different pattern":
				state.Scope.Pattern = "TestOther"
			case "future attempt":
				state.Attempt = 3
			case "invalid result":
				state.Results["TestAlpha"] = "unknown"
			case "missing test":
				delete(state.Results, "TestGamma")
			}
			previous := filepath.Join(cfg.previousDir, "attempt-"+strconv.Itoa(state.Attempt))
			if reason != "missing" {
				if err := saveCheckpoint(previous, state); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(previous, "covcounters.fixture"), []byte("invalid coverage"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if reason == "corrupt" {
				if err := os.WriteFile(filepath.Join(previous, checkpointName), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if reason == "unsafe latest" {
				state.Attempt = 2
				state.Reusable = false
				if err := saveCheckpoint(filepath.Join(cfg.previousDir, "attempt-2"), state); err != nil {
					t.Fatal(err)
				}
			}
			commandLog := fakeGo(t, reportEvents("TestAlpha", "pass", "TestBeta", "pass", "TestGamma", "skip"), "0")
			if err := runShard(cfg); err != nil {
				t.Fatal(err)
			}
			args, err := os.ReadFile(commandLog)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(args), "-run=^(TestAlpha|TestBeta|TestGamma)$\n") {
				t.Fatalf("did not fall back to full shard: %s", args)
			}
			if _, err := os.Stat(filepath.Join(cfg.coverageDir, "covcounters.fixture")); !os.IsNotExist(err) {
				t.Fatal("restored coverage from an invalid checkpoint")
			}
		})
	}
}

func TestReadResultsUsesFinalRootOutcomes(t *testing.T) {
	report := reportEvents("TestAlpha", "fail", "TestBeta", "skip", "TestAlpha", "pass")
	report += eventJSON("fail", "TestAlpha/subtest", "")
	path := filepath.Join(t.TempDir(), "report.log")
	if err := os.WriteFile(path, []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	results, err := readResults(path, []string{"TestAlpha", "TestBeta"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := (map[string]string{"TestAlpha": "pass", "TestBeta": "skip"}); !reflect.DeepEqual(results, want) {
		t.Fatalf("got %v, want %v", results, want)
	}
}

func TestUnsafeReportsCannotBeReused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		report  string
		success bool
	}{
		{"missing test", reportEvents("TestAlpha", "fail"), false},
		{"interrupted retry", reportEvents("TestAlpha", "pass", "TestBeta", "fail") + eventJSON("run", "TestBeta", ""), false},
		{"race", reportEvents("TestAlpha", "pass", "TestBeta", "fail") + eventJSON("output", "TestBeta", "WARNING: DATA RACE\n"), false},
		{"panic", reportEvents("TestAlpha", "pass", "TestBeta", "fail") + eventJSON("output", "TestBeta", "panic: error\n"), false},
		{"corrupt", reportEvents("TestAlpha", "pass", "TestBeta", "pass") + "{", true},
		{"unexpected test", reportEvents("TestOther", "fail"), false},
		{"runner failure", reportEvents("TestAlpha", "pass", "TestBeta", "pass"), false},
		{"false success", reportEvents("TestAlpha", "pass", "TestBeta", "fail"), true},
		{"no package result", eventJSON("pass", "TestAlpha", "") + eventJSON("pass", "TestBeta", ""), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.log")
			if err := os.WriteFile(path, []byte(tc.report), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readResults(path, []string{"TestAlpha", "TestBeta"}, tc.success); err == nil {
				t.Fatal("accepted unsafe report")
			}
		})
	}
}

func TestShardDoesNotResumeAnUnsafeAttempt(t *testing.T) {
	cfg := testConfig(t)
	fakeGo(t, reportEvents("TestAlpha", "pass", "TestBeta", "fail", "TestGamma", "skip")+eventJSON("output", "TestBeta", "WARNING: DATA RACE\n"), "1")
	if err := runShard(cfg); err == nil {
		t.Fatal("expected race failure")
	}
	if readCheckpoint(t, cfg.stateDir).Reusable {
		t.Fatal("saved a reusable checkpoint after a data race")
	}
}

func TestShardTestsRejectsInvalidSelections(t *testing.T) {
	for _, pattern := range []string{"", "TestAlpha|", "Test.*", "TestAlpha/subtest", "TestAlpha\n"} {
		if _, err := shardTests(pattern); err == nil {
			t.Fatalf("accepted %q", pattern)
		}
	}
}

func TestShardIgnoresSetupAndExcludedTests(t *testing.T) {
	cfg := testConfig(t)
	cfg.Pattern += "|TestMain|TestDotnetRuntimeEventsLive"
	commandLog := fakeGo(t, reportEvents("TestAlpha", "pass", "TestBeta", "pass", "TestGamma", "skip"), "0")
	if err := runShard(cfg); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(args), "TestMain") || strings.Contains(string(args), "TestDotnetRuntimeEventsLive") {
		t.Fatalf("selected tests absent from the active build: %s", args)
	}
	state := readCheckpoint(t, cfg.stateDir)
	if !state.Reusable || len(state.Results) != 3 {
		t.Fatalf("saved non-runnable test results: %+v", state)
	}
}

func TestShardWithOnlyExcludedTests(t *testing.T) {
	cfg := testConfig(t)
	cfg.Pattern = "TestMain|TestDotnetRuntimeEventsLive"
	commandLog := fakeGo(t, "", "0")
	if err := runShard(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(commandLog); !os.IsNotExist(err) {
		t.Fatal("ran a shard without runnable tests")
	}
}

func testConfig(t *testing.T) config {
	t.Helper()
	dir := t.TempDir()
	return config{
		scope:   scope{RunID: "42", Commit: "commit", Shard: "1", Arch: "amd64", Pattern: "TestAlpha|TestBeta|TestGamma"},
		attempt: 1, previousDir: filepath.Join(dir, "previous"), stateDir: filepath.Join(dir, "current"), coverageDir: filepath.Join(dir, "coverage"), report: filepath.Join(dir, "report.log"),
	}
}

func fakeGo(t *testing.T, report, exitCode string) string {
	t.Helper()
	dir := t.TempDir()
	commandLog := filepath.Join(dir, "command.log")
	if err := os.WriteFile(filepath.Join(dir, "active_test.go"), []byte(`package integration
func TestMain(m *testing.M) {}
func TestAlpha(t *testing.T) {}
func TestBeta(t *testing.T) {}
func TestGamma(t *testing.T) {}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "excluded_test.go"), []byte("package integration\nfunc TestDotnetRuntimeEventsLive(t *testing.T) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pkg, err := json.Marshal(map[string]any{"Dir": dir, "TestGoFiles": []string{"active_test.go"}})
	if err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
if [ "$1" = "list" ]; then
  printf '%s' "$FAKE_PACKAGE"
  exit 0
fi
printf '%s\n' "$@" > "$FAKE_COMMAND_LOG"
for arg do
  case "$arg" in
    --jsonfile=*) printf '%s' "$FAKE_REPORT" > "${arg#--jsonfile=}" ;;
  esac
done
exit "$FAKE_EXIT"
`
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_COMMAND_LOG", commandLog)
	t.Setenv("FAKE_PACKAGE", string(pkg))
	t.Setenv("FAKE_REPORT", report)
	t.Setenv("FAKE_EXIT", exitCode)
	return commandLog
}

func advanceAttempt(t *testing.T, cfg *config) {
	t.Helper()
	previous := filepath.Join(cfg.previousDir, "attempt-"+strconv.Itoa(cfg.attempt))
	if err := os.MkdirAll(cfg.previousDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(cfg.stateDir, previous); err != nil {
		t.Fatal(err)
	}
	cfg.attempt++
}

func readCheckpoint(t *testing.T, dir string) checkpoint {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, checkpointName))
	if err != nil {
		t.Fatal(err)
	}
	var state checkpoint
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func reportEvents(testResults ...string) string {
	var report strings.Builder
	packageResult := "pass"
	for i := 0; i < len(testResults); i += 2 {
		test, result := testResults[i], testResults[i+1]
		report.WriteString(eventJSON("run", test, ""))
		report.WriteString(eventJSON(result, test, ""))
		if result == "fail" {
			packageResult = "fail"
		}
	}
	// gotestsum appends events from retries to the same report.
	if len(testResults) >= 2 && testResults[len(testResults)-1] == "pass" {
		packageResult = "pass"
	}
	report.WriteString(eventJSON(packageResult, "", ""))
	return report.String()
}

func eventJSON(action, test, output string) string {
	data, _ := json.Marshal(map[string]string{"Action": action, "Package": testPackage, "Test": test, "Output": output})
	return string(data) + "\n"
}
