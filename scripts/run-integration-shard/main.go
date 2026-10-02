// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	checkpointVersion = 1
	testPackage       = "go.opentelemetry.io/obi/internal/test/integration"
	checkpointName    = "checkpoint.json"
)

type scope struct {
	RunID   string `json:"run_id"`
	Commit  string `json:"commit"`
	Shard   string `json:"shard"`
	Arch    string `json:"arch"`
	Pattern string `json:"pattern"`
}

type checkpoint struct {
	Version  int               `json:"version"`
	Scope    scope             `json:"scope"`
	Attempt  int               `json:"attempt"`
	Reusable bool              `json:"reusable"`
	Results  map[string]string `json:"results"`
}

type config struct {
	scope
	attempt     int
	previousDir string
	stateDir    string
	coverageDir string
	report      string
}

func main() {
	cfg, err := environmentConfig()
	if err == nil {
		err = runShard(cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func environmentConfig() (config, error) {
	attempt, err := strconv.Atoi(os.Getenv("GITHUB_RUN_ATTEMPT"))
	if err != nil || attempt < 1 {
		return config{}, errors.New("invalid GITHUB_RUN_ATTEMPT")
	}
	cfg := config{
		scope: scope{
			RunID:   os.Getenv("GITHUB_RUN_ID"),
			Commit:  os.Getenv("TEST_COMMIT"),
			Shard:   os.Getenv("MATRIX_ID"),
			Arch:    os.Getenv("MATRIX_ARCH"),
			Pattern: os.Getenv("MATRIX_TEST_PATTERN"),
		},
		attempt:     attempt,
		previousDir: os.Getenv("PREVIOUS_RESULTS_DIR"),
		stateDir:    os.Getenv("RETRY_STATE_DIR"),
		coverageDir: os.Getenv("TEST_COVERAGE_DIR"),
		report:      os.Getenv("TEST_REPORT"),
	}
	if cfg.RunID == "" || cfg.Commit == "" || cfg.Shard == "" || cfg.Arch == "" ||
		cfg.previousDir == "" || cfg.stateDir == "" || cfg.coverageDir == "" || cfg.report == "" {
		return config{}, errors.New("missing integration shard configuration")
	}
	return cfg, nil
}

func runShard(cfg config) error {
	tests, err := shardTests(cfg.Pattern)
	if err != nil {
		return err
	}
	state := checkpoint{
		Version: checkpointVersion,
		Scope:   cfg.scope,
		Attempt: cfg.attempt,
		Results: make(map[string]string, len(tests)),
	}
	for _, test := range tests {
		state.Results[test] = ""
	}
	if cfg.attempt > 1 {
		previous, loadErr := loadCheckpoint(cfg, tests)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Cannot resume shard; running all tests: %v\n", loadErr)
		} else {
			state.Results = previous.Results
		}
	}

	var pending []string
	for _, test := range tests {
		if result := state.Results[test]; result != "pass" && result != "skip" {
			pending = append(pending, test)
			state.Results[test] = ""
		}
	}
	// An interrupted attempt must not leave a reusable checkpoint behind.
	if err := saveCheckpoint(cfg.stateDir, state); err != nil {
		return err
	}
	if len(pending) == 0 {
		fmt.Println("All tests in this shard already completed successfully")
		state.Reusable = true
		return saveCheckpoint(cfg.stateDir, state)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.report), 0o755); err != nil {
		return err
	}
	fmt.Printf("Running %d of %d shard tests (attempt %d)\n", len(pending), len(tests), cfg.attempt)
	cmd := testCommand(strings.Join(pending, "|"), cfg.report)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	runErr := cmd.Run()
	results, reportErr := readResults(cfg.report, pending, runErr == nil)
	if reportErr == nil {
		maps.Copy(state.Results, results)
		state.Reusable = true
	} else {
		fmt.Fprintf(os.Stderr, "Test results cannot be reused: %v\n", reportErr)
	}
	if err := saveCheckpoint(cfg.stateDir, state); err != nil {
		return err
	}
	if runErr != nil {
		return fmt.Errorf("integration tests failed: %w", runErr)
	}
	return reportErr
}

func shardTests(pattern string) ([]string, error) {
	validName := regexp.MustCompile(`^Test[A-Za-z0-9_]+$`)
	tests := strings.Split(pattern, "|")
	for _, test := range tests {
		if !validName.MatchString(test) {
			return nil, fmt.Errorf("invalid shard test name %q", test)
		}
	}
	slices.Sort(tests)
	return slices.Compact(tests), nil
}

func testCommand(pattern, report string) *exec.Cmd {
	return exec.Command("go", "tool", "-modfile=./internal/tools/go.mod", "gotestsum",
		"--rerun-fails=2", "--rerun-fails-max-failures=2", "--rerun-fails-abort-on-data-race",
		"--rerun-fails-run-root-test", "--packages=./internal/test/integration", "-ftestname",
		"--jsonfile="+report, "--", "-race", "-count=1", "-timeout=40m", "-run=^("+pattern+")$")
}

func loadCheckpoint(cfg config, tests []string) (checkpoint, error) {
	paths, err := filepath.Glob(filepath.Join(cfg.previousDir, "*", checkpointName))
	if err != nil {
		return checkpoint{}, err
	}
	var latest checkpoint
	var latestDir string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return checkpoint{}, err
		}
		var state checkpoint
		if err := json.Unmarshal(data, &state); err != nil {
			return checkpoint{}, err
		}
		if state.Version != checkpointVersion || state.Scope != cfg.scope ||
			state.Attempt < 1 || state.Attempt >= cfg.attempt || len(state.Results) != len(tests) {
			return checkpoint{}, errors.New("checkpoint does not match this shard attempt")
		}
		for _, test := range tests {
			result, ok := state.Results[test]
			if !ok || (result != "" && result != "pass" && result != "fail" && result != "skip") {
				return checkpoint{}, errors.New("invalid checkpoint test result")
			}
		}
		if state.Attempt > latest.Attempt {
			latest = state
			latestDir = filepath.Dir(path)
		}
	}
	if !latest.Reusable {
		return checkpoint{}, errors.New("no reusable checkpoint for this shard")
	}
	if err := restoreCoverage(latestDir, cfg.coverageDir); err != nil {
		return checkpoint{}, err
	}
	return latest, nil
}

func restoreCoverage(source, destination string) error {
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	for _, pattern := range []string{"covmeta.*", "covcounters.*"} {
		paths, err := filepath.Glob(filepath.Join(source, pattern))
		if err != nil {
			return err
		}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(destination, filepath.Base(path)), data, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func saveCheckpoint(dir string, state checkpoint) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, checkpointName), data, 0o600)
}

func readResults(path string, tests []string, success bool) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	results := make(map[string]string, len(tests))
	for _, test := range tests {
		results[test] = ""
	}
	var packageResult string
	decoder := json.NewDecoder(file)
	for {
		var event struct {
			Action  string
			Package string
			Test    string
			Output  string
		}
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		if strings.Contains(event.Output, "WARNING: DATA RACE") ||
			strings.HasPrefix(event.Output, "panic:") || strings.Contains(event.Output, "\npanic:") {
			return nil, errors.New("data race or panic in test output")
		}
		if event.Package != testPackage || strings.Contains(event.Test, "/") {
			continue
		}
		if event.Test == "" {
			if event.Action == "pass" || event.Action == "fail" {
				packageResult = event.Action
			}
			continue
		}
		if _, ok := results[event.Test]; !ok {
			return nil, fmt.Errorf("unexpected test %q in report", event.Test)
		}
		switch event.Action {
		case "run":
			results[event.Test] = ""
		case "pass", "fail", "skip":
			results[event.Test] = event.Action
		}
	}
	failed := false
	for test, result := range results {
		if result == "" {
			return nil, fmt.Errorf("test %s did not complete", test)
		}
		failed = failed || result == "fail"
	}
	if packageResult == "" || success == failed || (success && packageResult != "pass") || (!success && packageResult != "fail") {
		return nil, errors.New("test report does not explain the runner exit status")
	}
	return results, nil
}
