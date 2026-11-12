// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	checkpointVersion  = 1
	testPackage        = "go.opentelemetry.io/obi/internal/test/integration"
	checkpointName     = "checkpoint.json"
	weightsFile        = "scripts/integration-test-weights.generated.json"
	defaultWeightKey   = "_default"
	maxReruns          = 2
	maxRerunFailures   = 2
	defaultTestTimeout = 40 * time.Minute
	// time left after go test's own timeout to compile, write the report and save the checkpoint
	timeoutMargin = 3 * time.Minute
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
	reruns      int
	// zero when the shard has no time limit
	deadline time.Time
	// typical seconds per test, used to skip reruns that cannot finish before the deadline
	weights map[string]float64
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
		reruns:      maxReruns,
		weights:     loadWeights(weightsFile),
	}
	if cfg.RunID == "" || cfg.Commit == "" || cfg.Shard == "" || cfg.Arch == "" ||
		cfg.previousDir == "" || cfg.stateDir == "" || cfg.coverageDir == "" || cfg.report == "" {
		return config{}, errors.New("missing integration shard configuration")
	}
	if minutes := os.Getenv("TEST_STEP_TIMEOUT_MINUTES"); minutes != "" {
		value, err := strconv.Atoi(minutes)
		if err != nil || value < 1 {
			return config{}, errors.New("invalid TEST_STEP_TIMEOUT_MINUTES")
		}
		cfg.deadline = time.Now().Add(time.Duration(value)*time.Minute - timeoutMargin)
	}
	return cfg, nil
}

// loadWeights returns nil when the weights are unavailable, which only disables the rerun time estimate
func loadWeights(path string) map[string]float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var weights map[string]float64
	if err := json.Unmarshal(data, &weights); err != nil {
		return nil
	}
	return weights
}

func runShard(cfg config) error {
	tests, err := shardTests(cfg.Pattern)
	if err != nil {
		return err
	}
	tests, err = runnableTests(tests)
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
			state.Reusable = true
		}
	}

	var pending []string
	for _, test := range tests {
		if result := state.Results[test]; result != "pass" && result != "skip" {
			pending = append(pending, test)
			state.Results[test] = ""
		}
	}
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
	for pass := 0; ; pass++ {
		timeout := cfg.testTimeout()
		if timeout <= 0 {
			return fmt.Errorf("no time left to run %s", strings.Join(pending, ", "))
		}

		report := cfg.reportPath(pass)
		interrupted, runErr := runTests(testCommand(strings.Join(pending, "|"), report, timeout))
		var results map[string]string
		var reportErr error
		if interrupted {
			results, reportErr = readInterruptedResults(report, pending)
		} else {
			results, reportErr = readResults(report, pending, runErr == nil)
		}
		if reportErr == nil {
			maps.Copy(state.Results, results)
			state.Reusable = true
		} else {
			fmt.Fprintf(os.Stderr, "Test results cannot be reused: %v\n", reportErr)
		}
		if err := saveCheckpoint(cfg.stateDir, state); err != nil {
			return err
		}
		if runErr == nil {
			return reportErr
		}
		if reportErr != nil || interrupted {
			return fmt.Errorf("integration tests failed: %w", runErr)
		}

		failed, ok := cfg.rerunnable(pass, results)
		if !ok {
			return fmt.Errorf("integration tests failed: %w", runErr)
		}
		fmt.Printf("Rerunning failed tests: %s\n", strings.Join(failed, ", "))
		pending = failed
	}
}

// rerunnable returns the failed tests when they are few, every other test completed and their
// typical duration fits before the deadline; otherwise the failure is left to a rerun of the job
func (cfg config) rerunnable(pass int, results map[string]string) ([]string, bool) {
	if pass >= cfg.reruns {
		return nil, false
	}

	var failed []string
	for test, result := range results {
		switch result {
		case "":
			return nil, false
		case "fail":
			failed = append(failed, test)
		}
	}
	if len(failed) == 0 || len(failed) > maxRerunFailures {
		return nil, false
	}
	slices.Sort(failed)

	if needed := cfg.expectedDuration(failed); !cfg.deadline.IsZero() && time.Until(cfg.deadline) < needed {
		fmt.Printf("Not rerunning %s: needs about %s, %s left\n",
			strings.Join(failed, ", "), needed, time.Until(cfg.deadline).Round(time.Second))
		return nil, false
	}
	return failed, true
}

func (cfg config) expectedDuration(tests []string) time.Duration {
	var seconds float64
	for _, test := range tests {
		weight, ok := cfg.weights[test]
		if !ok {
			weight = cfg.weights[defaultWeightKey]
		}
		seconds += weight
	}
	return time.Duration(seconds * float64(time.Second))
}

func (cfg config) testTimeout() time.Duration {
	if cfg.deadline.IsZero() {
		return defaultTestTimeout
	}
	return time.Until(cfg.deadline).Round(time.Second)
}

// reportPath keeps every rerun's report next to the first one
func (cfg config) reportPath(pass int) string {
	if pass == 0 {
		return cfg.report
	}
	return strings.TrimSuffix(cfg.report, ".log") + "-rerun" + strconv.Itoa(pass) + ".log"
}

// runTests forwards one interrupt to gotestsum, which runs in its own process group so a
// signal sent to the whole step reaches it only once; gotestsum relays it to go test
func runTests(cmd *exec.Cmd) (bool, error) {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	if err := cmd.Start(); err != nil {
		return false, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	interrupted := false
	for {
		select {
		case err := <-done:
			return interrupted, err
		case <-signals:
			if !interrupted {
				interrupted = true
				_ = cmd.Process.Signal(os.Interrupt)
			}
		}
	}
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

func testCommand(pattern, report string, timeout time.Duration) *exec.Cmd {
	return exec.Command("go", "tool", "-modfile=./internal/tools/go.mod", "gotestsum",
		"--packages=./internal/test/integration", "-ftestname", "--jsonfile="+report,
		"--", "-race", "-count=1", "-timeout="+timeout.String(), "-run=^("+pattern+")$")
}

func runnableTests(candidates []string) ([]string, error) {
	command := exec.Command("go", "list", "-race", "-json", "./internal/test/integration")
	command.Stderr = os.Stderr
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("list integration test files: %w", err)
	}
	var pkg struct {
		Dir          string
		TestGoFiles  []string
		XTestGoFiles []string
	}
	if err := json.Unmarshal(output, &pkg); err != nil {
		return nil, err
	}
	if pkg.Dir == "" {
		return nil, errors.New("missing integration test package directory")
	}
	available := make(map[string]bool)
	for _, name := range append(pkg.TestGoFiles, pkg.XTestGoFiles...) {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(pkg.Dir, name), nil, 0)
		if err != nil {
			return nil, err
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil && function.Name.Name != "TestMain" {
				available[function.Name.Name] = true
			}
		}
	}
	var tests []string
	for _, test := range candidates {
		if available[test] {
			tests = append(tests, test)
		}
	}
	return tests, nil
}

func loadCheckpoint(cfg config, tests []string) (checkpoint, error) {
	paths, err := filepath.Glob(filepath.Join(cfg.previousDir, "*", checkpointName))
	if err != nil {
		return checkpoint{}, err
	}
	flatPaths, err := filepath.Glob(filepath.Join(cfg.previousDir, checkpointName))
	if err != nil {
		return checkpoint{}, err
	}
	paths = append(paths, flatPaths...)
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
	if latest.Attempt == 0 {
		return checkpoint{}, errors.New("missing checkpoint for this shard")
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

type testReport struct {
	results       map[string]string
	packageResult string
	panicked      bool
}

func readResults(path string, tests []string, success bool) (map[string]string, error) {
	report, err := parseReport(path, tests)
	if err != nil {
		return nil, err
	}
	results := report.results
	if report.panicked {
		if success || report.packageResult != "fail" {
			return nil, errors.New("test report does not explain the runner exit status")
		}
		return results, nil
	}
	failed := false
	for test, result := range results {
		if result == "" {
			return nil, fmt.Errorf("test %s did not complete", test)
		}
		failed = failed || result == "fail"
	}
	packageResult := report.packageResult
	if packageResult == "" || success == failed || (success && packageResult != "pass") || (!success && packageResult != "fail") {
		return nil, errors.New("test report does not explain the runner exit status")
	}
	return results, nil
}

// readInterruptedResults keeps the outcomes of the tests that completed before an interrupt
func readInterruptedResults(path string, tests []string) (map[string]string, error) {
	report, err := parseReport(path, tests)
	return report.results, err
}

func parseReport(path string, tests []string) (testReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return testReport{}, err
	}
	defer file.Close()
	results := make(map[string]string, len(tests))
	for _, test := range tests {
		results[test] = ""
	}
	var packageResult string
	panicked := false
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
			return testReport{}, err
		}
		if strings.Contains(event.Output, "WARNING: DATA RACE") {
			return testReport{}, errors.New("data race in test output")
		}
		if strings.HasPrefix(event.Output, "panic:") || strings.Contains(event.Output, "\npanic:") {
			panicked = true
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
			return testReport{}, fmt.Errorf("unexpected test %q in report", event.Test)
		}
		switch event.Action {
		case "run":
			results[event.Test] = ""
		case "pass", "fail", "skip":
			results[event.Test] = event.Action
		}
	}
	return testReport{results: results, packageResult: packageResult, panicked: panicked}, nil
}
