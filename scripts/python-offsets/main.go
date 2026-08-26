// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/grafana/go-offsets-tracker/pkg/offsets"
)

const (
	repository     = "https://github.com/python/cpython.git"
	offsetsPath    = "pkg/internal/cpython/runtime/offsets.json"
	checkpointPath = "configs/offsets/python_versions.json"
	probePath      = "scripts/python-offsets/testdata/python_inspect.c"
)

var finalTag = regexp.MustCompile(`^v(3\.(9|10|11|12|13|14)\.(\d+))$`)

type checkpoint struct {
	Series map[string]verifiedTag `json:"series"`
}

type verifiedTag struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
}

type release struct {
	tag, commit, version, series string
	patch                        int
}

type probeResult struct {
	Version            string `json:"version"`
	Finalizing         uint64 `json:"finalizing"`
	Main               uint64 `json:"main"`
	InterpreterGC      uint64 `json:"interpreter_gc"`
	GenerationStats    uint64 `json:"generation_stats"`
	Collecting         uint64 `json:"collecting"`
	DebugGC            uint64 `json:"debug_gc"`
	DebugInterpreterGC uint64 `json:"debug_interpreter_gc"`
}

type offsetsFile struct {
	Supported map[string]int            `json:"supported"`
	Data      map[string]offsets.Struct `json:"data"`
}

func main() {
	if err := update(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func update(ctx context.Context) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("python offsets require linux/amd64, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	state := &checkpoint{}
	if err := readJSON(checkpointPath, state); err != nil {
		return err
	}
	file := offsetsFile{}
	if err := readJSON(offsetsPath, &file); err != nil {
		return err
	}
	if file.Supported == nil {
		return fmt.Errorf("missing supported Python versions in %s", offsetsPath)
	}
	track := &offsets.Track{Data: file.Data}
	output, err := run(ctx, "", "git", "ls-remote", "--tags", repository)
	if err != nil {
		return err
	}
	refs, err := parseRefs(output)
	if err != nil {
		return err
	}
	releases, err := selectReleases(refs, state)
	if err != nil {
		return err
	}

	temporary, err := os.MkdirTemp("", "obi-python-offsets-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	source := filepath.Join(temporary, "cpython")
	if _, err := run(ctx, "", "git", "init", "--quiet", source); err != nil {
		return err
	}
	if _, err := run(ctx, "", "git", "-C", source, "remote", "add", "origin", repository); err != nil {
		return err
	}

	changed := false
	for _, item := range releases {
		result, inspectErr := inspect(ctx, temporary, source, item)
		if inspectErr != nil {
			return inspectErr
		}
		fieldChanged, validateErr := validate(track, item, result)
		if validateErr != nil {
			return validateErr
		}
		changed = changed || fieldChanged
		changed = changed || file.Supported[item.series] != item.patch
		file.Supported[item.series] = item.patch
		next := verifiedTag{Tag: item.tag, Commit: item.commit}
		changed = changed || state.Series[item.series] != next
		state.Series[item.series] = next
	}
	if !changed {
		return nil
	}
	if err := writeJSON(offsetsPath, file); err != nil {
		return err
	}
	return writeJSON(checkpointPath, state)
}

func parseRefs(data []byte) (map[string]string, error) {
	refs := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "refs/tags/") {
			continue
		}
		name := strings.TrimPrefix(fields[1], "refs/tags/")
		if strings.HasSuffix(name, "^{}") || refs[name] == "" {
			refs[strings.TrimSuffix(name, "^{}")] = fields[0]
		}
	}
	for name, commit := range refs {
		if len(commit) != 40 {
			return nil, fmt.Errorf("tag %s has invalid commit %q", name, commit)
		}
	}
	return refs, nil
}

func selectReleases(refs map[string]string, state *checkpoint) ([]release, error) {
	var selected []release
	for _, series := range []string{"3.9", "3.10", "3.11", "3.12", "3.13", "3.14"} {
		stored, ok := state.Series[series]
		if !ok || refs[stored.Tag] != stored.Commit {
			return nil, fmt.Errorf("verified CPython %s tag is missing or moved", series)
		}
		storedMatch := finalTag.FindStringSubmatch(stored.Tag)
		if len(storedMatch) == 0 || "3."+storedMatch[2] != series {
			return nil, fmt.Errorf("verified CPython %s tag is not a final release", series)
		}
		storedPatch, _ := strconv.Atoi(storedMatch[3])
		var pending []release
		for tag, commit := range refs {
			match := finalTag.FindStringSubmatch(tag)
			if len(match) == 0 || "3."+match[2] != series {
				continue
			}
			patch, _ := strconv.Atoi(match[3])
			if patch >= storedPatch {
				pending = append(pending, release{
					tag: tag, commit: commit, version: match[1], series: series, patch: patch,
				})
			}
		}
		if len(pending) == 0 {
			return nil, fmt.Errorf("no final CPython %s release found", series)
		}
		sort.Slice(pending, func(i, j int) bool { return pending[i].patch < pending[j].patch })
		selected = append(selected, pending...)
	}
	return selected, nil
}

func inspect(ctx context.Context, temporary, source string, item release) (probeResult, error) {
	if _, err := run(ctx, "", "git", "-C", source, "fetch", "--quiet", "--depth=1", "origin", "refs/tags/"+item.tag); err != nil {
		return probeResult{}, err
	}
	if _, err := run(ctx, "", "git", "-C", source, "checkout", "--quiet", "--force", "--detach", item.commit); err != nil {
		return probeResult{}, err
	}
	build := filepath.Join(temporary, "build-"+item.version)
	if err := os.Mkdir(build, 0o755); err != nil {
		return probeResult{}, err
	}
	if _, err := run(ctx, build, filepath.Join(source, "configure"), "--quiet", "--without-ensurepip"); err != nil {
		return probeResult{}, err
	}
	probe, _ := filepath.Abs(probePath)
	executable := filepath.Join(build, "python-offsets")
	if _, err := run(ctx, build, "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-DPy_BUILD_CORE",
		"-I"+build, "-I"+filepath.Join(source, "Include"), probe, "-o", executable); err != nil {
		return probeResult{}, err
	}
	output, err := run(ctx, build, executable)
	if err != nil {
		return probeResult{}, err
	}
	result := probeResult{}
	if err := json.Unmarshal(output, &result); err != nil {
		return probeResult{}, fmt.Errorf("parsing %s probe: %w", item.tag, err)
	}
	return result, nil
}

func validate(track *offsets.Track, item release, result probeResult) (bool, error) {
	if normalizeVersion(result.Version) != item.version {
		return false, fmt.Errorf("CPython %s reported version %q", item.tag, result.Version)
	}

	checks := map[[2]string]uint64{}
	switch item.series {
	case "3.9", "3.10", "3.11", "3.12":
		checks[[2]string{"_PyRuntimeState", "_finalizing"}] = result.Finalizing
		checks[[2]string{"_PyRuntimeState", "interpreters.main"}] = result.Main
		checks[[2]string{"PyInterpreterState", "gc"}] = result.InterpreterGC
		checks[[2]string{"_gc_runtime_state", "collecting"}] = result.Collecting
		checks[[2]string{"_gc_runtime_state", "generation_stats"}] = result.GenerationStats
	case "3.13", "3.14":
		checks[[2]string{"_gc_runtime_state", "generation_stats"}] = result.GenerationStats
		checks[[2]string{"_Py_DebugOffsets", "gc"}] = result.DebugGC
		checks[[2]string{"_Py_DebugOffsets", "interpreter_state.gc"}] = result.DebugInterpreterGC
	}
	// These ABI tripwires require decoder review rather than automatic table advancement.
	wantCollecting := map[string]uint64{"3.13": 200, "3.14": 192}
	if expected := wantCollecting[item.series]; expected != 0 && result.Collecting != expected {
		return false, fmt.Errorf("CPython %s changed GC collecting: expected %d, got %d", item.tag, expected, result.Collecting)
	}
	for name, observed := range checks {
		expected, ok := track.Find(name[0], name[1], item.version)
		if !ok || expected != observed {
			return false, fmt.Errorf("CPython %s changed %s.%s: expected %d, got %d", item.tag, name[0], name[1], expected, observed)
		}
	}
	changed := false
	if item.series == "3.12" {
		for _, name := range [][2]string{{"_PyRuntimeState", "_finalizing"}, {"_PyRuntimeState", "interpreters.main"}, {"PyInterpreterState", "gc"}, {"_gc_runtime_state", "collecting"}} {
			changed = setNewest(track, name, item.version) || changed
		}
	}
	if item.series == "3.14" {
		for _, name := range [][2]string{{"_gc_runtime_state", "generation_stats"}, {"_Py_DebugOffsets", "gc"}, {"_Py_DebugOffsets", "interpreter_state.gc"}} {
			changed = setNewest(track, name, item.version) || changed
		}
	}
	return changed, nil
}

func setNewest(track *offsets.Track, name [2]string, value string) bool {
	field := track.Data[name[0]][name[1]]
	if field.Versions.Newest == value {
		return false
	}
	field.Versions.Newest = value
	track.Data[name[0]][name[1]] = field
	return true
}

func normalizeVersion(value string) string {
	return strings.Replace(value, "b", "-b", 1)
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.CreateTemp(filepath.Dir(path), ".python-offsets-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := file.Chmod(info.Mode()); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		switch key {
		case "CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "CONFIG_SITE", "LC_ALL":
			continue
		}
		cmd.Env = append(cmd.Env, value)
	}
	cmd.Env = append(cmd.Env, "CONFIG_SITE=/dev/null", "LC_ALL=C")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, bytes.TrimSpace(output))
	}
	return output, nil
}
