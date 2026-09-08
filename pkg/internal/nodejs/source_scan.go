// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
)

var sigusr1Quoted = []string{`"SIGUSR1"`, `'SIGUSR1'`, "`SIGUSR1`"}

const dependencyDir = "node_modules"

// sourceSIGUSR1Reference scans the Node.js application's source files for
// references to "SIGUSR1", 'SIGUSR1', or `SIGUSR1`. This is a fallback
// detection method used when the symbol-based detection fails (e.g. stripped
// binaries with dynamic libuv).
func sourceSIGUSR1Reference(pid int) sourceScanResult {
	// Code passed with --eval never reaches the filesystem, so the command
	// line is the only place a handler registered that way appears.
	if cmdlineSIGUSR1Reference(pid) {
		return sourceScanFound
	}

	dir, err := harvest.FindNodeJSAppDir(app.PID(pid))
	if err != nil {
		return sourceScanUnavailable
	}

	return dirSIGUSR1Reference(dir)
}

func cmdlineSIGUSR1Reference(pid int) bool {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}

	return lineContainsSIGUSR1(strings.ReplaceAll(string(cmdline), "\x00", " "))
}

func lineContainsSIGUSR1(line string) bool {
	for _, pattern := range sigusr1Quoted {
		if strings.Contains(line, pattern) {
			return true
		}
	}
	return false
}

func scanFileForSIGUSR1(path string) sourceScanResult {
	found := false
	if err := harvest.ScanJSFileLines(path, func(line string) bool {
		if lineContainsSIGUSR1(line) {
			found = true
			return true
		}
		return false
	}); err != nil {
		return sourceScanUnavailable
	}

	if found {
		return sourceScanFound
	}
	return sourceScanClean
}

// dirSIGUSR1Reference scans the application's own compiled and source files
// plus the entry point of every installed dependency. A scan that cannot read
// a file reports sourceScanUnavailable rather than a clean result, so an
// unreadable tree is never mistaken for an application without a handler.
func dirSIGUSR1Reference(dir string) sourceScanResult {
	result := sourceScanClean

	_ = harvest.WalkCompiledJSFiles(dir, func(path string) error {
		switch scanFileForSIGUSR1(path) {
		case sourceScanFound:
			result = sourceScanFound
			return filepath.SkipAll
		case sourceScanUnavailable:
			result = sourceScanUnavailable
		case sourceScanClean:
		}
		return nil
	})

	if result != sourceScanClean {
		return result
	}

	return dependenciesSIGUSR1Reference(dir)
}

// dependenciesSIGUSR1Reference scans the entry point of each installed
// dependency. Walking the whole node_modules tree of every discovered process
// is too expensive, but a dependency that installs a SIGUSR1 handler does it
// from the module the application loads.
func dependenciesSIGUSR1Reference(dir string) sourceScanResult {
	result := sourceScanClean

	for _, pkgDir := range dependencyPackageDirs(filepath.Join(dir, dependencyDir)) {
		for _, entry := range packageEntryPoints(pkgDir) {
			switch scanFileForSIGUSR1(entry) {
			case sourceScanFound:
				return sourceScanFound
			case sourceScanUnavailable:
				result = sourceScanUnavailable
			case sourceScanClean:
			}
		}
	}

	return result
}

func dependencyPackageDirs(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	var dirs []string
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		path := filepath.Join(root, entry.Name())
		if !strings.HasPrefix(entry.Name(), "@") {
			dirs = append(dirs, path)
			continue
		}

		scoped, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		for _, s := range scoped {
			if s.IsDir() {
				dirs = append(dirs, filepath.Join(path, s.Name()))
			}
		}
	}

	return dirs
}

func packageEntryPoints(pkgDir string) []string {
	candidates := []string{filepath.Join(pkgDir, "index.js")}

	if manifest, err := os.ReadFile(filepath.Join(pkgDir, "package.json")); err == nil {
		var pkg struct {
			Main string `json:"main"`
		}
		if err := json.Unmarshal(manifest, &pkg); err == nil && pkg.Main != "" {
			candidates = append(candidates, filepath.Join(pkgDir, filepath.Clean("/"+pkg.Main)))
		}
	}

	var entries []string
	for _, candidate := range candidates {
		if slices.Contains(entries, candidate) {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			entries = append(entries, candidate)
		}
	}

	return entries
}
