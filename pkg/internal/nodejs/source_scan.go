// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
)

var sigusr1Quoted = []string{`"SIGUSR1"`, `'SIGUSR1'`, "`SIGUSR1`"}

const dependencyDir = "node_modules"

// sourceScanBudget bounds the scan, which walks an application tree of unknown
// size. Exhausting it reports sourceScanUnavailable, so a tree too large to
// search in time withholds the signal instead of being read as handler-free.
const sourceScanBudget = time.Second

// maxAppRootClimb bounds the search for the package root above the entry
// point's own directory.
const maxAppRootClimb = 8

// resolvedExtensions mirror the extensions Node appends when a manifest entry
// point has none of its own.
var resolvedExtensions = []string{"", ".js", ".cjs", ".mjs", "/index.js"}

// exportsConditions are the "exports" keys walked when resolving an entry
// point, in the order Node would consider them for a plain require.
var exportsConditions = []string{".", "default", "node", "require", "import"}

const maxExportsDepth = 4

// appScanSkipDirs keeps the shared skip list, which excludes system
// directories the entry point can resolve into, and descends into compiled
// output because a bundled application is the only copy of its own source.
var appScanSkipDirs = func() map[string]string {
	skip := harvest.CompiledScanSkipDirs()
	delete(skip, ".next")
	return skip
}()

// sourceSIGUSR1Reference looks for evidence that the application installs its
// own SIGUSR1 handler, for runtimes whose libuv signal tree cannot be read.
// It reports sourceScanUnavailable whenever some part of the application could
// not be examined, so an unreadable tree is never taken for a clean one.
func sourceSIGUSR1Reference(pid int) sourceScanResult {
	// Code passed with --eval never reaches the filesystem, so the command
	// line is the only place a handler registered that way appears.
	if cmdlineSIGUSR1Reference(pid) {
		return sourceScanFound
	}

	entryDir, err := harvest.FindNodeJSAppDir(app.PID(pid))
	if err != nil {
		return sourceScanUnavailable
	}

	return dirSIGUSR1Reference(applicationRoot(entryDir))
}

// applicationRoot climbs from the entry point's directory to the package root,
// so that an entry point such as /app/dist/main.js is scanned together with
// /app/src and /app/node_modules rather than /app/dist alone.
func applicationRoot(entryDir string) string {
	dir := entryDir

	for range maxAppRootClimb {
		if isPackageRoot(dir) {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir || filepath.Base(dir) == "root" {
			break
		}
		dir = parent
	}

	return entryDir
}

func isPackageRoot(dir string) bool {
	if info, err := os.Stat(filepath.Join(dir, "package.json")); err == nil && info.Mode().IsRegular() {
		return true
	}
	return isDirectory(filepath.Join(dir, dependencyDir))
}

func cmdlineSIGUSR1Reference(pid int) bool {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}

	return containsSIGUSR1(strings.ReplaceAll(string(cmdline), "\x00", " "))
}

func containsSIGUSR1(line string) bool {
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
		if containsSIGUSR1(line) {
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

func dirSIGUSR1Reference(dir string) sourceScanResult {
	deadline := time.Now().Add(sourceScanBudget)

	if result := scanApplicationTree(dir, deadline); result != sourceScanClean {
		return result
	}

	return scanDependencies(dir, deadline)
}

// scanApplicationTree walks the application's own files. Entries the walk could
// not examine downgrade the result to unavailable without stopping it, so one
// unreadable directory neither hides the rest of the tree nor passes for a
// clean scan.
func scanApplicationTree(dir string, deadline time.Time) sourceScanResult {
	result := sourceScanClean

	err := harvest.WalkAppJSFiles(dir, appScanSkipDirs,
		func(path string) error {
			if time.Now().After(deadline) {
				result = sourceScanUnavailable
				return filepath.SkipAll
			}

			switch scanFileForSIGUSR1(path) {
			case sourceScanFound:
				result = sourceScanFound
				return filepath.SkipAll
			case sourceScanUnavailable:
				result = sourceScanUnavailable
			case sourceScanClean:
			}

			return nil
		},
		func(_ string, _ error) {
			result = sourceScanUnavailable
		})

	if err != nil && result != sourceScanFound {
		return sourceScanUnavailable
	}

	return result
}

// scanDependencies scans the entry point of each installed dependency. Walking
// every dependency in full is too expensive for a discovered process, and a
// dependency that installs a SIGUSR1 handler does so from the module the
// application loads.
func scanDependencies(dir string, deadline time.Time) sourceScanResult {
	// Yarn Plug'n'Play keeps dependencies in zip archives with no
	// node_modules to walk, so their handlers cannot be seen at all.
	if hasPlugNPlayManifest(dir) {
		return sourceScanUnavailable
	}

	root := filepath.Join(dir, dependencyDir)

	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return sourceScanClean
		}
		return sourceScanUnavailable
	}

	result := sourceScanClean

	for _, pkgDir := range dependencyPackageDirs(root, entries) {
		if time.Now().After(deadline) {
			return sourceScanUnavailable
		}

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

func hasPlugNPlayManifest(dir string) bool {
	for _, name := range []string{".pnp.cjs", ".pnp.js"} {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && info.Mode().IsRegular() {
			return true
		}
	}

	return false
}

// dependencyPackageDirs resolves through symlinks because pnpm materializes
// every package as a link into its own store.
func dependencyPackageDirs(root string, entries []os.DirEntry) []string {
	var dirs []string

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}

		path := filepath.Join(root, name)
		if !isDirectory(path) {
			continue
		}

		if !strings.HasPrefix(name, "@") {
			dirs = append(dirs, path)
			continue
		}

		scoped, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		for _, s := range scoped {
			scopedPath := filepath.Join(path, s.Name())
			if isDirectory(scopedPath) {
				dirs = append(dirs, scopedPath)
			}
		}
	}

	return dirs
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func packageEntryPoints(pkgDir string) []string {
	candidates := []string{"index.js"}

	if manifest, err := os.ReadFile(filepath.Join(pkgDir, "package.json")); err == nil {
		var pkg struct {
			Main    string          `json:"main"`
			Exports json.RawMessage `json:"exports"`
		}
		if err := json.Unmarshal(manifest, &pkg); err == nil {
			if pkg.Main != "" {
				candidates = append(candidates, pkg.Main)
			}
			candidates = append(candidates, exportsCandidates(pkg.Exports, 0)...)
		}
	}

	var entries []string
	for _, candidate := range candidates {
		resolved, ok := resolveEntryPoint(pkgDir, candidate)
		if ok && !slices.Contains(entries, resolved) {
			entries = append(entries, resolved)
		}
	}

	return entries
}

// exportsCandidates collects the paths reachable through the conditional
// "exports" map, which ESM-only packages use in place of "main".
func exportsCandidates(raw json.RawMessage, depth int) []string {
	if len(raw) == 0 || depth > maxExportsDepth {
		return nil
	}

	var asString string
	if json.Unmarshal(raw, &asString) == nil {
		return []string{asString}
	}

	var asObject map[string]json.RawMessage
	if json.Unmarshal(raw, &asObject) != nil {
		return nil
	}

	var candidates []string
	for _, condition := range exportsConditions {
		if value, ok := asObject[condition]; ok {
			candidates = append(candidates, exportsCandidates(value, depth+1)...)
		}
	}

	return candidates
}

// resolveEntryPoint applies Node's extension and directory-index resolution to
// a manifest entry, which routinely omits the extension.
func resolveEntryPoint(pkgDir, entry string) (string, bool) {
	base := filepath.Join(pkgDir, filepath.Clean("/"+entry))

	for _, suffix := range resolvedExtensions {
		candidate := base + suffix
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, true
		}
	}

	return "", false
}
