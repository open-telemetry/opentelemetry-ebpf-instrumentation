// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
	"go.opentelemetry.io/obi/pkg/internal/pythontools"
)

const (
	maxPythonFileBytes = MaxJSFileScanBytes
	maxPythonFiles     = 10_000
	pyLit              = `(?:[rRuU])?(?:"([^"\r\n]*)"|'([^'\r\n]*)')`
	pyObj              = `(?:[A-Za-z_][A-Za-z0-9_]*\.)+`
)

var pySkipDirs = map[string]struct{}{
	".hg":           {},
	".nox":          {},
	".svn":          {},
	".tox":          {},
	".venv":         {},
	"__pycache__":   {},
	"dist-packages": {},
	"env":           {},
	"site-packages": {},
	"venv":          {},
}

func ExtractPythonRoutes(ctx context.Context, fi *exec.FileInfo) (*RouteHarvesterResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fi == nil {
		return nil, errors.New("python route harvesting requires process file info")
	}

	dirs, err := pythontools.AppDirsForPID(fi.Pid(), fi.ServiceAttrs().EnvVars)
	if err != nil {
		return nil, err
	}
	importRoots := dirs.PythonPath
	if dirs.AppOnImportPath {
		importRoots = append([]string{dirs.App}, dirs.PythonPath...)
	}
	return extractPythonRoutesFrom(ctx, append([]string{dirs.App}, dirs.PythonPath...), importRoots, maxPythonFiles)
}

func extractPythonRoutes(ctx context.Context, dirs ...string) (*RouteHarvesterResult, error) {
	return extractPythonRoutesFrom(ctx, dirs, dirs, maxPythonFiles)
}

// extractPythonRoutesFrom scans the application directory, dirs[0], and then
// any further import roots, sharing maxFiles across all of them. Django
// includes resolve against importRoots, in the order Python searches them.
func extractPythonRoutesFrom(ctx context.Context, dirs, importRoots []string, maxFiles int) (*RouteHarvesterResult, error) {
	log := slog.With("component", "route.harvester.python")
	e := pythonExtractor{
		routes:       map[string]struct{}{},
		djangoRoutes: map[string][]djangoRoute{},
	}
	kind := PartialRoutes
	roots, boundaries := pythonScanRoots(dirs)
	remaining := maxFiles
	for i, root := range roots {
		scanned, err := walkPythonFiles(ctx, root, remaining, boundaries, func(path string) error {
			if err := e.scanFile(ctx, path); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				log.Debug("error processing file", "file", path, "error", err)
				return nil
			}
			if len(e.djangoRoutes[path]) > 0 && langtools.PathWithinBoundary(dirs[0], path) {
				kind = CompleteRoutes
			}
			return nil
		})
		if err != nil {
			if i == 0 || ctx.Err() != nil {
				return nil, fmt.Errorf("scan Python directory: %w", err)
			}
			log.Debug("error scanning Python import root", "dir", root, "error", err)
		}
		remaining -= scanned
		if remaining <= 0 {
			break
		}
	}

	if err := resolveDjangoRoutes(ctx, dirs, importRoots, e.djangoRoutes, e.routes); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(e.routes))
	for route := range e.routes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result = append(result, route)
	}
	sort.Strings(result)
	return &RouteHarvesterResult{Routes: result, Kind: kind}, nil
}

// pythonScanRoots returns the directories to walk, the application
// directory, dirs[0], first, followed by its import roots without duplicates.
// Installation directories such as site-packages are left out, and the
// packages that the .dist-info metadata of a walked directory declares are
// skipped: their routes are not the application's. Every other root, every
// left-out directory and every installed package is a boundary that no walk
// enters, so no file is scanned twice and an explicit root is scanned even
// when an enclosing walk would skip it by name.
func pythonScanRoots(dirs []string) ([]string, map[string]struct{}) {
	roots := make([]string, 0, len(dirs))
	boundaries := map[string]struct{}{}
	for i, dir := range dirs {
		if slices.Contains(roots, dir) {
			continue
		}
		boundaries[dir] = struct{}{}
		if i > 0 && pythonInstallationDir(dir) {
			continue
		}
		roots = append(roots, dir)
		for _, installed := range installedPythonPackages(dir) {
			boundaries[installed] = struct{}{}
		}
	}
	return roots, boundaries
}

func pythonInstallationDir(dir string) bool {
	name := filepath.Base(dir)
	return name == "site-packages" || name == "dist-packages"
}

func installedPythonPackages(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var installed []string
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasSuffix(entry.Name(), ".dist-info") {
			continue
		}
		for _, owned := range distributionOwnedPaths(filepath.Join(dir, entry.Name(), "RECORD")) {
			installed = append(installed, filepath.Join(dir, owned))
		}
	}
	return installed
}

func distributionOwnedPaths(record string) []string {
	file, _ := langtools.OpenMetadataFile(record, maxPythonFileBytes)
	if file == nil {
		return nil
	}
	defer file.Close()

	recorded := map[string]struct{}{}
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		entry, _, _ := strings.Cut(scan.Text(), ",")
		path := filepath.Clean(filepath.FromSlash(entry))
		if entry == "" || filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
			continue
		}
		recorded[path] = struct{}{}
	}

	var owned []string
	for path := range recorded {
		if filepath.Ext(path) != ".py" {
			continue
		}
		if root := ownedPackageRoot(path, recorded); !slices.Contains(owned, root) {
			owned = append(owned, root)
		}
	}
	return owned
}

func ownedPackageRoot(path string, recorded map[string]struct{}) string {
	parts := strings.Split(path, string(filepath.Separator))
	for i := 1; i < len(parts); i++ {
		packageDir := filepath.Join(parts[:i]...)
		if _, ok := recorded[filepath.Join(packageDir, "__init__.py")]; ok {
			return packageDir
		}
	}
	return path
}

func walkPythonFiles(ctx context.Context, root string, maxFiles int, boundaries map[string]struct{}, fn func(string) error) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	files, err := os.ReadDir(root)
	if err != nil {
		return 0, err
	}
	scanned := 0
	limit := false
	for _, file := range files {
		path := filepath.Join(root, file.Name())
		if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err != nil {
				return err
			}
			_, boundary := boundaries[path]
			if info.IsDir() {
				if boundary || skipPythonDir(info.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if boundary || !info.Mode().IsRegular() || info.Size() > maxPythonFileBytes || filepath.Ext(path) != ".py" {
				return nil
			}
			scanned++
			if err := fn(path); err != nil {
				return err
			}
			if scanned >= maxFiles {
				limit = true
				return filepath.SkipAll
			}
			return nil
		}); err != nil {
			return scanned, err
		}
		if limit {
			break
		}
	}
	return scanned, ctx.Err()
}

func skipPythonDir(name string) bool {
	if _, ok := skipDirs[name]; ok {
		return true
	}
	_, ok := pySkipDirs[name]
	return ok
}

type pythonExtractor struct {
	routes       map[string]struct{}
	djangoRoutes map[string][]djangoRoute
}

func (e *pythonExtractor) scanFile(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, _ := langtools.OpenMetadataFile(path, maxPythonFileBytes)
	if file == nil {
		return nil
	}
	defer file.Close()

	var djangoRoutes []djangoRoute
	djangoLists := map[string]*djangoList{}
	djangoAliases := map[string]string{}
	hasDjangoPath := false
	scanStmt := func(text string) {
		scanPythonStmt(text, e.routes)
		if match := djangoFromImportAliasPattern.FindStringSubmatch(text); match != nil {
			djangoAliases[match[3]] = match[1] + "." + match[2]
		} else if match := djangoImportAliasPattern.FindStringSubmatch(text); match != nil {
			djangoAliases[match[2]] = match[1]
		}
		// Remember the Django path import so subsequent statements can be scanned as Django routes.
		if djangoPathImportPattern.MatchString(text) {
			hasDjangoPath = true
		}
		if hasDjangoPath {
			if assignment, ok := djangoListAssignment(text); ok {
				applyDjangoAssignment(djangoLists, assignment, djangoAliases)
				// Subsequent includes resolve this name through its tracked list.
				delete(djangoAliases, assignment.name)
				return
			}
			djangoRoutes = append(djangoRoutes, scanDjango(text, djangoAliases)...)
		}
	}

	scan := bufio.NewScanner(file)
	var stmt strings.Builder
	depth := 0
	for scan.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if stmt.Len() == 0 {
			depth = parenDelta(line)
			startsStmt := startsFastAPI(line) || startsFlask(line) ||
				djangoImportStart.MatchString(line) ||
				hasDjangoPath && (djangoPathStart.MatchString(line) || djangoI18nStart.MatchString(line) ||
					djangoListAssignmentPattern.MatchString(line))
			if !startsStmt || depth <= 0 {
				scanStmt(line)
				continue
			}
			stmt.WriteString(line)
			continue
		}

		stmt.WriteByte(' ')
		stmt.WriteString(line)
		depth += parenDelta(line)
		if depth <= 0 {
			scanStmt(stmt.String())
			stmt.Reset()
			depth = 0
		}
	}
	if err := scan.Err(); err != nil {
		return err
	}
	for name, list := range djangoLists {
		for _, declaration := range list.routes {
			if err := ctx.Err(); err != nil {
				return err
			}
			declaration.listName = name
			djangoRoutes = append(djangoRoutes, declaration)
		}
	}
	e.djangoRoutes[path] = djangoRoutes
	return ctx.Err()
}

func scanPythonStmt(stmt string, routes map[string]struct{}) {
	scanFastAPI(stmt, routes)
	scanFlask(stmt, routes)
}

// parenDelta returns opening minus closing parentheses and square brackets on a
// line, ignoring quoted text and comments.
func parenDelta(line string) int {
	depth := 0
	var quote byte
	for i := 0; i < len(line); i++ {
		if quote != 0 {
			switch line[i] {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch line[i] {
		case '\'', '"':
			quote = line[i]
		case '#':
			return depth
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		}
	}
	return depth
}

func addPyMatch(routes map[string]struct{}, re *regexp.Regexp, line string) {
	match := re.FindStringSubmatch(line)
	for i := 1; i < len(match); i++ {
		if strings.HasPrefix(match[i], "/") {
			routes[match[i]] = struct{}{}
			return
		}
	}
}
