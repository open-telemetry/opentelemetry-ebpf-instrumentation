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
	return extractPythonRoutes(ctx, dirs...)
}

// extractPythonRoutes scans the application directory, dirs[0], and then any
// further import roots. The file limit is shared across all of them.
func extractPythonRoutes(ctx context.Context, dirs ...string) (*RouteHarvesterResult, error) {
	log := slog.With("component", "route.harvester.python")
	e := pythonExtractor{
		routes:       map[string]struct{}{},
		djangoRoutes: map[string][]djangoRoute{},
	}
	kind := PartialRoutes
	remaining := maxPythonFiles
	for _, root := range pythonScanRoots(dirs) {
		scanned := 0
		err := walkPythonFilesN(ctx, root.dir, remaining, func(path string) error {
			scanned++
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
			if root.app || ctx.Err() != nil {
				return nil, fmt.Errorf("scan Python directory: %w", err)
			}
			log.Debug("error scanning Python import root", "dir", root.dir, "error", err)
		}
		remaining -= scanned
		if remaining <= 0 {
			break
		}
	}

	if err := resolveDjangoRoutes(ctx, dirs, e.djangoRoutes, e.routes); err != nil {
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

type pythonScanRoot struct {
	dir string
	app bool
}

// pythonScanRoots returns the directories to walk for the application
// directory, dirs[0], and its import roots. Each directory is replaced by the
// outermost one covering it, so no file is scanned twice; the root covering
// the application directory is marked app, and failing to scan it fails the
// harvest. Import roots holding installed packages are left out: their routes
// are not the application's.
func pythonScanRoots(dirs []string) []pythonScanRoot {
	candidates := make([]string, 0, len(dirs))
	for i, dir := range dirs {
		if i == 0 || !pythonDependencyDir(dir) {
			candidates = append(candidates, dir)
		}
	}
	roots := make([]pythonScanRoot, 0, len(candidates))
	for i, dir := range candidates {
		cover := dir
		for _, other := range candidates {
			if len(other) < len(cover) && langtools.PathWithinBoundary(other, dir) {
				cover = other
			}
		}
		if j := slices.IndexFunc(roots, func(root pythonScanRoot) bool { return root.dir == cover }); j >= 0 {
			roots[j].app = roots[j].app || i == 0
			continue
		}
		roots = append(roots, pythonScanRoot{dir: cover, app: i == 0})
	}
	return roots
}

// pythonDependencyDir reports whether an import root holds installed packages:
// an installation directory such as site-packages, or a pip --target
// directory, which has the distributions' .dist-info metadata at its top level.
func pythonDependencyDir(dir string) bool {
	if name := filepath.Base(dir); name == "site-packages" || name == "dist-packages" {
		return true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasSuffix(entry.Name(), ".dist-info") {
			return true
		}
	}
	return false
}

func walkPythonFiles(ctx context.Context, root string, fn func(string) error) error {
	return walkPythonFilesN(ctx, root, maxPythonFiles, fn)
}

func walkPythonFilesN(ctx context.Context, root string, maxFiles int, fn func(string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	files, err := os.ReadDir(root)
	if err != nil {
		return err
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
			if info.IsDir() {
				if skipPythonDir(info.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() || info.Size() > maxPythonFileBytes || filepath.Ext(path) != ".py" {
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
			return err
		}
		if limit {
			break
		}
	}
	return ctx.Err()
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
