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
	"regexp/syntax"
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

	dir, err := pythontools.AppDirForPID(fi.Pid(), fi.ServiceAttrs().EnvVars)
	if err != nil {
		return nil, err
	}
	return extractPythonRoutes(ctx, dir)
}

func extractPythonRoutes(ctx context.Context, dir string) (*RouteHarvesterResult, error) {
	log := slog.With("component", "route.harvester.python")
	e := pythonExtractor{
		routes:       map[string]struct{}{},
		djangoRoutes: map[string][]djangoRoute{},
	}
	kind := PartialRoutes
	err := walkPythonFiles(ctx, dir, func(path string) error {
		if err := e.scanFile(ctx, path); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Debug("error processing file", "file", path, "error", err)
			return nil
		}
		if len(e.djangoRoutes[path]) > 0 {
			kind = CompleteRoutes
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan Python directory: %w", err)
	}

	if err := resolveDjangoRoutes(ctx, dir, e.djangoRoutes, e.routes); err != nil {
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
			startsStmt := startsFastAPI(line) || startsFlask(line) || startsPyramid(line) ||
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
	scanPyramid(stmt, routes)
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

// pyDelimitedEnd finds the matching delimiter for a call or list starting at open.
// Delimiters inside quoted strings are part of the argument value.
func pyDelimitedEnd(stmt string, open int) int {
	opening, closing := stmt[open], byte(')')
	if opening == '[' {
		closing = ']'
	}
	depth := 0
	var quote byte
	for i := open; i < len(stmt); i++ {
		if quote != 0 {
			switch stmt[i] {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch stmt[i] {
		case '\'', '"':
			quote = stmt[i]
		case opening:
			depth++
		case closing:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// singleSegmentRegexParam reports whether a parameter regex matches one non-empty
// path segment: a character class repeated with + or an exact count, such as [0-9]{4}.
func singleSegmentRegexParam(body *syntax.Regexp) bool {
	// Both + and positive exact counts such as {4} produce non-empty parameters.
	fixedCount := body.Op == syntax.OpRepeat && body.Min > 0 && body.Min == body.Max
	if (body.Op != syntax.OpPlus && !fixedCount) || body.Sub[0].Op != syntax.OpCharClass {
		return false
	}
	class := body.Sub[0]
	// Rune stores inclusive [low, high] pairs. A single-segment parameter
	// requires every range to exclude the path separator.
	for i := 0; i < len(class.Rune); i += 2 {
		if class.Rune[i] <= '/' && '/' <= class.Rune[i+1] {
			return false
		}
	}
	return true
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
