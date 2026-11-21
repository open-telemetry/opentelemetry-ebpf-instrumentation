// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxPythonManifestBytes int64 = 2 * 1024 * 1024

	aiohttpMethodNames = `get|post|put|patch|delete|head|options|view`
	aiohttpMethods     = `(?:` + aiohttpMethodNames + `)`
	aiohttpName        = `([A-Za-z_][A-Za-z0-9_]*)`
	// aiohttpMethodArg matches the method argument of route()/add_route(),
	// e.g. "GET" or hdrs.METH_GET.
	aiohttpMethodArg = `[^,()]+,\s*`
)

// aiohttpDependencyPattern matches aiohttp, but not packages such as
// aiohttp-jinja2, as a requirement line (aiohttp>=3.9), a TOML key
// (aiohttp = "^3.9") or a quoted name ("aiohttp>=3.9", name = "aiohttp").
var aiohttpDependencyPattern = regexp.MustCompile(`(?im)(?:^[ \t]*|["'])aiohttp[ \t]*(?:[\[<>=!~;@#"']|\r?$)`)

var aiohttpImportPattern = regexp.MustCompile(`^(?:from\s+aiohttp(?:\.web)?\s+import\b|import\s+aiohttp\b)`)

// aiohttpTablePattern does not require the closing parenthesis, so the first
// line of a multi-line RouteTableDef( call is enough.
var aiohttpTablePattern = regexp.MustCompile(`^` + aiohttpName + `\s*=\s*(?:` + pyObj + `)?RouteTableDef\s*\(`)

var aiohttpAssignmentPattern = regexp.MustCompile(`^` + aiohttpName + `\s*=[^=]`)

var aiohttpDecoratorPattern = regexp.MustCompile(`^@` + aiohttpName + `\.`)

// aiohttpPatterns cover router calls (app.router.add_get) and route
// definitions (web.get).
var aiohttpPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b` + pyObj + `add_` + aiohttpMethods + `\s*\(\s*` + pyLit),
	regexp.MustCompile(`\b` + pyObj + `add_` + aiohttpMethods + `\s*\([^)]*\bpath\s*=\s*` + pyLit),
	regexp.MustCompile(`\b` + pyObj + `add_route\s*\(\s*` + aiohttpMethodArg + pyLit),
	regexp.MustCompile(`\b` + pyObj + `add_route\s*\([^)]*\bpath\s*=\s*` + pyLit),
	regexp.MustCompile(`\bweb\.` + aiohttpMethods + `\s*\(\s*` + pyLit),
	regexp.MustCompile(`\bweb\.` + aiohttpMethods + `\s*\([^)]*\bpath\s*=\s*` + pyLit),
	regexp.MustCompile(`\bweb\.route\s*\(\s*` + aiohttpMethodArg + pyLit),
	regexp.MustCompile(`\bweb\.route\s*\([^)]*\bpath\s*=\s*` + pyLit),
}

// aiohttpDecoratorPatterns cover route table decorators (@routes.get). They
// only apply to names assigned from RouteTableDef.
var aiohttpDecoratorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^@` + aiohttpName + `\.` + aiohttpMethods + `\s*\(\s*` + pyLit),
	regexp.MustCompile(`^@` + aiohttpName + `\.` + aiohttpMethods + `\s*\([^)]*\bpath\s*=\s*` + pyLit),
	regexp.MustCompile(`^@` + aiohttpName + `\.route\s*\(\s*` + aiohttpMethodArg + pyLit),
	regexp.MustCompile(`^@` + aiohttpName + `\.route\s*\([^)]*\bpath\s*=\s*` + pyLit),
}

var aiohttpStart = regexp.MustCompile(
	`(?:^@` + pyObj + `(?:` + aiohttpMethodNames + `|route)|\b` +
		pyObj + `add_(?:` + aiohttpMethodNames + `|routes?)|\bweb\.(?:` + aiohttpMethodNames + `|route))\s*\(`,
)

// aiohttpRegexParam matches {name:regex} placeholders, allowing one level of
// nested braces in the regex like aiohttp does, e.g. {year:\d{4}}.
var aiohttpRegexParam = regexp.MustCompile(`\{` + aiohttpName + `:([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}`)

// aiohttpTailRegexes match the rest of the path, e.g. {tail:.*}. They are
// reported with the path converter, which the route matcher lets span several
// segments.
var aiohttpTailRegexes = map[string]struct{}{
	".*": {},
	".+": {},
}

// dependsOnAiohttp reports whether a dependency manifest in dir lists aiohttp.
// Route modules often call app.router.add_get without importing aiohttp.
func dependsOnAiohttp(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() || !isPythonManifest(entry.Name()) {
			continue
		}
		data, _, err := langtools.ReadMetadataFile(filepath.Join(dir, entry.Name()), maxPythonManifestBytes)
		if err == nil && aiohttpDependencyPattern.Match(data) {
			return true
		}
	}
	return false
}

func isPythonManifest(name string) bool {
	switch name {
	case "pyproject.toml", "Pipfile", "poetry.lock":
		return true
	}
	return strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")
}

// aiohttpFile tracks the aiohttp state of a single Python file. It is enabled
// when the project depends on aiohttp or the file imports it.
type aiohttpFile struct {
	enabled bool
	tables  map[string]struct{}
}

// scan records the aiohttp routes declared by stmt. It returns true when stmt
// is a route table decorator whose route it recorded, which other Python
// scanners must not handle.
func (f *aiohttpFile) scan(stmt string, routes map[string]struct{}) bool {
	if aiohttpImportPattern.MatchString(stmt) {
		f.enabled = true
		return false
	}
	if !f.enabled {
		return false
	}

	if match := aiohttpTablePattern.FindStringSubmatch(stmt); match != nil {
		if f.tables == nil {
			f.tables = map[string]struct{}{}
		}
		f.tables[match[1]] = struct{}{}
		return false
	}
	if match := aiohttpAssignmentPattern.FindStringSubmatch(stmt); match != nil {
		delete(f.tables, match[1])
	}

	if f.isTableDecorator(stmt) {
		return addAiohttpRoutes(routes, aiohttpDecoratorPatterns, stmt)
	}
	addAiohttpRoutes(routes, aiohttpPatterns, stmt)
	return false
}

func (f *aiohttpFile) isTableDecorator(stmt string) bool {
	match := aiohttpDecoratorPattern.FindStringSubmatch(stmt)
	if match == nil {
		return false
	}
	_, ok := f.tables[match[1]]
	return ok
}

func (f *aiohttpFile) starts(line string) bool {
	return f.enabled && aiohttpStart.MatchString(line)
}

// addAiohttpRoutes adds every route matched by patterns, since a single
// add_routes statement can declare several routes. It reports whether any
// route was added.
func addAiohttpRoutes(routes map[string]struct{}, patterns []*regexp.Regexp, stmt string) bool {
	added := false
	for _, re := range patterns {
		for _, match := range re.FindAllStringSubmatch(stmt, -1) {
			for _, group := range match[1:] {
				if strings.HasPrefix(group, "/") {
					routes[aiohttpTemplate(group)] = struct{}{}
					added = true
					break
				}
			}
		}
	}
	return added
}

// aiohttpTemplate drops the regex of {name:regex} parameters, like aiohttp's
// canonical path, except for tail regexes, which keep the path converter.
func aiohttpTemplate(path string) string {
	return aiohttpRegexParam.ReplaceAllStringFunc(path, func(param string) string {
		match := aiohttpRegexParam.FindStringSubmatch(param)
		if _, ok := aiohttpTailRegexes[match[2]]; ok {
			return "{" + match[1] + ":path}"
		}
		return "{" + match[1] + "}"
	})
}
