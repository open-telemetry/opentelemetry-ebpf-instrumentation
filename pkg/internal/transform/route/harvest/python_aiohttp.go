// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"context"
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
	aiohttpAnnotation  = `(?:\s*:[^=]+)?`
	// A method argument is never a path, so Flask's route("/path") is not read as route(method, path).
	aiohttpMethodArg = `(?:[rRuU]?(?:"[^"/]*"|'[^'/]*')|[A-Za-z_][\w.]*)\s*,\s*`
	// A path must be a whole argument, so "/users/" + user_id is not a route.
	aiohttpPathArg       = pyLit + `\s*[,)]`
	aiohttpTailConverter = ":path}"
)

// aiohttpDependencyPattern matches aiohttp but not packages such as aiohttp-jinja2.
var aiohttpDependencyPattern = regexp.MustCompile(`(?im)(?:^[ \t]*|["'])aiohttp[ \t]*(?:[\[<>=!~;@#"']|\r?$)`)

var aiohttpImportPattern = regexp.MustCompile(`^(?:from\s+aiohttp(?:\.web)?\s+import\b|import\s+aiohttp\b)`)

var aiohttpImportStart = regexp.MustCompile(`^from\s+aiohttp(?:\.web)?\s+import\s*\(`)

// "web as aioweb" and "ClientSession as web" do not bind web to aiohttp's module.
var aiohttpWebImportPattern = regexp.MustCompile(`^(?:from\s+aiohttp\s+import\s*(?:\(?\s*|.*[(,]\s*)web\s*(?:[,)]|$)|import\s+aiohttp\.web\s+as\s+web\b)`)

const aiohttpWebName = "web"

var aiohttpWebWithPattern = regexp.MustCompile(`^(?:async\s+)?with\b.*\bas\s+` + aiohttpWebName + `\s*[,:)]`)

// No closing parenthesis, so the first line of a multi-line RouteTableDef( call is enough.
var aiohttpTablePattern = regexp.MustCompile(`^` + aiohttpName + aiohttpAnnotation + `\s*=\s*(?:` + pyObj + `)?RouteTableDef\s*\(`)

var aiohttpAssignmentPattern = regexp.MustCompile(`^` + aiohttpName + aiohttpAnnotation + `\s*=[^=]`)

var aiohttpDecoratorPattern = regexp.MustCompile(`^@` + aiohttpName + `\.(?:` + aiohttpMethods + `\s*\(|route\s*\(\s*` + aiohttpMethodArg + `)`)

// Keyword paths are not read: path= can belong to a nested call, such as a functools.partial handler.
// Other libraries also have add_view or add_route methods, so the receiver must be a router.
var aiohttpRouterPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\brouter\.add_` + aiohttpMethods + `\s*\(\s*` + aiohttpPathArg),
	regexp.MustCompile(`\brouter\.add_route\s*\(\s*` + aiohttpMethodArg + aiohttpPathArg),
}

var aiohttpModulePatterns = aiohttpDefinitionPatterns(`\baiohttp\.web\.`)

var aiohttpWebPatterns = aiohttpDefinitionPatterns(`(?:^|[^.\w])web\.`)

var aiohttpDecoratorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^@` + aiohttpName + `\.` + aiohttpMethods + `\s*\(\s*` + aiohttpPathArg),
	regexp.MustCompile(`^@` + aiohttpName + `\.route\s*\(\s*` + aiohttpMethodArg + aiohttpPathArg),
}

func aiohttpDefinitionPatterns(receiver string) []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(receiver + aiohttpMethods + `\s*\(\s*` + aiohttpPathArg),
		regexp.MustCompile(receiver + `route\s*\(\s*` + aiohttpMethodArg + aiohttpPathArg),
	}
}

var aiohttpStart = regexp.MustCompile(
	`(?:^@` + pyObj + `(?:` + aiohttpMethodNames + `|route)|\b` +
		pyObj + `add_(?:` + aiohttpMethodNames + `|routes?)|\bweb\.(?:` + aiohttpMethodNames + `|route))\s*\(`,
)

// aiohttpRegexParam allows one level of nested braces, like aiohttp does: {year:\d{4}}.
var aiohttpRegexParam = regexp.MustCompile(`\{` + aiohttpName + `:([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}`)

var aiohttpTailRegexes = map[string]struct{}{
	".*": {},
	".+": {},
}

// dependsOnAiohttp reports whether the manifests nearest to dir, up to root, list aiohttp.
func dependsOnAiohttp(ctx context.Context, root, dir string) (bool, error) {
	depends := false
	err := langtools.WalkParentDirectories(dir, root, func(dir string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		found, listed := manifestsListAiohttp(dir)
		depends = listed
		return found, nil
	})
	return depends, err
}

func manifestsListAiohttp(dir string) (found, listed bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, false
	}

	for _, entry := range entries {
		if entry.IsDir() || !isPythonManifest(entry.Name()) {
			continue
		}
		found = true
		data, _, err := langtools.ReadMetadataFile(filepath.Join(dir, entry.Name()), maxPythonManifestBytes)
		if err == nil && aiohttpDependencyPattern.Match(data) {
			return true, true
		}
	}
	return found, false
}

func isPythonManifest(name string) bool {
	// Lock files are left out: they also list transitive dependencies.
	switch name {
	case "pyproject.toml", "Pipfile":
		return true
	}
	return strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")
}

type aiohttpFile struct {
	enabled     bool
	webImported bool
	tables      map[string]struct{}
}

// scan returns true for route table decorators, which other Python scanners must skip.
func (f *aiohttpFile) scan(stmt string, routes map[string]struct{}) bool {
	if aiohttpWebImportPattern.MatchString(stmt) {
		f.webImported = true
	}
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
		if match[1] == aiohttpWebName {
			f.webImported = false
		}
	}
	if aiohttpWebWithPattern.MatchString(stmt) {
		f.webImported = false
	}

	if f.isTableDecorator(stmt) {
		addAiohttpRoutes(routes, aiohttpDecoratorPatterns, stmt)
		return true
	}
	addAiohttpRoutes(routes, aiohttpRouterPatterns, stmt)
	addAiohttpRoutes(routes, aiohttpModulePatterns, stmt)
	if f.webImported {
		addAiohttpRoutes(routes, aiohttpWebPatterns, stmt)
	}
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
	if aiohttpImportStart.MatchString(line) {
		return true
	}
	return f.enabled && aiohttpStart.MatchString(line)
}

func addAiohttpRoutes(routes map[string]struct{}, patterns []*regexp.Regexp, stmt string) {
	for _, re := range patterns {
		for _, match := range re.FindAllStringSubmatch(stmt, -1) {
			for _, group := range match[1:] {
				if !strings.HasPrefix(group, "/") {
					continue
				}
				if route, ok := aiohttpTemplate(group); ok {
					routes[route] = struct{}{}
				}
				break
			}
		}
	}
}

// aiohttpTemplate returns false when a catch-all is not the last parameter: the partial matcher discards it.
func aiohttpTemplate(path string) (string, bool) {
	route := aiohttpRegexParam.ReplaceAllStringFunc(path, func(param string) string {
		match := aiohttpRegexParam.FindStringSubmatch(param)
		if _, ok := aiohttpTailRegexes[match[2]]; ok {
			return "{" + match[1] + aiohttpTailConverter
		}
		return "{" + match[1] + "}"
	})

	tail := strings.Index(route, aiohttpTailConverter)
	return route, tail < 0 || tail == len(route)-len(aiohttpTailConverter)
}
