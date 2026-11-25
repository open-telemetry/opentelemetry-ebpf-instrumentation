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
	// aiohttpAnnotation matches an optional type annotation in an
	// assignment, e.g. "routes: web.RouteTableDef = ...".
	aiohttpAnnotation = `(?:\s*:[^=]+)?`
	// aiohttpMethodArg matches the method argument of route()/add_route(),
	// e.g. "GET", "*" or hdrs.METH_GET. It cannot be a path, so Flask's
	// route("/path", ...) is not taken for aiohttp's route(method, path).
	aiohttpMethodArg = `(?:[rRuU]?(?:"[^"/]*"|'[^'/]*')|[A-Za-z_][\w.]*)\s*,\s*`
	// aiohttpPathArg matches a path literal that is a whole argument, so a
	// partial path such as "/users/" + user_id or "/users/%s" % user_id is
	// not recorded as a route.
	aiohttpPathArg = pyLit + `\s*[,)]`
	// aiohttpTailConverter ends the parameters that match the rest of the path.
	aiohttpTailConverter = ":path}"
)

// aiohttpDependencyPattern matches aiohttp, but not packages such as
// aiohttp-jinja2, as a requirement line (aiohttp>=3.9), a TOML key
// (aiohttp = "^3.9") or a quoted dependency ("aiohttp>=3.9").
var aiohttpDependencyPattern = regexp.MustCompile(`(?im)(?:^[ \t]*|["'])aiohttp[ \t]*(?:[\[<>=!~;@#"']|\r?$)`)

var aiohttpImportPattern = regexp.MustCompile(`^(?:from\s+aiohttp(?:\.web)?\s+import\b|import\s+aiohttp\b)`)

// aiohttpImportStart matches the first line of a parenthesized aiohttp
// import, which is buffered so the names on the following lines are seen.
var aiohttpImportStart = regexp.MustCompile(`^from\s+aiohttp(?:\.web)?\s+import\s*\(`)

// aiohttpWebImportPattern matches imports binding the name web to aiohttp's
// web module, e.g. "from aiohttp import hdrs, web". web must be an imported
// name itself: "web as aioweb" does not bind web, and "ClientSession as web"
// binds it to something else.
var aiohttpWebImportPattern = regexp.MustCompile(`^(?:from\s+aiohttp\s+import\s*(?:\(?\s*|.*[(,]\s*)web\s*(?:[,)]|$)|import\s+aiohttp\.web\s+as\s+web\b)`)

// aiohttpWebName is the name route definitions use for aiohttp's web module.
const aiohttpWebName = "web"

// aiohttpWebWithPattern matches a with statement rebinding web, e.g.
// "async with ClientSession() as web:".
var aiohttpWebWithPattern = regexp.MustCompile(`^(?:async\s+)?with\b.*\bas\s+` + aiohttpWebName + `\s*[,:)]`)

// aiohttpTablePattern does not require the closing parenthesis, so the first
// line of a multi-line RouteTableDef( call is enough.
var aiohttpTablePattern = regexp.MustCompile(`^` + aiohttpName + aiohttpAnnotation + `\s*=\s*(?:` + pyObj + `)?RouteTableDef\s*\(`)

var aiohttpAssignmentPattern = regexp.MustCompile(`^` + aiohttpName + aiohttpAnnotation + `\s*=[^=]`)

// aiohttpDecoratorPattern matches decorators shaped like a route table's,
// @routes.get( or @routes.route(method, ...). Flask's @routes.route("/path")
// on a reused name is left to the Flask scanner.
var aiohttpDecoratorPattern = regexp.MustCompile(`^@` + aiohttpName + `\.(?:` + aiohttpMethods + `\s*\(|route\s*\(\s*` + aiohttpMethodArg + `)`)

// The patterns below only read the path from the first positional argument
// (or the second, after the method). Keyword paths are left out: a path=
// argument can also belong to a nested call, such as a functools.partial
// handler, and would then be recorded as a route that does not exist.

// aiohttpRouterPatterns cover router calls (app.router.add_get). The
// receiver must be a router, since other libraries also have add_view or
// add_route methods.
var aiohttpRouterPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\brouter\.add_` + aiohttpMethods + `\s*\(\s*` + aiohttpPathArg),
	regexp.MustCompile(`\brouter\.add_route\s*\(\s*` + aiohttpMethodArg + aiohttpPathArg),
}

// aiohttpModulePatterns cover route definitions through the module path
// (aiohttp.web.get).
var aiohttpModulePatterns = aiohttpDefinitionPatterns(`\baiohttp\.web\.`)

// aiohttpWebPatterns cover route definitions through the web name (web.get).
// They only apply to files importing web from aiohttp, since a client or any
// other object can also be named web.
var aiohttpWebPatterns = aiohttpDefinitionPatterns(`(?:^|[^.\w])web\.`)

// aiohttpDecoratorPatterns cover route table decorators (@routes.get). They
// only apply to names assigned from RouteTableDef.
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

// dependsOnAiohttp reports whether the dependency manifests closest to dir,
// looking no further up than root, list aiohttp. Route modules often call
// app.router.add_get without importing aiohttp, and an application started
// from a subdirectory (python src/main.py) keeps its manifests in a parent.
func dependsOnAiohttp(ctx context.Context, root, dir string) (bool, error) {
	depends := false
	err := langtools.WalkParentDirectories(dir, root, func(dir string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		found, listed := manifestsListAiohttp(dir)
		depends = listed
		// The nearest manifests describe the application: stop there.
		return found, nil
	})
	return depends, err
}

// manifestsListAiohttp reports whether dir holds any dependency manifest, and
// whether one of them lists aiohttp.
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
	// Lock files are left out: they also list transitive dependencies, so
	// aiohttp used only as an HTTP client would enable the scan.
	switch name {
	case "pyproject.toml", "Pipfile":
		return true
	}
	return strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")
}

// aiohttpFile tracks the aiohttp state of a single Python file. It is enabled
// when the project depends on aiohttp or the file imports it.
type aiohttpFile struct {
	enabled     bool
	webImported bool
	tables      map[string]struct{}
}

// scan records the aiohttp routes declared by stmt. It returns true when stmt
// is an aiohttp decorator of a route table, which other Python scanners must
// not handle even when no route is recorded: they would keep a partial path
// such as "/users/" + suffix.
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
	// A client bound to web, as in "async with ClientSession() as web:", would
	// turn its requests into routes.
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

// addAiohttpRoutes adds every route matched by patterns, since a single
// add_routes statement can declare several routes.
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

// aiohttpTemplate drops the regex of {name:regex} parameters, like aiohttp's
// canonical path, except for tail regexes, which keep the path converter. It
// returns false when a tail parameter is not the last one: the partial route
// matcher discards such routes.
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
