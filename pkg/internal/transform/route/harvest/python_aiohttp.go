// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"regexp"
	"strings"
)

const (
	aiohttpMethodNames = `get|post|put|patch|delete|head|options|view`
	aiohttpMethods     = `(?:` + aiohttpMethodNames + `)`
	aiohttpName        = `([A-Za-z_][A-Za-z0-9_]*)`
	// aiohttpMethodArg matches the method argument of route()/add_route(),
	// e.g. "GET" or hdrs.METH_GET.
	aiohttpMethodArg = `[^,()]+,\s*`
)

var aiohttpImportPattern = regexp.MustCompile(`^(?:from\s+aiohttp(?:\.web)?\s+import\b|import\s+aiohttp\b)`)

var aiohttpTablePattern = regexp.MustCompile(`^` + aiohttpName + `\s*=\s*(?:` + pyObj + `)?RouteTableDef\s*\(\s*\)`)

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
var aiohttpRegexParam = regexp.MustCompile(`\{` + aiohttpName + `:[^{}]*(?:\{[^{}]*\}[^{}]*)*\}`)

// aiohttpFile tracks the aiohttp state of a single Python file.
type aiohttpFile struct {
	imported bool
	tables   map[string]struct{}
}

// scan records the aiohttp routes declared by stmt. It returns true when stmt
// is a route table decorator, which other Python scanners must not handle.
func (f *aiohttpFile) scan(stmt string, routes map[string]struct{}) bool {
	if aiohttpImportPattern.MatchString(stmt) {
		f.imported = true
		return false
	}
	if !f.imported {
		return false
	}

	if match := aiohttpTablePattern.FindStringSubmatch(stmt); match != nil {
		if f.tables == nil {
			f.tables = map[string]struct{}{}
		}
		f.tables[match[1]] = struct{}{}
		return false
	}

	if f.isTableDecorator(stmt) {
		for _, re := range aiohttpDecoratorPatterns {
			addAiohttpMatches(routes, re, stmt)
		}
		return true
	}

	for _, re := range aiohttpPatterns {
		addAiohttpMatches(routes, re, stmt)
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
	return f.imported && aiohttpStart.MatchString(line)
}

// addAiohttpMatches adds every route matched by re, since a single add_routes
// statement can declare several routes.
func addAiohttpMatches(routes map[string]struct{}, re *regexp.Regexp, stmt string) {
	for _, match := range re.FindAllStringSubmatch(stmt, -1) {
		for _, group := range match[1:] {
			if strings.HasPrefix(group, "/") {
				routes[aiohttpRegexParam.ReplaceAllString(group, "{$1}")] = struct{}{}
				break
			}
		}
	}
}
