// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type djangoRoute struct {
	path          string
	includeModule string
	admin         bool
}

var djangoAdminRoutes = []string{
	"",
	"login/",
	"logout/",
	"password_change/",
	"password_change/done/",
	"autocomplete/",
	"jsi18n/",
	"r/<path:content_type_id>/<path:object_id>/",
	"<app_label>/",
	"<app_label>/<model_name>/",
	"<app_label>/<model_name>/add/",
	"<app_label>/<model_name>/<path:object_id>/history/",
	"<app_label>/<model_name>/<path:object_id>/delete/",
	"<app_label>/<model_name>/<path:object_id>/change/",
	"<app_label>/<model_name>/<path:object_id>/",
}

var djangoPathImportPattern = regexp.MustCompile(
	`^from\s+django\.urls\s+import\s+(?:\(\s*)?(?:\w+(?:\s+as\s+\w+)?\s*,\s*)*path\s*(?:,|\)|$|#)`,
)

var djangoImportStart = regexp.MustCompile(`^from\s+django\.urls\s+import\s*\(`)

var djangoFromImportAliasPattern = regexp.MustCompile(
	`^from\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+import\s+([A-Za-z_]\w*)\s+as\s+([A-Za-z_]\w*)\s*(?:#.*)?$`,
)

var djangoImportAliasPattern = regexp.MustCompile(
	`^import\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+as\s+([A-Za-z_]\w*)\s*(?:#.*)?$`,
)

var djangoPathStart = regexp.MustCompile(`\bpath\s*\(`)

var djangoI18nStart = regexp.MustCompile(`\bi18n_patterns\s*\(`)

var djangoI18nUnprefixedDefault = regexp.MustCompile(
	`(?:^|,)\s*prefix_default_language\s*=\s*False\s*,?\s*$`,
)

var djangoPathPattern = regexp.MustCompile(
	`\bpath\s*\(\s*(?:route\s*=\s*)?` + pyLit +
		`\s*,\s*(?:view\s*=\s*)?(?:include\s*\(\s*` + pyLit + `|(admin\.site\.urls)\b` +
		`|(include)\s*\(\s*(?:([A-Za-z_]\w*)\s*[,)])?)?`,
)

// djangoCallEnd finds the closing parenthesis for the call starting at open.
// Parentheses inside quoted strings are part of the argument value.
func djangoCallEnd(stmt string, open int) int {
	depth := 0
	var quote byte
	for i := open; i < len(stmt); i++ {
		if quote != 0 {
			if stmt[i] == '\\' {
				i++
			} else if stmt[i] == quote {
				quote = 0
			}
			continue
		}
		switch stmt[i] {
		case '\'', '"':
			quote = stmt[i]
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func scanDjango(stmt string, aliases map[string]string) []djangoRoute {
	if wrapper := djangoI18nStart.FindStringIndex(stmt); wrapper != nil {
		routes := scanDjango(stmt[:wrapper[0]], aliases)
		end := djangoCallEnd(stmt, wrapper[1]-1)
		if end < 0 {
			return routes
		}
		// Prefix only declarations inside the wrapper, including mounts for child modules.
		localized := scanDjango(stmt[wrapper[1]:end], aliases)
		if djangoI18nUnprefixedDefault.MatchString(stmt[wrapper[1]:end]) {
			// The default language also serves these routes without a language prefix.
			routes = append(routes, localized...)
		}
		for i := range localized {
			localized[i].path = "<language>/" + localized[i].path
		}
		routes = append(routes, localized...)
		return append(routes, scanDjango(stmt[end+1:], aliases)...)
	}

	var routes []djangoRoute
	for _, match := range djangoPathPattern.FindAllStringSubmatch(stmt, -1) {
		// The path literal has separate captures for double and single quotes.
		route := match[1]
		if route == "" {
			route = match[2]
		}

		// A literal include, such as include("checkout.urls"), names the module directly.
		includeModule := match[3]
		if includeModule == "" {
			includeModule = match[4]
		}

		// A non-literal include can refer to an imported alias, such as checkout_urls.
		if match[6] != "" {
			includeModule = aliases[match[7]]
			if includeModule == "" {
				// An unresolved include is a mount whose endpoints are unknown.
				continue
			}
		}

		// The resolver expands includes and admin.site.urls; ordinary views are endpoints.
		routes = append(routes, djangoRoute{
			path:          route,
			includeModule: includeModule,
			admin:         match[5] != "",
		})
	}
	return routes
}

// indexDjangoModules maps dotted include targets, such as "checkout.urls", to
// scanned Python files relative to the application root.
func indexDjangoModules(root string, files map[string][]djangoRoute) map[string]string {
	modules := make(map[string]string, len(files))
	for file := range files {
		rel, err := filepath.Rel(root, file)
		if err != nil {
			continue
		}
		module := strings.TrimSuffix(filepath.ToSlash(rel), ".py")
		module = strings.ReplaceAll(module, "/", ".")
		if module == "__init__" {
			continue
		}
		if packageModule, ok := strings.CutSuffix(module, ".__init__"); ok {
			modules[packageModule] = file
			continue
		}
		if _, exists := modules[module]; !exists {
			modules[module] = file
		}
	}
	return modules
}

// djangoRootFiles selects starting points for route expansion. Included files
// contribute routes through their parent prefixes.
func djangoRootFiles(files map[string][]djangoRoute, modules map[string]string) []string {
	included := map[string]struct{}{}
	for _, declarations := range files {
		for _, declaration := range declarations {
			if file, ok := modules[declaration.includeModule]; ok {
				included[file] = struct{}{}
			}
		}
	}

	var roots []string
	for file, declarations := range files {
		if _, ok := included[file]; !ok && len(declarations) > 0 {
			roots = append(roots, file)
		}
	}
	sort.Strings(roots)
	return roots
}

// resolveDjangoRoutes collects endpoint paths from the scanned URL configurations.
func resolveDjangoRoutes(root string, files map[string][]djangoRoute, routes map[string]struct{}) {
	const maxIncludeDepth = 32

	modules := indexDjangoModules(root, files)
	active := map[string]bool{}
	var visit func(file, prefix string)
	visit = func(file, prefix string) {
		if active[file] || len(active) >= maxIncludeDepth {
			return
		}
		// Track the current chain so another mount can visit this file again.
		active[file] = true
		defer delete(active, file)

		for _, declaration := range files[file] {
			if declaration.includeModule != "" {
				if child, ok := modules[declaration.includeModule]; ok {
					visit(child, prefix+declaration.path)
				}
				continue
			}
			if declaration.admin {
				for _, adminRoute := range djangoAdminRoutes {
					routes["/"+prefix+declaration.path+adminRoute] = struct{}{}
				}
				continue
			}
			routes["/"+prefix+declaration.path] = struct{}{}
		}
	}
	for _, file := range djangoRootFiles(files, modules) {
		visit(file, "")
	}
}
