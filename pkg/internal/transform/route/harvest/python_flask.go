// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import "regexp"

var flaskPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^@` + pyObj + `(?:route|get|post|put|patch|delete)\s*\(\s*` + pyLit),
	regexp.MustCompile(`^@` + pyObj + `(?:route|get|post|put|patch|delete)\s*\([^)]*\brule\s*=\s*` + pyLit),
	regexp.MustCompile(`\b` + pyObj + `add_url_rule\s*\(\s*` + pyLit),
	regexp.MustCompile(`\b` + pyObj + `add_url_rule\s*\([^)]*\brule\s*=\s*` + pyLit),
	regexp.MustCompile(`\b(?:` + pyObj + `)?Blueprint\s*\([^)]*\burl_prefix\s*=\s*` + pyLit),
	regexp.MustCompile(`\b` + pyObj + `register_blueprint\s*\([^)]*\burl_prefix\s*=\s*` + pyLit),
}

func scanFlask(line string, routes map[string]struct{}) {
	for _, re := range flaskPatterns {
		addPyMatch(routes, re, line)
	}
}
