// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"regexp"
	"strings"
)

var falconImportPattern = regexp.MustCompile(
	`^\s*import\s+falcon(?:\.asgi)?(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*(?:#.*)?$`,
)

var falconPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b` + pyObj + `add_route\s*\(\s*` + pyLit),
}

var falconStart = regexp.MustCompile(
	`\b` + pyObj + `add_route\s*\(`,
)

var falconConverterPattern = regexp.MustCompile(
	`\{([A-Za-z_][A-Za-z0-9_]*):[^{}]*\}`,
)

var falconParameterSegmentPattern = regexp.MustCompile(
	`^\{[A-Za-z_][A-Za-z0-9_]*\}$`,
)

func scanFalcon(line string, routes map[string]struct{}) {
	for _, re := range falconPatterns {
		match := re.FindStringSubmatch(line)
		for i := 1; i < len(match); i++ {
			if len(match[i]) > 0 && match[i][0] == '/' {
				route := falconConverterPattern.ReplaceAllString(match[i], `{$1}`)
				if falconRouteSupported(route) {
					routes[route] = struct{}{}
				}
				break
			}
		}
	}
}

func falconRouteSupported(route string) bool {
	for _, segment := range strings.Split(route, "/") {
		if strings.ContainsAny(segment, "{}") &&
			!falconParameterSegmentPattern.MatchString(segment) {
			return false
		}
	}
	return true
}

func startsFalcon(line string) bool {
	return falconStart.MatchString(line)
}
