// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"regexp"
	"strings"
)

const pyArgEnd = `\s*[,)]`

const maxPyramidRegexBraceDepth = 1

// add_route(name, pattern) or add_route(..., pattern=...).
var pyramidPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b` + pyObj + `add_route\s*\(\s*` + pyLit + `\s*,\s*` + pyLit + pyArgEnd),
	regexp.MustCompile(`\b` + pyObj + `add_route\s*\([^()]*\bpattern\s*=\s*` + pyLit + pyArgEnd),
}

var pyramidStart = regexp.MustCompile(`\b` + pyObj + `add_route\s*\(`)

var (
	pyramidNamePattern      = regexp.MustCompile(`^[A-Za-z_]\w*$`)
	pyramidRemainderPattern = regexp.MustCompile(`^\*\w*$`)
)

func startsPyramid(line string) bool {
	return pyramidStart.MatchString(line)
}

func scanPyramid(stmt string, routes map[string]struct{}) {
	for _, re := range pyramidPatterns {
		match := re.FindStringSubmatch(stmt)
		if match == nil {
			continue
		}
		// pattern is the last pyLit, which has two groups.
		pattern := match[len(match)-2] + match[len(match)-1]
		if route, ok := pyramidRoute(pattern); ok {
			routes[route] = struct{}{}
		}
	}
}

// pyramidRoute converts a Pyramid pattern to matcher syntax, rejecting what it can't express.
func pyramidRoute(pattern string) (string, bool) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}

	segments := strings.Split(pattern, "/")
	last := len(segments) - 1
	for i, segment := range segments {
		if i == last && pyramidRemainderPattern.MatchString(segment) {
			segments[i] = "*"
			continue
		}
		if !strings.ContainsAny(segment, "{}*") {
			if strings.ContainsAny(segment, ":<>") {
				return "", false
			}
			continue
		}
		name, ok := pyramidParamName(segment)
		if !ok {
			return "", false
		}
		segments[i] = "{" + name + "}"
	}
	return strings.Join(segments, "/"), true
}

func pyramidParamName(segment string) (string, bool) {
	if !strings.HasPrefix(segment, "{") || !strings.HasSuffix(segment, "}") {
		return "", false
	}
	inner := segment[1 : len(segment)-1]
	name, regex, hasRegex := strings.Cut(inner, ":")
	if !pyramidNamePattern.MatchString(name) || !balancedPyramidRegex(regex) {
		return "", false
	}
	if hasRegex && pyramidRegexMayMatchSlash(regex) {
		return "", false
	}
	return name, true
}

func balancedPyramidRegex(regex string) bool {
	depth := 0
	for _, c := range regex {
		switch c {
		case '{':
			depth++
		case '}':
			depth--
		}
		if depth < 0 || depth > maxPyramidRegexBraceDepth {
			return false
		}
	}
	return depth == 0
}

func pyramidRegexMayMatchSlash(regex string) bool {
	return strings.Contains(regex, ".") || strings.Contains(regex, "[^") ||
		strings.Contains(regex, `\S`) || strings.Contains(regex, `\W`) || strings.Contains(regex, `\D`)
}
