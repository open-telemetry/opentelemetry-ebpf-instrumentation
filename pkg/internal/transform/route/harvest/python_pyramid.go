// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

const pyramidCatchAll = "/*"

// Pyramid's signature is add_route(name, pattern=None, ...).
const pyramidPatternPosition = 2

var pyramidStart = regexp.MustCompile(`\b` + pyObj + `add_route\s*\(`)

var (
	pyramidNamePattern      = regexp.MustCompile(`^[A-Za-z_]\w*$`)
	pyramidRemainderPattern = regexp.MustCompile(`^\*\w*$`)
	// RFC 3986 path characters except ':', which the route matcher reads as a placeholder.
	pyramidLiteralSegment = regexp.MustCompile(`^[A-Za-z0-9._~%!$&'()+,;=@-]*$`)
	pyFullLiteral         = regexp.MustCompile(`^([rRuU]?)(?:"([^"\r\n]*)"|'([^'\r\n]*)')$`)
	// Escapes Python decodes in non-raw strings; others such as \d are kept as written.
	pyDecodedEscape     = regexp.MustCompile(`\\[\\'"abfnrtvxNuU0-7]`)
	pyKeywordArgPattern = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=(.*)$`)
)

func startsPyramid(line string) bool {
	return pyramidStart.MatchString(line)
}

func scanPyramid(stmt string, routes map[string]struct{}) {
	for _, call := range pyramidStart.FindAllStringIndex(stmt, -1) {
		if !pyInCode(stmt, call[0]) {
			continue
		}
		open := call[1] - 1
		end := pyDelimitedEnd(stmt, open)
		if end < 0 {
			continue
		}
		args, ok := pyTopLevelArgs(stmt[open+1 : end])
		if !ok {
			continue
		}
		pattern, ok := pyramidPattern(args)
		if !ok {
			continue
		}
		if route, ok := pyramidRoute(pattern); ok {
			routes[route] = struct{}{}
		}
	}
}

// pyInCode reports whether pos is outside quoted text and comments.
func pyInCode(stmt string, pos int) bool {
	var quote byte
	for i := 0; i < pos; i++ {
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
		case '#':
			return false
		}
	}
	return quote == 0
}

// pyramidPattern returns the pattern argument only when it is a single string literal.
func pyramidPattern(args []string) (string, bool) {
	var value string
	found := false
	positional := 0
	for _, arg := range args {
		if arg == "" {
			continue
		}
		// *args and **kwargs could supply the pattern.
		if strings.HasPrefix(arg, "*") {
			return "", false
		}
		key, keywordValue, isKeyword := pyKeywordArg(arg)
		// Static routes only generate URLs and never match requests.
		if isKeyword && key == "static" && keywordValue != "False" {
			return "", false
		}
		if isKeyword {
			if key != "pattern" {
				continue
			}
			arg = keywordValue
		} else {
			positional++
			if positional != pyramidPatternPosition {
				continue
			}
		}
		if found {
			return "", false
		}
		value, found = arg, true
	}
	if !found {
		return "", false
	}
	return pyStringLiteral(value)
}

// pyramidRoute converts a Pyramid pattern to matcher syntax, rejecting what it can't express.
func pyramidRoute(pattern string) (string, bool) {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}

	segments := pyramidSegments(pattern)
	last := len(segments) - 1
	for i, segment := range segments {
		if i == last && pyramidRemainderPattern.MatchString(segment) {
			segments[i] = "*"
			continue
		}
		if pyramidLiteralSegment.MatchString(segment) {
			continue
		}
		name, ok := pyramidParamName(segment)
		if !ok {
			return "", false
		}
		segments[i] = "{" + name + "}"
	}
	route := strings.Join(segments, "/")
	if route == pyramidCatchAll {
		return "", false
	}
	return route, true
}

// pyramidSegments splits a pattern at '/' outside placeholders, so {name:[^/]+} stays whole.
func pyramidSegments(pattern string) []string {
	var segments []string
	depth, start := 0, 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '{':
			depth++
		case '}':
			depth--
		case '/':
			if depth == 0 {
				segments = append(segments, pattern[start:i])
				start = i + 1
			}
		}
	}
	return append(segments, pattern[start:])
}

func pyramidParamName(segment string) (string, bool) {
	if !strings.HasPrefix(segment, "{") || !strings.HasSuffix(segment, "}") {
		return "", false
	}
	inner := segment[1 : len(segment)-1]
	name, regex, hasRegex := strings.Cut(inner, ":")
	if !pyramidNamePattern.MatchString(name) {
		return "", false
	}
	if !hasRegex {
		return name, true
	}
	expr, err := syntax.Parse(regex, syntax.Perl)
	if err != nil || !pythonSegmentPattern(expr) {
		return "", false
	}
	return name, true
}

// pyTopLevelArgs splits call arguments at commas outside quotes and brackets.
// It returns false when the arguments hold a comment, which joined lines leave in place.
func pyTopLevelArgs(args string) ([]string, bool) {
	var parts []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(args); i++ {
		if quote != 0 {
			switch args[i] {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch args[i] {
		case '\'', '"':
			quote = args[i]
		case '#':
			return nil, false
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(args[start:i]))
				start = i + 1
			}
		}
	}
	return append(parts, strings.TrimSpace(args[start:])), true
}

// pyStringLiteral returns the value of an argument that is exactly one string literal.
func pyStringLiteral(arg string) (string, bool) {
	match := pyFullLiteral.FindStringSubmatch(arg)
	if match == nil {
		return "", false
	}
	value := match[2] + match[3]
	// The source text differs from the runtime value when Python decodes an escape.
	raw := strings.EqualFold(match[1], "r")
	if !raw && pyDecodedEscape.MatchString(value) {
		return "", false
	}
	return value, true
}

// pyKeywordArg splits a name=value argument; comparisons such as a == b are not keywords.
func pyKeywordArg(arg string) (string, string, bool) {
	match := pyKeywordArgPattern.FindStringSubmatch(arg)
	if match == nil || strings.HasPrefix(match[2], "=") {
		return "", "", false
	}
	return match[1], strings.TrimSpace(match[2]), true
}
