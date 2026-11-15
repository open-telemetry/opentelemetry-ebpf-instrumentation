// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"regexp"
	"strings"
)

var falconImportPattern = regexp.MustCompile(
	`^\s*(?:import\s+falcon(?:\.asgi)?(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?|from\s+falcon(?:\.asgi)?\s+import\b.*)\s*(?:#.*)?$`,
)

var falconStart = regexp.MustCompile(
	`\b` + pyObj + `add_route\s*\(`,
)

var falconURIKeyword = regexp.MustCompile(
	`(?:^|,)\s*uri_template\s*=\s*`,
)

var falconConverterPattern = regexp.MustCompile(
	`\{([A-Za-z_][A-Za-z0-9_]*):([^{}]*)\}`,
)

var falconParameterSegmentPattern = regexp.MustCompile(
	`^\{[A-Za-z_][A-Za-z0-9_]*(?::path)?\}$`,
)

func scanFalcon(line string, routes map[string]struct{}) {
	match := falconStart.FindStringIndex(line)
	if match == nil {
		return
	}

	openParen := strings.Index(line[match[0]:], "(")
	if openParen < 0 {
		return
	}

	args := line[match[0]+openParen+1:]
	args = strings.TrimSpace(args)

	// Falcon accepts the URI template as the first positional argument.
	route, ok := parseFalconString(args)
	if !ok {
		// It can also be supplied by keyword.
		keyword := falconURIKeyword.FindStringIndex(args)
		if keyword == nil {
			return
		}
		route, ok = parseFalconString(args[keyword[1]:])
		if !ok {
			return
		}
	}

	if !strings.HasPrefix(route, "/") {
		return
	}

	route = falconConverterPattern.ReplaceAllStringFunc(route, func(converter string) string {
		parts := falconConverterPattern.FindStringSubmatch(converter)
		if len(parts) != 3 {
			return converter
		}
		if parts[2] == "path" {
			return "{" + parts[1] + ":path}"
		}
		return "{" + parts[1] + "}"
	})

	if falconRouteSupported(route) {
		routes[route] = struct{}{}
	}
}

// parseFalconString reads a simple Python string literal at the start of input.
// It handles escaped quote characters and leaves unsupported expressions alone.
func parseFalconString(input string) (string, bool) {
	input = strings.TrimSpace(input)

	raw := false
	if len(input) > 0 && (input[0] == 'r' || input[0] == 'R' || input[0] == 'u' || input[0] == 'U') {
		raw = input[0] == 'r' || input[0] == 'R'
		input = input[1:]
	}

	if len(input) == 0 || (input[0] != '\'' && input[0] != '"') {
		return "", false
	}

	quote := input[0]
	var value strings.Builder

	for i := 1; i < len(input); i++ {
		ch := input[i]

		if ch == quote {
			return value.String(), true
		}

		if ch == '\\' && i+1 < len(input) {
			next := input[i+1]
			if !raw && (next == quote || next == '\\') {
				value.WriteByte(next)
				i++
				continue
			}
			value.WriteByte(ch)
			continue
		}

		value.WriteByte(ch)
	}

	return "", false
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
