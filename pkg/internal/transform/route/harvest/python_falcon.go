// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

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

var falconConverterPattern = regexp.MustCompile(
	`\{([A-Za-z_][A-Za-z0-9_]*):([^{}]*)\}`,
)

var falconParameterSegmentPattern = regexp.MustCompile(
	`^\{[A-Za-z_][A-Za-z0-9_]*(?::path)?\}$`,
)

func scanFalcon(line string, routes map[string]struct{}) bool {
	match := falconStart.FindStringIndex(line)
	if match == nil {
		return false
	}

	openParen := strings.Index(line[match[0]:], "(")
	if openParen < 0 {
		return false
	}
	openParen += match[0]

	args, ok := falconCallArguments(line, openParen)
	if !ok {
		return false
	}

	var route string
	found := false

	// Falcon accepts the URI template as the first positional argument.
	if len(args) > 0 {
		route, found = parseFalconString(args[0])
	}

	// It can also be supplied by a top-level keyword argument.
	if !found {
		for _, arg := range args {
			arg = strings.TrimSpace(arg)
			equal := strings.Index(arg, "=")
			if equal < 0 || strings.TrimSpace(arg[:equal]) != "uri_template" {
				continue
			}

			route, found = parseFalconString(arg[equal+1:])
			if found {
				break
			}
		}
	}

	if !found || !strings.HasPrefix(route, "/") {
		return false
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

	if !falconRouteSupported(route) {
		return false
	}

	routes[route] = struct{}{}
	return true
}

// falconCallArguments returns only the top-level arguments of a Python call.
// Nested calls and commas inside strings do not split arguments.
func falconCallArguments(line string, openParen int) ([]string, bool) {
	var args []string
	start := openParen + 1

	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0
	var quote byte

	for i := openParen + 1; i < len(line); i++ {
		ch := line[i]

		if quote != 0 {
			if ch == '\\' {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}

		switch ch {
		case '\'', '"':
			quote = ch
		case '#':
			return nil, false
		case '(':
			parenDepth++
		case ')':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				args = append(args, strings.TrimSpace(line[start:i]))
				return args, true
			}
			parenDepth--
		case '[':
			bracketDepth++
		case ']':
			bracketDepth--
		case '{':
			braceDepth++
		case '}':
			braceDepth--
		case ',':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				args = append(args, strings.TrimSpace(line[start:i]))
				start = i + 1
			}
		}
	}

	return nil, false
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
			if strings.TrimSpace(input[i+1:]) != "" {
				return "", false
			}
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
	for segment := range strings.SplitSeq(route, "/") {
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
