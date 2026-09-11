// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"regexp"
	"strings"
)

func (e *RouteExtractor) recordStringDeclaration(line string) {
	m := e.patterns.ConstDeclaration.FindStringSubmatchIndex(line)
	if m == nil {
		return
	}
	name := line[m[2]:m[3]]

	if _, exists := e.jsConsts[name]; exists {
		e.jsConsts[name] = ""
		return
	}
	if len(e.jsConsts) >= maxJSStringConsts {
		return
	}

	e.jsConsts[name] = constStringValue(line[m[1]:])
}

func constStringValue(initializer string) string {
	if initializer == "" || !isJSQuote(initializer[0]) {
		return ""
	}

	end := endOfJSString(initializer, 0)
	if end >= len(initializer) {
		return ""
	}

	rest := strings.TrimSpace(initializer[end+1:])
	rest = strings.TrimSpace(strings.TrimPrefix(rest, ";"))
	if !isJSTrailingComment(rest) {
		return ""
	}

	return jsStringLiteral(initializer[:end+1])
}

func isJSTrailingComment(s string) bool {
	if s == "" || strings.HasPrefix(s, "//") {
		return true
	}
	if !strings.HasPrefix(s, "/*") {
		return false
	}
	return strings.HasSuffix(s, "*/") && len(s) >= len("/**/")
}

func (e *RouteExtractor) resolveRouteCall(line string, call *regexp.Regexp) (method, path string) {
	m := call.FindStringSubmatchIndex(line)
	if m == nil {
		return "", ""
	}

	if len(m) > 2 && m[2] >= 0 {
		method = line[m[2]:m[3]]
	}

	arg, complete := firstJSArgument(line[m[1]:])
	if !complete {
		return method, ""
	}

	return method, e.resolveJSExpression(arg)
}

func firstJSArgument(rest string) (arg string, complete bool) {
	depth := 0
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '\'', '"', '`':
			i = endOfJSString(rest, i)
		case '(', '[', '{':
			depth++
		case ']', '}':
			depth--
		case ')':
			if depth == 0 {
				return strings.TrimSpace(rest[:i]), true
			}
			depth--
		case ',':
			if depth == 0 {
				return strings.TrimSpace(rest[:i]), true
			}
		}
	}

	return strings.TrimSpace(rest), false
}

func (e *RouteExtractor) resolveJSExpression(expr string) string {
	var path strings.Builder
	for _, operand := range splitJSConcat(expr) {
		value := e.resolveJSOperand(operand)
		if value == "" {
			return ""
		}
		path.WriteString(value)
	}

	return path.String()
}

func splitJSConcat(expr string) []string {
	var (
		operands []string
		depth    int
		start    int
	)

	for i := 0; i < len(expr); i++ {
		switch expr[i] {
		case '\'', '"', '`':
			i = endOfJSString(expr, i)
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
		case '+':
			if depth == 0 {
				operands = append(operands, strings.TrimSpace(expr[start:i]))
				start = i + 1
			}
		}
	}

	return append(operands, strings.TrimSpace(expr[start:]))
}

func (e *RouteExtractor) resolveJSOperand(operand string) string {
	if operand == "" {
		return ""
	}

	if isJSQuote(operand[0]) {
		if endOfJSString(operand, 0) != len(operand)-1 {
			return ""
		}
		contents := operand[1 : len(operand)-1]
		if operand[0] == '`' {
			return e.substituteTemplate(contents)
		}
		return contents
	}

	if !isJSIdentifier(operand) {
		return ""
	}

	return e.jsConsts[operand]
}

func isJSIdentifier(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := range len(s) {
		if !isURLPatternNameChar(s[i]) {
			return false
		}
	}
	return true
}

func (e *RouteExtractor) substituteTemplate(contents string) string {
	var out strings.Builder
	for i := 0; i < len(contents); i++ {
		switch contents[i] {
		case '\\':
			out.WriteByte(contents[i])
			if i+1 < len(contents) {
				i++
				out.WriteByte(contents[i])
			}
		case '$':
			if i+1 >= len(contents) || contents[i+1] != '{' {
				out.WriteByte('$')
				continue
			}
			end := endOfJSInterpolation(contents, i+1)
			if end >= len(contents) {
				out.WriteString(contents[i:])
				return out.String()
			}
			if value := e.jsConsts[strings.TrimSpace(contents[i+2:end])]; value != "" {
				out.WriteString(value)
			} else {
				out.WriteString(contents[i : end+1])
			}
			i = end
		default:
			out.WriteByte(contents[i])
		}
	}

	return out.String()
}

func endOfJSInterpolation(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '\'', '"', '`':
			i = endOfJSString(s, i)
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(s)
}
