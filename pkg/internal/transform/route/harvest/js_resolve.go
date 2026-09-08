// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"regexp"
	"strings"
)

// recordStringDeclaration remembers a string constant declared by the line
// (const prefix = '/api'), so that later route calls can refer to it. Only a
// declaration whose whole initializer is a single string literal is tracked;
// once the per-file cap is reached, new names are dropped but a redeclared
// name still takes its latest value.
func (e *RouteExtractor) recordStringDeclaration(line string) {
	m := e.patterns.StringDeclaration.FindStringSubmatchIndex(line)
	if m == nil {
		return
	}
	name := line[m[2]:m[3]]

	open := m[1] - 1
	end := endOfJSString(line, open)
	if end >= len(line) {
		return
	}

	rest := strings.TrimSpace(line[end+1:])
	if rest != "" && rest != ";" {
		return
	}

	value := jsStringLiteral(line[open : end+1])
	if value == "" {
		return
	}

	if _, exists := e.jsConsts[name]; !exists && len(e.jsConsts) >= maxJSStringConsts {
		return
	}
	e.jsConsts[name] = value
}

// resolveRouteCall returns the method captured by the call pattern (empty when
// it captures none) and the path its first argument resolves to. An empty path
// means the line holds no such call or its path is not statically resolvable.
func (e *RouteExtractor) resolveRouteCall(line string, call *regexp.Regexp) (method, path string) {
	m := call.FindStringSubmatchIndex(line)
	if m == nil {
		return "", ""
	}

	if len(m) > 2 && m[2] >= 0 {
		method = line[m[2]:m[3]]
	}

	return method, e.resolveJSExpression(firstJSArgument(line[m[1]:]))
}

// firstJSArgument returns the first argument of the call whose source follows
// its opening parenthesis. The argument ends at the first comma or closing
// parenthesis outside a string literal or a nested object, array or call. It
// is returned as read when the source ends before either of them.
func firstJSArgument(rest string) string {
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
				return strings.TrimSpace(rest[:i])
			}
			depth--
		case ',':
			if depth == 0 {
				return strings.TrimSpace(rest[:i])
			}
		}
	}

	return strings.TrimSpace(rest)
}

// resolveJSExpression returns the string value of a path expression: a string
// literal, a template literal, a known constant, or a concatenation of them.
// The value is unknown when any operand is not statically resolvable, in
// which case an empty string is returned.
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

// splitJSConcat splits an expression into the operands of its top-level '+'
// operators. A '+' inside a string literal or a nested object, array or call
// does not separate operands.
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

// resolveJSOperand returns the string value of a single operand: the contents
// of a string literal, a template literal with its known interpolations
// substituted, or the value of a known constant. Anything else (a member
// access, a call, an unknown name) is not statically resolvable.
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

// substituteTemplate replaces every ${name} interpolation of a template
// literal that names a known constant with its value. Any other interpolation
// is kept as is, so that the path cleanup turns it into a placeholder.
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
			if value, ok := e.jsConsts[strings.TrimSpace(contents[i+2:end])]; ok {
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

// endOfJSInterpolation returns the offset of the brace closing the
// interpolation that opens at open, or len(s) when it does not close in s.
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
