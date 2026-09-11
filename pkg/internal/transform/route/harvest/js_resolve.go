// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"regexp"
	"strings"
)

// recordStringDeclaration remembers a constant declared by the line
// (const prefix = '/api'), so that later route calls can refer to it. Only a
// const whose whole initializer is a single string literal has a value; any
// other const is remembered as unresolvable, so that a same-named literal in
// another scope cannot be taken for it. A name declared again, whatever its
// new initializer, becomes unresolvable for the same reason. Once the per-file
// cap is reached, new names are dropped.
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

// constStringValue returns the value of a const initializer when the whole of
// it is a single string literal, optionally followed by a semicolon and a
// trailing comment, and an empty string otherwise.
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

// isJSTrailingComment reports whether s is empty or holds nothing but a
// comment: a line comment, or a block comment closed on the same line.
func isJSTrailingComment(s string) bool {
	if s == "" || strings.HasPrefix(s, "//") {
		return true
	}
	if !strings.HasPrefix(s, "/*") {
		return false
	}
	return strings.HasSuffix(s, "*/") && len(s) >= len("/**/")
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

	// an argument cut by the end of the line is left for the scan to complete
	// with the next line
	arg, complete := firstJSArgument(line[m[1]:])
	if !complete {
		return method, ""
	}

	return method, e.resolveJSExpression(arg)
}

// firstJSArgument returns the first argument of the call whose source follows
// its opening parenthesis. The argument ends at the first comma or closing
// parenthesis outside a string literal or a nested object, array or call;
// complete reports whether that end was found before the source ran out.
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
