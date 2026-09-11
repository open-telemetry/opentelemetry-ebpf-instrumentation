// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"regexp"
	"strings"
)

// jsSource is a piece of JavaScript source together with its code mask: the
// same bytes with the contents of string and regular expression literals and
// the comments replaced by spaces. Patterns and separators are looked up in
// the mask, so that they match code only, and values are sliced from the
// text at the offsets found. A line is lexed once and sliced from then on.
type jsSource struct {
	text string
	code string
}

// lexJS returns s with its code mask, and the offset of a block comment that
// s opens without closing (-1 when it opens none).
func lexJS(s string) (src jsSource, openComment int) {
	out := []byte(s)
	blank := func(from, to int) {
		for j := from; j < to && j < len(out); j++ {
			out[j] = ' '
		}
	}

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"', '`':
			end := endOfJSString(s, i)
			blank(i+1, end)
			i = end
		case '\\':
			// outside a literal, a backslash can only start a unicode escape
			// of an identifier
			i++
		case '/':
			if end, ok := endOfJSComment(s, i); ok {
				if end >= len(s) && s[i+1] == '*' {
					blank(i, len(s))
					return jsSource{text: s, code: string(out)}, i
				}
				blank(i, end+1)
				i = end
			} else if startsJSRegex(s, i) {
				end := endOfJSRegex(s, i)
				blank(i+1, end)
				i = end
			}
		}
	}

	return jsSource{text: s, code: string(out)}, -1
}

func (s jsSource) slice(from, to int) jsSource {
	return jsSource{text: s.text[from:to], code: s.code[from:to]}
}

// trim removes the leading and trailing bytes that are not code: whitespace
// and comments. The trailing bytes of an unterminated literal go with them.
func (s jsSource) trim() jsSource {
	s = s.trimStart()
	end := len(s.code)
	for end > 0 && isJSSpace(s.code[end-1]) {
		end--
	}
	return s.slice(0, end)
}

// trimStart removes the leading bytes that are not code: whitespace and
// comments.
func (s jsSource) trimStart() jsSource {
	start := 0
	for start < len(s.code) && isJSSpace(s.code[start]) {
		start++
	}
	return s.slice(start, len(s.code))
}

func isJSSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// split cuts s at each occurrence of sep outside a literal, a comment or a
// nested object, array or call.
func (s jsSource) split(sep byte) []jsSource {
	var (
		parts []jsSource
		depth int
		start int
	)

	for i := 0; i < len(s.code); i++ {
		switch s.code[i] {
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
		case sep:
			if depth == 0 {
				parts = append(parts, s.slice(start, i).trim())
				start = i + 1
			}
		}
	}

	return append(parts, s.slice(start, len(s.code)).trim())
}

// jsCommentState tracks a block comment spanning lines while a file is
// scanned, so that commented-out code neither declares a constant nor makes
// a live one ambiguous. The code around the delimiters is still scanned.
type jsCommentState struct {
	open bool
	// whether the open comment started after code on its line, and how many
	// lines it has run for: such an opening is most likely a regular
	// expression misread as a comment once it runs maxJSMidLineCommentLines
	midLine bool
	lines   int
}

// strip returns the code of the line outside block comments, lexed and
// without its indentation, and whether there is any. Only the start of the
// line is trimmed, since a literal opened on it may close on a later line.
func (c *jsCommentState) strip(line string) (src jsSource, ok bool) {
	current := strings.TrimSpace(line)
	if c.open {
		end := strings.Index(current, "*/")
		switch {
		case end >= 0:
			c.open = false
			current = strings.TrimSpace(current[end+len("*/"):])
		case c.midLine && c.lines >= maxJSMidLineCommentLines:
			// scanning resumes rather than losing the rest of the file
			c.open = false
		default:
			c.lines++
			return jsSource{}, false
		}
	}

	src, opened := lexJS(current)
	if opened >= 0 {
		c.open = true
		c.midLine = opened > 0
		c.lines = 0
		src = src.slice(0, opened)
	}
	src = src.trimStart()
	return src, src.text != ""
}

// jsLineBuffer holds the lines of a call or route object not complete yet,
// so that the next line can complete it. It gives up on anything spanning
// maxJSBufferedLines, so that a long stretch of unmatched lines is not
// rescanned at each line.
type jsLineBuffer struct {
	text  string
	lines int
}

// merge prepends the buffered lines to the line and empties the buffer. It
// returns the merged text and how many lines it holds.
func (b *jsLineBuffer) merge(line string) (merged string, lines int) {
	if b.text == "" {
		return line, 1
	}
	merged, lines = b.text+"\n"+line, b.lines+1
	b.text, b.lines = "", 0
	return merged, lines
}

// keep buffers the text, made of the given number of lines, unless a call
// spanning that many lines is not credible.
func (b *jsLineBuffer) keep(text string, lines int) {
	if lines < maxJSBufferedLines {
		b.text, b.lines = text, lines
	}
}

// recordConstDeclaration remembers the constants declared by the line
// (const prefix = '/api', const a = '/a', b = '/b'), so that later route
// calls can refer to them. Each const holds what its initializer resolves
// to; any other const is remembered as unresolvable, so that a same-named
// literal in another scope cannot be taken for it. A name declared again,
// whatever its new initializer, becomes unresolvable for the same reason.
// Once the per-file cap of resolved values is reached, new names are
// remembered as unresolvable too; bundled files declare thousands of
// constants, so only the values are bounded, not the names.
func (e *RouteExtractor) recordConstDeclaration(line jsSource) {
	if !e.patterns.ConstDeclaration.MatchString(line.text) {
		return
	}

	for _, statement := range line.split(';') {
		m := e.patterns.ConstDeclaration.FindStringSubmatchIndex(statement.text)
		if m == nil {
			continue
		}
		for _, declarator := range statement.slice(m[2], m[3]).split(',') {
			d := e.patterns.ConstDeclarator.FindStringSubmatchIndex(declarator.text)
			if d == nil {
				continue
			}
			e.recordConst(declarator.text[d[2]:d[3]], declarator.slice(d[4], d[5]))
		}
	}
}

func (e *RouteExtractor) recordConst(name string, initializer jsSource) {
	if previous, exists := e.jsConsts[name]; exists {
		if previous != "" {
			e.jsResolvedConsts--
		}
		e.jsConsts[name] = ""
		return
	}

	value := ""
	if e.jsResolvedConsts < maxJSConsts {
		value = e.resolveJSExpression(initializer)
	}
	if value != "" {
		e.jsResolvedConsts++
	}
	e.jsConsts[name] = value
}

// routeCall is a route call found on a line: the method captured by the call
// pattern (empty when it captures none) and the path its first argument
// resolves to.
type routeCall struct {
	method string
	path   string
}

// resolveRouteCalls returns every call of the line matched by the pattern
// whose path resolves. Nothing is returned when the argument of any of the
// calls runs past the end of the line; cut reports it, so that the line can
// be completed with the next one and resolved as a whole.
func (e *RouteExtractor) resolveRouteCalls(line jsSource, call *regexp.Regexp) (calls []routeCall, cut bool) {
	for _, m := range call.FindAllStringSubmatchIndex(line.code, -1) {
		arg, complete := firstJSArgument(line.slice(m[1], len(line.text)))
		if !complete {
			return nil, true
		}

		path := e.resolveJSExpression(arg)
		if path == "" {
			continue
		}
		method := ""
		if len(m) > 2 && m[2] >= 0 {
			method = line.text[m[2]:m[3]]
		}
		calls = append(calls, routeCall{method: method, path: path})
	}

	return calls, false
}

// firstJSArgument returns the first argument of the call whose source follows
// its opening parenthesis. The argument ends at the first comma or closing
// parenthesis outside a literal, a comment or a nested object, array or call;
// complete reports whether that end was found before the source ran out.
func firstJSArgument(rest jsSource) (arg jsSource, complete bool) {
	depth := 0
	for i := 0; i < len(rest.code); i++ {
		switch rest.code[i] {
		case '(', '[', '{':
			depth++
		case ']', '}':
			depth--
		case ')':
			if depth == 0 {
				return rest.slice(0, i).trim(), true
			}
			depth--
		case ',':
			if depth == 0 {
				return rest.slice(0, i).trim(), true
			}
		}
	}

	return rest.trim(), false
}

// endOfJSComment returns the offset of the last byte of the comment opening
// at open, and whether s[open:] opens one at all. A line comment ends before
// the newline; a block comment left unclosed ends with s.
func endOfJSComment(s string, open int) (end int, ok bool) {
	if !strings.HasPrefix(s[open:], "//") && !strings.HasPrefix(s[open:], "/*") {
		return 0, false
	}

	if s[open+1] == '/' {
		if nl := strings.IndexByte(s[open:], '\n'); nl >= 0 {
			return open + nl - 1, true
		}
		return len(s), true
	}

	if closing := strings.Index(s[open+2:], "*/"); closing >= 0 {
		return open + 2 + closing + 1, true
	}
	return len(s), true
}

// jsRegexKeywords are the keywords after which a slash begins a regular
// expression literal rather than a division.
var jsRegexKeywords = map[string]bool{
	"await": true, "case": true, "delete": true, "do": true, "else": true,
	"in": true, "instanceof": true, "new": true, "return": true,
	"throw": true, "typeof": true, "void": true, "yield": true,
}

// startsJSRegex reports whether the slash at open begins a regular expression
// literal rather than a division or a comment: a slash that follows an
// operator, an opening bracket, a separator, one of jsRegexKeywords or
// nothing at all. This is the usual guess of a tokenizer without a parser;
// it is wrong after a closing parenthesis or brace, which the scan bounds
// with maxJSMidLineCommentLines.
func startsJSRegex(s string, open int) bool {
	if open+1 < len(s) && (s[open+1] == '/' || s[open+1] == '*') {
		return false
	}

	before := strings.TrimRight(s[:open], " \t\r\n")
	if before == "" {
		return true
	}
	if strings.IndexByte("(,=:[!&|?{};+-*%<>~^", before[len(before)-1]) >= 0 {
		return true
	}

	start := len(before)
	for start > 0 && isJSIdentifierChar(before[start-1]) {
		start--
	}
	return jsRegexKeywords[before[start:]]
}

// endOfJSRegex returns the offset of the slash closing the regular expression
// literal that opens at open. A slash inside a character class or after a
// backslash does not close it. A regular expression cannot span lines, so
// one left unclosed ends at the end of its line, or of s.
func endOfJSRegex(s string, open int) int {
	inClass := false
	for i := open + 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '\n':
			return i
		case '/':
			if !inClass {
				return i
			}
		}
	}
	return len(s)
}

// resolveJSExpression returns the string value of a path expression: a string
// literal, a template literal, a number, a known constant, or a concatenation
// of them. The value is unknown when any operand is not statically
// resolvable, in which case an empty string is returned.
func (e *RouteExtractor) resolveJSExpression(expr jsSource) string {
	var path strings.Builder
	for _, operand := range expr.split('+') {
		value := e.resolveJSOperand(operand)
		if value == "" {
			return ""
		}
		path.WriteString(value)
	}

	return path.String()
}

// resolveJSOperand returns the string value of a single operand: the contents
// of a string literal, a template literal with its resolvable interpolations
// substituted, a number, a parenthesized expression, or the value of a known
// constant. TypeScript syntax around the operand is ignored. Anything else (a
// member access, a call, an unknown name) is not statically resolvable.
func (e *RouteExtractor) resolveJSOperand(operand jsSource) string {
	operand = e.stripJSTypeSyntax(operand)
	if operand.text == "" {
		return ""
	}

	if closesJSGroup(operand) {
		return e.resolveJSExpression(operand.slice(1, len(operand.text)-1))
	}

	if isJSNumber(operand.text) {
		return operand.text
	}

	if isJSQuote(operand.text[0]) {
		if endOfJSString(operand.text, 0) != len(operand.text)-1 {
			return ""
		}
		contents := operand.text[1 : len(operand.text)-1]
		// a literal spanning lines is not a path
		if strings.Contains(contents, "\n") {
			return ""
		}
		if operand.text[0] == '`' {
			return e.substituteTemplate(contents)
		}
		return contents
	}

	if !isJSIdentifier(operand.text) {
		return ""
	}

	return e.jsConsts[operand.text]
}

// stripJSTypeSyntax removes the TypeScript syntax around an operand that has
// no runtime effect: a leading <type> cast, a trailing as or satisfies
// assertion, and a trailing non-null assertion.
func (e *RouteExtractor) stripJSTypeSyntax(operand jsSource) jsSource {
	if strings.Contains(operand.text, " as ") || strings.Contains(operand.text, " satisfies ") {
		if m := e.patterns.TypeAssertion.FindStringIndex(operand.text); m != nil {
			operand = operand.slice(0, m[0])
		}
	}
	if strings.HasPrefix(operand.text, "<") {
		if m := e.patterns.TypeCast.FindStringIndex(operand.text); m != nil {
			operand = operand.slice(m[1], len(operand.text))
		}
	}
	if strings.HasSuffix(operand.text, "!") {
		operand = operand.slice(0, len(operand.text)-1)
	}
	return operand.trim()
}

// closesJSGroup reports whether operand is a single parenthesized group: it
// opens with a parenthesis that is closed by its last byte.
func closesJSGroup(operand jsSource) bool {
	if operand.code == "" || operand.code[0] != '(' {
		return false
	}

	depth := 0
	for i := 0; i < len(operand.code); i++ {
		switch operand.code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i == len(operand.code)-1
			}
		}
	}
	return false
}

func isJSNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isJSIdentifier(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := range len(s) {
		if !isJSIdentifierChar(s[i]) {
			return false
		}
	}
	return true
}

func isJSIdentifierChar(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// substituteTemplate replaces every ${...} interpolation of a template
// literal whose expression resolves with its value. Any other interpolation
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
			// the interpolation sits inside a literal, which the line's mask
			// blanked, so its expression is lexed on its own
			expr, _ := lexJS(contents[i+2 : end])
			if value := e.resolveJSExpression(expr); value != "" {
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
