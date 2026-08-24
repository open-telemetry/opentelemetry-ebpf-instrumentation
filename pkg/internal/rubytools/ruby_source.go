// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"strings"
)

const ambiguousRubyLine = "\x00"

func rubyLines(data []byte, eraseStrings bool) []string {
	lines := strings.Split(string(data), "\n")
	result := make([]string, 0, len(lines))
	var heredocs []rubyHeredoc
	var percentLiteral *rubyPercentLiteral
	var slashLiteral *rubySlashLiteral
	var quote byte
	blockComment := false
	sourceEnded := false
	for _, rawLine := range lines {
		line := strings.TrimSuffix(rawLine, "\r")
		if sourceEnded {
			result = append(result, "")
			continue
		}
		if len(heredocs) != 0 {
			terminator := line
			if heredocs[0].allowIndent {
				terminator = strings.TrimLeft(terminator, " \t")
			}
			if terminator == heredocs[0].delimiter {
				heredocs = heredocs[1:]
			}
			result = append(result, "")
			continue
		}
		if percentLiteral != nil {
			literal, end, closed := scanRubyPercentLiteralRange(line, 0, *percentLiteral)
			if !closed {
				percentLiteral = &literal
				result = append(result, "")
				continue
			}
			percentLiteral = nil
			line = strings.Repeat(" ", end+1) + line[end+1:]
		}
		if slashLiteral != nil {
			literal, end, closed := scanRubySlashLiteral(line, 0, *slashLiteral)
			if !closed {
				slashLiteral = &literal
				result = append(result, "")
				continue
			}
			slashLiteral = nil
			line = strings.Repeat(" ", end+1) + line[end+1:]
		}
		if blockComment {
			if line == "=end" || strings.HasPrefix(line, "=end ") {
				blockComment = false
			}
			result = append(result, "")
			continue
		}
		if quote == 0 && (line == "=begin" || strings.HasPrefix(line, "=begin ")) {
			blockComment = true
			result = append(result, "")
			continue
		}
		if quote == 0 && line == "__END__" {
			sourceEnded = true
			result = append(result, "")
			continue
		}
		if ambiguousRubyStringSyntax(line, quote) || ambiguousRubyPercentLiteral(line, quote) ||
			ambiguousRubySlashCommand(line, quote) {
			result = append(result, ambiguousRubyLine)
			continue
		}

		lineHeredocs := rubyHeredocs(line, quote)
		if ambiguousRubyHeredocs(lineHeredocs) {
			result = append(result, ambiguousRubyLine)
			continue
		}
		percentStarted := false
		literalStart := 0
		if literal, start, ok := findMultilineRubyPercentLiteral(line, quote); ok {
			percentLiteral = &literal
			percentStarted = true
			literalStart = start
		}
		slashStarted := false
		if !percentStarted {
			literal, start, ok := findMultilineRubySlashLiteral(line, quote)
			if ok {
				slashLiteral = &literal
				slashStarted = true
				literalStart = start
			}
		}
		if len(lineHeredocs) != 0 {
			heredocs = lineHeredocs
		}
		if percentStarted || slashStarted {
			preserved, erased, nextQuote := cleanRubyLine(line[:literalStart], quote)
			quote = nextQuote
			if eraseStrings {
				result = append(result, erased)
			} else {
				result = append(result, preserved+line[literalStart:])
			}
			continue
		}
		preserved, erased, nextQuote := cleanRubyLine(line, quote)
		quote = nextQuote
		switch {
		case eraseStrings:
			result = append(result, erased)
		default:
			result = append(result, preserved)
		}
	}
	return result
}

type rubySlashLiteral struct {
	inCharacterClass bool
}

func multilineRubySlashLiteral(line string, quote byte) (rubySlashLiteral, bool) {
	literal, _, ok := findMultilineRubySlashLiteral(line, quote)
	return literal, ok
}

func findMultilineRubySlashLiteral(line string, quote byte) (rubySlashLiteral, int, bool) {
	for index := 0; index < len(line); index++ {
		char := line[index]
		if quote != 0 {
			if char == '\\' {
				index++
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '#' {
			return rubySlashLiteral{}, 0, false
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			continue
		}
		if char == '%' {
			literal, start, ok := rubyPercentLiteralAt(line, index)
			if ok {
				_, end, closed := scanRubyPercentLiteralRange(line, start, literal)
				if !closed {
					return rubySlashLiteral{}, 0, false
				}
				index = end
				continue
			}
		}
		if char != '/' || !rubyRegexCanStart(line[:index]) {
			continue
		}

		literal, end, closed := scanRubySlashLiteral(line, index+1, rubySlashLiteral{})
		if !closed {
			return literal, index, true
		}
		index = end
	}
	return rubySlashLiteral{}, 0, false
}

func scanRubySlashLiteral(
	line string,
	start int,
	literal rubySlashLiteral,
) (rubySlashLiteral, int, bool) {
	for index := start; index < len(line); index++ {
		switch line[index] {
		case '\\':
			index++
		case '[':
			literal.inCharacterClass = true
		case ']':
			literal.inCharacterClass = false
		case '/':
			if !literal.inCharacterClass {
				return literal, index, true
			}
		}
	}
	return literal, len(line), false
}

func rubyRegexCanStart(prefix string) bool {
	return rubyRegexExpressionCanStart(prefix) || rubyCommandArgumentCanStart(prefix)
}

func rubyRegexExpressionCanStart(prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return true
	}
	if strings.ContainsRune("=([{,:;!&|?~<>+-*/%^", rune(prefix[len(prefix)-1])) ||
		strings.HasSuffix(prefix, "..") {
		return true
	}
	for _, keyword := range [...]string{"return", "when", "if", "unless", "and", "or", "then"} {
		if strings.HasSuffix(prefix, keyword) {
			index := len(prefix) - len(keyword)
			if index == 0 || !isRubyWordByte(prefix[index-1]) {
				return true
			}
		}
	}
	return false
}

type rubyPercentLiteral struct {
	open  byte
	close byte
	depth int
}

func multilineRubyPercentLiteral(line string, quote byte) (rubyPercentLiteral, bool) {
	literal, _, ok := findMultilineRubyPercentLiteral(line, quote)
	return literal, ok
}

func findMultilineRubyPercentLiteral(line string, quote byte) (rubyPercentLiteral, int, bool) {
	for index := 0; index < len(line); index++ {
		char := line[index]
		if quote != 0 {
			if char == '\\' {
				index++
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '#' {
			return rubyPercentLiteral{}, 0, false
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			continue
		}
		if char == '/' && rubyRegexCanStart(line[:index]) {
			_, end, closed := scanRubySlashLiteral(line, index+1, rubySlashLiteral{})
			if !closed {
				return rubyPercentLiteral{}, 0, false
			}
			index = end
			continue
		}
		if char != '%' {
			continue
		}

		literal, start, ok := rubyPercentLiteralAt(line, index)
		if !ok {
			continue
		}
		literal, end, closed := scanRubyPercentLiteralRange(line, start, literal)
		if !closed {
			return literal, index, true
		}
		index = end
	}
	return rubyPercentLiteral{}, 0, false
}

func rubyPercentLiteralAt(line string, index int) (rubyPercentLiteral, int, bool) {
	delimiterIndex := index + 1
	if delimiterIndex < len(line) && strings.ContainsRune("qQwWiIxrs", rune(line[delimiterIndex])) {
		delimiterIndex++
	}
	if delimiterIndex >= len(line) || isRubyWordByte(line[delimiterIndex]) ||
		line[delimiterIndex] == ' ' || line[delimiterIndex] == '\t' {
		return rubyPercentLiteral{}, 0, false
	}
	return newRubyPercentLiteral(line[delimiterIndex]), delimiterIndex + 1, true
}

func rubyPercentLiteralCanStart(prefix string) bool {
	if rubyRegexCanStart(prefix) {
		return true
	}
	trimmed := strings.TrimRight(prefix, " \t")
	if trimmed == "" {
		return true
	}
	if strings.ContainsRune("<>+-*/%^", rune(trimmed[len(trimmed)-1])) {
		return true
	}
	return rubyCommandArgumentCanStart(prefix)
}

func rubyCommandArgumentCanStart(prefix string) bool {
	trimmed := rubyCommandArgument(prefix)
	for _, command := range [...]string{"abort", "fail", "p", "print", "printf", "puts", "raise", "warn"} {
		if trimmed == command {
			return true
		}
	}
	dot := strings.LastIndexByte(trimmed, '.')
	if dot <= 0 || dot == len(trimmed)-1 || strings.ContainsAny(trimmed, " \t") {
		return false
	}
	method := trimmed[dot+1:]
	if method[0] != '_' && (method[0] < 'A' || method[0] > 'Z') &&
		(method[0] < 'a' || method[0] > 'z') {
		return false
	}
	for index := range len(method) {
		if !isRubyWordByte(method[index]) && (index != len(method)-1 || method[index] != '!' && method[index] != '?') {
			return false
		}
	}
	return true
}

func rubyBareCommandArgumentCanStart(prefix string) bool {
	argument := rubyCommandArgument(prefix)
	if argument == "" || argument[0] < 'a' || argument[0] > 'z' {
		return false
	}
	for index := 1; index < len(argument); index++ {
		if !isRubyWordByte(argument[index]) &&
			(index != len(argument)-1 || argument[index] != '!' && argument[index] != '?') {
			return false
		}
	}
	return true
}

func rubyCommandArgument(prefix string) string {
	rightTrimmed := strings.TrimRight(prefix, " \t")
	if rightTrimmed == "" || len(rightTrimmed) == len(prefix) {
		return ""
	}
	argument := strings.TrimSpace(rightTrimmed)
	if separator := strings.LastIndexAny(argument, "=,;([{"); separator >= 0 {
		argument = strings.TrimSpace(argument[separator+1:])
	}
	return argument
}

func ambiguousRubyStringSyntax(line string, quote byte) bool {
	for index := 0; index < len(line); index++ {
		char := line[index]
		if quote != 0 {
			if char == '\\' {
				index++
				continue
			}
			if quote != '\'' && char == '#' && index+1 < len(line) && line[index+1] == '{' {
				end, ambiguous := rubyInterpolationEnd(line, index)
				if ambiguous {
					return true
				}
				index = end
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '#' {
			if index+1 < len(line) && line[index+1] == '{' {
				end, ambiguous := rubyInterpolationEnd(line, index)
				if ambiguous {
					return true
				}
				index = end
				continue
			}
			return false
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			continue
		}
		if char == '?' && index+1 < len(line) && line[index+1] != ' ' && line[index+1] != '\t' &&
			(rubyRegexCanStart(line[:index]) || rubyBareCommandArgumentCanStart(line[:index]) ||
				strings.HasSuffix(line[:index], " ") || strings.HasSuffix(line[:index], "\t")) {
			return true
		}
	}
	return false
}

func rubyInterpolationEnd(line string, start int) (int, bool) {
	end := strings.IndexByte(line[start+2:], '}')
	if end < 0 {
		return len(line), true
	}
	end += start + 2
	expression := line[start+2 : end]
	return end, strings.ContainsAny(expression, "'\"`/%{}")
}

func ambiguousRubyPercentLiteral(line string, quote byte) bool {
	for index := 0; index < len(line); index++ {
		char := line[index]
		if quote != 0 {
			if char == '\\' {
				index++
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '#' {
			return false
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			continue
		}
		if char == '/' && rubyRegexCanStart(line[:index]) {
			_, end, closed := scanRubySlashLiteral(line, index+1, rubySlashLiteral{})
			if !closed {
				return false
			}
			index = end
			continue
		}
		if char != '%' {
			continue
		}
		literal, start, ok := rubyPercentLiteralAt(line, index)
		if !ok {
			continue
		}
		if !rubyPercentLiteralCanStart(line[:index]) {
			return true
		}
		_, end, closed := scanRubyPercentLiteralRange(line, start, literal)
		if !closed {
			return false
		}
		index = end
	}
	return false
}

func ambiguousRubySlashCommand(line string, quote byte) bool {
	for index := 0; index < len(line); index++ {
		char := line[index]
		if quote != 0 {
			if char == '\\' {
				index++
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '#' {
			return false
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			continue
		}
		if char == '%' {
			literal, start, ok := rubyPercentLiteralAt(line, index)
			if ok {
				_, end, closed := scanRubyPercentLiteralRange(line, start, literal)
				if !closed {
					return false
				}
				index = end
				continue
			}
		}
		if char != '/' {
			continue
		}
		if rubyRegexCanStart(line[:index]) {
			_, end, closed := scanRubySlashLiteral(line, index+1, rubySlashLiteral{})
			if !closed {
				return !rubyRegexExpressionCanStart(line[:index])
			}
			index = end
			continue
		}
		if _, _, closed := scanRubySlashLiteral(line, index+1, rubySlashLiteral{}); closed {
			return true
		}
		if rubyBareCommandArgumentCanStart(line[:index]) {
			return true
		}
	}
	return false
}

func newRubyPercentLiteral(delimiter byte) rubyPercentLiteral {
	closeDelimiter := delimiter
	switch delimiter {
	case '(':
		closeDelimiter = ')'
	case '[':
		closeDelimiter = ']'
	case '{':
		closeDelimiter = '}'
	case '<':
		closeDelimiter = '>'
	}
	return rubyPercentLiteral{open: delimiter, close: closeDelimiter, depth: 1}
}

func scanRubyPercentLiteral(line string, start int, literal rubyPercentLiteral) int {
	literal, _, _ = scanRubyPercentLiteralRange(line, start, literal)
	return literal.depth
}

func scanRubyPercentLiteralRange(
	line string,
	start int,
	literal rubyPercentLiteral,
) (rubyPercentLiteral, int, bool) {
	for index := start; index < len(line); index++ {
		if line[index] == '\\' {
			index++
			continue
		}
		if literal.open != literal.close && line[index] == literal.open {
			literal.depth++
			continue
		}
		if line[index] == literal.close {
			literal.depth--
			if literal.depth == 0 {
				return literal, index, true
			}
		}
	}
	return literal, len(line), false
}

func isRubyWordByte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9' || value == '_'
}

type rubyHeredoc struct {
	delimiter   string
	allowIndent bool
	ambiguous   bool
}

func ambiguousRubyHeredocs(heredocs []rubyHeredoc) bool {
	for _, heredoc := range heredocs {
		if heredoc.ambiguous {
			return true
		}
	}
	return false
}

func rubyHeredocs(line string, quote byte) []rubyHeredoc {
	var heredocs []rubyHeredoc
	for index := 0; index < len(line); index++ {
		char := line[index]
		if quote != 0 {
			if char == '\\' {
				index++
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		if char == '#' {
			return heredocs
		}
		if char == '\'' || char == '"' || char == '`' {
			quote = char
			continue
		}
		if char == '%' {
			literal, start, ok := rubyPercentLiteralAt(line, index)
			if ok {
				_, end, closed := scanRubyPercentLiteralRange(line, start, literal)
				if !closed {
					return heredocs
				}
				index = end
				continue
			}
		}
		if char == '/' && rubyRegexCanStart(line[:index]) {
			_, end, closed := scanRubySlashLiteral(line, index+1, rubySlashLiteral{})
			if !closed {
				return heredocs
			}
			index = end
			continue
		}
		if char != '<' || index+1 >= len(line) || line[index+1] != '<' {
			continue
		}

		allowIndent := false
		if index+2 < len(line) && (line[index+2] == '-' || line[index+2] == '~') {
			allowIndent = true
		}
		canStart, ambiguous := rubyHeredocStart(line[:index])
		if !canStart {
			continue
		}

		index += 2
		if allowIndent {
			index++
		}
		var delimiterQuote byte
		if index < len(line) && (line[index] == '\'' || line[index] == '"' || line[index] == '`') {
			delimiterQuote = line[index]
			index++
		}
		start := index
		if delimiterQuote != 0 {
			for index < len(line) && line[index] != delimiterQuote {
				index++
			}
			if index == start || index >= len(line) {
				continue
			}
		} else {
			for index < len(line) && ((line[index] >= 'A' && line[index] <= 'Z') ||
				(line[index] >= 'a' && line[index] <= 'z') ||
				(line[index] >= '0' && line[index] <= '9') || line[index] == '_') {
				index++
			}
			if index == start {
				continue
			}
		}
		heredocs = append(heredocs, rubyHeredoc{
			delimiter:   line[start:index],
			allowIndent: allowIndent,
			ambiguous:   ambiguous,
		})
	}
	return heredocs
}

func rubyHeredocCanStart(prefix string) bool {
	canStart, _ := rubyHeredocStart(prefix)
	return canStart
}

func rubyHeredocStart(prefix string) (bool, bool) {
	if rubyCommandArgumentCanStart(prefix) {
		return true, true
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || strings.ContainsRune("=([{,:;", rune(prefix[len(prefix)-1])) {
		return true, false
	}
	for _, keyword := range [...]string{"return", "when", "then", "and", "or"} {
		if strings.HasSuffix(prefix, keyword) {
			index := len(prefix) - len(keyword)
			if index == 0 || !isRubyWordByte(prefix[index-1]) {
				return true, false
			}
		}
	}
	if prefix[0] >= 'a' && prefix[0] <= 'z' || prefix[0] == '_' {
		for index := 1; index < len(prefix); index++ {
			if !isRubyWordByte(prefix[index]) && prefix[index] != '!' && prefix[index] != '?' {
				return false, false
			}
		}
		return true, true
	}
	return false, false
}

func cleanRubyLine(line string, quote byte) (string, string, byte) {
	preserved := []byte(line)
	erased := []byte(line)
	insideAtStart := quote != 0
	for index := 0; index < len(preserved); index++ {
		char := preserved[index]
		if quote == 0 {
			if char == '%' {
				literal, start, ok := rubyPercentLiteralAt(line, index)
				if ok {
					_, end, closed := scanRubyPercentLiteralRange(line, start, literal)
					if closed {
						eraseRubyRange(erased, index, end)
						index = end
						continue
					}
				}
			}
			if char == '/' && rubyRegexCanStart(string(preserved[:index])) {
				_, end, closed := scanRubySlashLiteral(line, index+1, rubySlashLiteral{})
				if closed {
					eraseRubyRange(erased, index, end)
					index = end
					continue
				}
			}
			switch char {
			case '#':
				return string(preserved[:index]), string(erased[:index]), quote
			case '\'', '"', '`':
				quote = char
				erased[index] = ' '
			}
			continue
		}

		erased[index] = ' '
		if char == '\\' {
			index++
			if index < len(erased) {
				erased[index] = ' '
			}
			continue
		}
		if char == quote {
			quote = 0
		}
	}
	if insideAtStart {
		return "", string(erased), quote
	}
	return string(preserved), string(erased), quote
}

func eraseRubyRange(line []byte, start, end int) {
	for index := start; index <= end; index++ {
		line[index] = ' '
	}
}
