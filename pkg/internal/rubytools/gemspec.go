// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"io"
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

var (
	gemNamePattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	gemVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	doBlockSuffix     = regexp.MustCompile(`(?:^|\s)do\s+\|([a-z_][A-Za-z0-9_]*)\|\s*$`)
)

func readGemspec(path string) serviceMetadata {
	file, _ := langtools.OpenMetadataFile(path, maxRubyMetadataBytes)
	if file == nil {
		return serviceMetadata{}
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxRubyMetadataBytes+1))
	if err != nil || int64(len(data)) > maxRubyMetadataBytes {
		return serviceMetadata{}
	}
	return parseGemspec(data)
}

func parseGemspec(data []byte) serviceMetadata {
	lines := rubyLines(data, false)
	structure := rubyLines(data, true)
	var variable, name, version string
	invocations := 0
	headerIndex := -1
	constructorName := false
	constructorVersion := false
	for index, line := range lines {
		if structure[index] == ambiguousRubyLine {
			return serviceMetadata{}
		}
		invocations += gemspecInvocationCount(structure[index])
		parsedVariable, parsedName, parsedVersion, ok := parseGemspecHeader(line)
		if !ok {
			continue
		}
		headerIndex = index
		variable = parsedVariable
		name = parsedName
		version = parsedVersion
		constructorName = parsedName != ""
		constructorVersion = parsedVersion != ""
	}
	if invocations != 1 || headerIndex < 0 || variable == "" || !rubyTopLevelAt(structure, headerIndex) {
		return serviceMetadata{}
	}

	nameAssignments := 0
	versionAssignments := 0
	depth := 0
	closed := false
	for index, line := range lines {
		if index == headerIndex {
			depth = 1
			continue
		}
		if closed {
			if strings.TrimSpace(line) != "" {
				return serviceMetadata{}
			}
			continue
		}

		nameValue, nameAssigned := parseGemspecAssignment(line, variable, "name")
		versionValue, versionAssigned := parseGemspecAssignment(line, variable, "version")
		if gemspecFieldReference(structure[index], variable, "name") && !nameAssigned ||
			gemspecFieldReference(structure[index], variable, "version") && !versionAssigned ||
			continuedGemspecFieldReference(structure, index, variable, "name") ||
			continuedGemspecFieldReference(structure, index, variable, "version") {
			return serviceMetadata{}
		}

		if nameAssigned {
			if depth != 1 {
				return serviceMetadata{}
			}
			nameAssignments++
			if nameValue != "" {
				name = nameValue
			}
		}
		if versionAssigned {
			if depth != 1 {
				return serviceMetadata{}
			}
			versionAssignments++
			if versionValue != "" {
				version = versionValue
			}
		}

		if depth == 0 {
			continue
		}
		if rubyBlockEnd(structure[index]) {
			depth--
			if depth == 0 {
				closed = true
			}
			continue
		}
		if rubyBlockStart(structure[index]) {
			depth++
		}
	}
	if !closed || nameAssignments > 1 || versionAssignments > 1 ||
		(constructorName && nameAssignments != 0) ||
		(constructorVersion && versionAssignments != 0) ||
		!validGemName(name) {
		return serviceMetadata{}
	}
	if !validGemVersion(version) {
		version = ""
	}
	return serviceMetadata{Name: name, Version: version}
}

func rubyTopLevelAt(lines []string, end int) bool {
	depth := 0
	for _, line := range lines[:end] {
		if rubyBlockEnd(line) {
			if depth == 0 {
				return false
			}
			depth--
			continue
		}
		if rubyBlockStart(line) {
			depth++
		}
	}
	return depth == 0
}

func rubyBlockStart(line string) bool {
	line = strings.TrimSpace(line)
	return strings.HasSuffix(line, "{") || moduleDeclaration.MatchString(line) ||
		anyClassDeclaration.MatchString(line) || blockDeclaration.MatchString(line)
}

func rubyBlockEnd(line string) bool {
	line = strings.TrimSpace(line)
	return line == "}" || line == "end"
}

func parseGemspecHeader(line string) (string, string, string, bool) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "::")
	const prefix = "Gem::Specification.new"
	if !strings.HasPrefix(line, prefix) {
		return "", "", "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	match := doBlockSuffix.FindStringSubmatchIndex(rest)
	if len(match) != 4 {
		return "", "", "", false
	}
	arguments := strings.TrimSpace(rest[:match[0]])
	variable := rest[match[2]:match[3]]
	if arguments == "" || arguments == "()" {
		return variable, "", "", true
	}
	if strings.HasPrefix(arguments, "(") && strings.HasSuffix(arguments, ")") {
		arguments = strings.TrimSpace(arguments[1 : len(arguments)-1])
	}
	if arguments == "" {
		return variable, "", "", true
	}
	name, rest, ok := consumeRubyLiteral(arguments)
	if !ok {
		return "", "", "", false
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return variable, name, "", true
	}
	if !strings.HasPrefix(rest, ",") {
		return "", "", "", false
	}
	version, rest, ok := consumeRubyLiteral(strings.TrimSpace(strings.TrimPrefix(rest, ",")))
	if !ok || strings.TrimSpace(rest) != "" {
		return "", "", "", false
	}
	return variable, name, version, true
}

func gemspecInvocationCount(line string) int {
	const prefix = "Gem::Specification.new"
	count := 0
	for index := 0; index < len(line); index++ {
		if !strings.HasPrefix(line[index:], prefix) || !rubyConstantBoundary(line, index) {
			continue
		}
		end := index + len(prefix)
		if end < len(line) && (isRubyWordByte(line[end]) || strings.ContainsRune("!?=", rune(line[end]))) {
			continue
		}
		count++
		index = end - 1
	}
	return count
}

func rubyConstantBoundary(line string, index int) bool {
	if index == 0 {
		return true
	}
	if index >= 2 && line[index-2:index] == "::" {
		return index == 2 || !isRubyWordByte(line[index-3])
	}
	return !isRubyWordByte(line[index-1]) && line[index-1] != ':'
}

func parseGemspecAssignment(line, variable, field string) (string, bool) {
	line = strings.TrimSpace(line)
	prefix := variable + "." + field
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if rest != "" && isRubyWordByte(rest[0]) {
		return "", false
	}
	if strings.HasPrefix(rest, "==") || strings.HasPrefix(rest, "=~") {
		return "", false
	}
	if !strings.HasPrefix(rest, "=") {
		return "", true
	}
	value, rest, ok := consumeRubyLiteral(strings.TrimSpace(strings.TrimPrefix(rest, "=")))
	if !ok || strings.TrimSpace(rest) != "" {
		return "", true
	}
	return value, true
}

func gemspecFieldReference(line, variable, field string) bool {
	for index := 0; index < len(line); index++ {
		if !strings.HasPrefix(line[index:], variable) ||
			(index != 0 && isRubyWordByte(line[index-1])) {
			continue
		}
		cursor := index + len(variable)
		if cursor < len(line) && isRubyWordByte(line[cursor]) {
			continue
		}
		for {
			for cursor < len(line) && (line[cursor] == ' ' || line[cursor] == '\t') {
				cursor++
			}
			if cursor >= len(line) || line[cursor] != ')' {
				break
			}
			cursor++
		}
		switch {
		case strings.HasPrefix(line[cursor:], "&."):
			cursor += 2
		case strings.HasPrefix(line[cursor:], "::"):
			cursor += 2
		case cursor < len(line) && line[cursor] == '.':
			cursor++
		default:
			continue
		}
		for cursor < len(line) && (line[cursor] == ' ' || line[cursor] == '\t') {
			cursor++
		}
		if strings.HasPrefix(line[cursor:], field) {
			end := cursor + len(field)
			if end == len(line) || !isRubyWordByte(line[end]) {
				return true
			}
		}
	}
	return false
}

func continuedGemspecFieldReference(lines []string, index int, variable, field string) bool {
	if index == 0 {
		return false
	}
	previousIndex := index - 1
	for previousIndex >= 0 && strings.TrimSpace(lines[previousIndex]) == "" {
		previousIndex--
	}
	if previousIndex < 0 {
		return false
	}
	withoutWhitespace := strings.NewReplacer(" ", "", "\t", "").Replace
	previous := withoutWhitespace(strings.TrimSpace(lines[previousIndex]))
	line := withoutWhitespace(strings.TrimSpace(lines[index]))
	var prefixes []string
	switch previous {
	case variable, variable + "\\":
		prefixes = []string{"." + field, "&." + field}
	case variable + ".", variable + "&.", variable + ".\\", variable + "&.\\":
		prefixes = []string{field}
	default:
		return false
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(line, prefix) &&
			(len(line) == len(prefix) || !isRubyWordByte(line[len(prefix)])) {
			return true
		}
	}
	return false
}

func consumeRubyLiteral(value string) (string, string, bool) {
	if len(value) < 2 || (value[0] != '\'' && value[0] != '"') {
		return "", value, false
	}
	quote := value[0]
	end := strings.IndexByte(value[1:], quote)
	if end < 0 {
		return "", value, false
	}
	end++
	literal := value[1:end]
	if strings.Contains(literal, "\\") || strings.Contains(literal, "#{") {
		return "", value, false
	}
	rest := strings.TrimSpace(value[end+1:])
	if after, ok := strings.CutPrefix(rest, ".freeze"); ok {
		rest = strings.TrimSpace(after)
	}
	return literal, rest, true
}

func validGemName(value string) bool {
	if value == "" || strings.ContainsRune(".-_", rune(value[0])) || !gemNamePattern.MatchString(value) {
		return false
	}
	return strings.IndexFunc(value, func(character rune) bool {
		return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
	}) >= 0
}

func validGemVersion(value string) bool {
	return value != "" && gemVersionPattern.MatchString(value)
}
