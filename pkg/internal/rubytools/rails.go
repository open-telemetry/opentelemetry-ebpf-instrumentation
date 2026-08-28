// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"io"
	"regexp"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

var (
	rubyConstant        = `[A-Z][A-Za-z0-9_]*`
	rubyConstantPath    = rubyConstant + `(?:::` + rubyConstant + `)*`
	moduleDeclaration   = regexp.MustCompile(`^\s*module\s+(` + rubyConstantPath + `)\s*$`)
	classDeclaration    = regexp.MustCompile(`^\s*class\s+((?:::)?` + rubyConstantPath + `)\s*<\s*(?:::)?Rails::Application\s*$`)
	anyClassDeclaration = regexp.MustCompile(`^\s*class\b`)
	blockDeclaration    = regexp.MustCompile(`^\s*(?:def|if|unless|case|begin|for|while|until)\b|(?:=|;|\(|\[|\{|,|&&|\|\||\?|:|\b(?:and|or)\b)\s*(?:if|unless|case|begin|for|while|until)\b|\bdo(?:\s*\|[^|]*\|)?\s*$|\{\s*(?:\|[^|]*\|)?\s*$`)
	endDeclaration      = regexp.MustCompile(`^\s*end\b`)
	acronymBoundary     = regexp.MustCompile(`([A-Z\d]+)([A-Z][a-z])`)
	wordBoundary        = regexp.MustCompile(`([a-z\d])([A-Z])`)
)

type rubyBlock struct {
	module string
}

func readRailsApplicationName(path string) string {
	file, _ := langtools.OpenMetadataFile(path, maxRubyMetadataBytes)
	if file == nil {
		return ""
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxRubyMetadataBytes+1))
	if err != nil || int64(len(data)) > maxRubyMetadataBytes {
		return ""
	}
	return parseRailsApplicationName(data)
}

func parseRailsApplicationName(data []byte) string {
	var blocks []rubyBlock
	var candidate string
	for _, line := range rubyLines(data, true) {
		if line == ambiguousRubyLine {
			return ""
		}
		if match := classDeclaration.FindStringSubmatch(line); len(match) == 2 {
			if candidate != "" || insideDynamicRubyBlock(blocks) {
				return ""
			}
			enclosing := currentRubyModule(blocks)
			if ambiguousQualifiedConstant(match[1], enclosing) {
				return ""
			}
			candidate = qualifiedRubyConstant(match[1], enclosing)
			blocks = append(blocks, rubyBlock{})
			continue
		}

		if strings.Contains(line, "Rails::Application") && anyClassDeclaration.MatchString(line) {
			return ""
		}
		if match := moduleDeclaration.FindStringSubmatch(line); len(match) == 2 {
			enclosing := currentRubyModule(blocks)
			if ambiguousQualifiedConstant(match[1], enclosing) {
				return ""
			}
			name := qualifiedRubyConstant(match[1], enclosing)
			blocks = append(blocks, rubyBlock{module: name})
			continue
		}
		if anyClassDeclaration.MatchString(line) || blockDeclaration.MatchString(line) {
			blocks = append(blocks, rubyBlock{})
			continue
		}
		if endDeclaration.MatchString(line) || strings.TrimSpace(line) == "}" {
			if len(blocks) == 0 {
				return ""
			}
			blocks = blocks[:len(blocks)-1]
		}
	}
	if len(blocks) != 0 {
		return ""
	}
	return railsServiceName(candidate)
}

func ambiguousQualifiedConstant(name, enclosing string) bool {
	return enclosing != "" && !strings.HasPrefix(name, "::") && strings.Contains(name, "::")
}

func insideDynamicRubyBlock(blocks []rubyBlock) bool {
	for _, block := range blocks {
		if block.module == "" {
			return true
		}
	}
	return false
}

func currentRubyModule(blocks []rubyBlock) string {
	for _, block := range slices.Backward(blocks) {
		if block.module != "" {
			return block.module
		}
	}
	return ""
}

func qualifiedRubyConstant(name, enclosing string) string {
	if after, ok := strings.CutPrefix(name, "::"); ok {
		return after
	}
	if enclosing == "" {
		return name
	}
	return enclosing + "::" + name
}

func railsServiceName(className string) string {
	if className == "" {
		return ""
	}
	className = strings.TrimSuffix(className, "::Application")
	parts := strings.Split(className, "::")
	for index, part := range parts {
		part = acronymBoundary.ReplaceAllString(part, `${1}_${2}`)
		part = wordBoundary.ReplaceAllString(part, `${1}_${2}`)
		part = strings.ReplaceAll(part, "_", "-")
		parts[index] = strings.ToLower(part)
	}
	return strings.Join(parts, "/")
}
