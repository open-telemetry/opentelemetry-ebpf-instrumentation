// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/internal/config/nodejs"

import (
	"errors"
	"fmt"
	"strings"
)

// FunctionReference identifies an exact CommonJS module export.
type FunctionReference struct {
	ModuleSpecifier string
	ExportPath      []string
}

// V2SpanTarget contains the target and refinements relevant to the currently
// supported Node.js Config v2 dynamic-span subset.
type V2SpanTarget struct {
	Function            string
	FunctionNoRet       string
	USDTSpan            string
	USDTNoRet           string
	HasAttributes       bool
	AutomaticAttributes bool
}

// ParseFunctionReference parses the exact CommonJS export syntax
// moduleSpecifier#exportPath.
func ParseFunctionReference(reference string) (FunctionReference, error) {
	if reference == "" || strings.ContainsAny(reference, " \t\r\n") {
		return FunctionReference{}, fmt.Errorf("invalid node.js function reference %q", reference)
	}
	separator := strings.IndexByte(reference, '#')
	if separator <= 0 || separator != strings.LastIndexByte(reference, '#') || separator == len(reference)-1 {
		return FunctionReference{}, errors.New("node.js function reference must be moduleSpecifier#exportPath")
	}
	moduleSpecifier := reference[:separator]
	if strings.ContainsAny(moduleSpecifier, "*?") {
		return FunctionReference{}, errors.New("node.js module specifier globs are not supported")
	}
	exportPath := strings.Split(reference[separator+1:], ".")
	for _, component := range exportPath {
		if !isExportIdentifier(component) {
			return FunctionReference{}, errors.New("node.js export path must contain JavaScript identifiers")
		}
	}
	return FunctionReference{ModuleSpecifier: moduleSpecifier, ExportPath: exportPath}, nil
}

// ValidateV2DynamicSpans validates the Node.js subset of Config v2 dynamic
// spans without coupling this runtime package to the shared schema package.
func ValidateV2DynamicSpans(ruleIndex int, languageGlobs []string, languageRegex string, spans []V2SpanTarget) error {
	if len(spans) == 0 {
		return nil
	}
	path := fmt.Sprintf("capture.rules[%d].refine.spans", ruleIndex)
	if len(languageGlobs) != 1 || languageGlobs[0] != "nodejs" || languageRegex != "" {
		return fmt.Errorf("%s is currently supported only for rules matching process.language_glob: [nodejs]", path)
	}
	for spanIndex, span := range spans {
		spanPath := fmt.Sprintf("%s[%d]", path, spanIndex)
		if span.Function == "" || span.FunctionNoRet != "" || span.USDTSpan != "" || span.USDTNoRet != "" {
			return fmt.Errorf("%s.on.function is the only currently supported Node.js span target", spanPath)
		}
		if span.HasAttributes || span.AutomaticAttributes {
			return fmt.Errorf("%s.attributes and automatic_attributes are not currently supported", spanPath)
		}
		if _, err := ParseFunctionReference(span.Function); err != nil {
			return fmt.Errorf("%s.on.function: %w", spanPath, err)
		}
	}
	return nil
}

func isExportIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		if character == '_' || character == '$' ||
			character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' {
			continue
		}
		if i > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}
