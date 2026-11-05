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
