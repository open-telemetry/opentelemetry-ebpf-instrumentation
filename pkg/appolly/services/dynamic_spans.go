// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

import (
	"errors"
	"fmt"
	"strings"
)

// DynamicSpan is a span declaration attached to a matching capture selector.
// Runtime-specific adapters interpret FunctionReference.
type DynamicSpan struct {
	Name              string
	FunctionReference string
}

// NodeFunctionReference identifies an exact CommonJS module export.
type NodeFunctionReference struct {
	ModuleSpecifier string
	ExportPath      []string
}

// ParseNodeFunctionReference parses the Node.js exact CommonJS export syntax
// moduleSpecifier#exportPath.
func ParseNodeFunctionReference(reference string) (NodeFunctionReference, error) {
	if reference == "" || strings.ContainsAny(reference, " \t\r\n") {
		return NodeFunctionReference{}, fmt.Errorf("invalid node.js function reference %q", reference)
	}
	separator := strings.IndexByte(reference, '#')
	if separator <= 0 || separator != strings.LastIndexByte(reference, '#') || separator == len(reference)-1 {
		return NodeFunctionReference{}, errors.New("node.js function reference must be moduleSpecifier#exportPath")
	}
	moduleSpecifier := reference[:separator]
	if strings.ContainsAny(moduleSpecifier, "*?") {
		return NodeFunctionReference{}, errors.New("node.js module specifier globs are not supported")
	}
	exportPath := strings.Split(reference[separator+1:], ".")
	for _, component := range exportPath {
		if !isNodeExportIdentifier(component) {
			return NodeFunctionReference{}, errors.New("node.js export path must contain JavaScript identifiers")
		}
	}
	return NodeFunctionReference{ModuleSpecifier: moduleSpecifier, ExportPath: exportPath}, nil
}

func isNodeExportIdentifier(value string) bool {
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
