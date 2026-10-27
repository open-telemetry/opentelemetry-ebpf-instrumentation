// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javadynamic

import (
	"fmt"
	"strings"
	"unicode"
)

// FunctionReference is the parsed Java Class#method selector.
type FunctionReference struct {
	ClassSelector  string
	MethodSelector string
	ClassGlob      bool
	MethodGlob     bool
	HasParameters  bool
	Parameters     []string
}

// ParseFunctionReference validates the runtime-supported Java selector syntax.
func ParseFunctionReference(reference string) (FunctionReference, error) {
	invalid := func(reason string) (FunctionReference, error) {
		return FunctionReference{}, fmt.Errorf("invalid Java method reference: %s", reason)
	}
	if reference == "" || strings.IndexFunc(reference, unicode.IsSpace) >= 0 {
		return invalid("reference must be non-empty and contain no whitespace")
	}
	sep := strings.IndexByte(reference, '#')
	if sep <= 0 || sep != strings.LastIndexByte(reference, '#') {
		return invalid("reference must contain exactly one '#' separator")
	}
	classSelector, methodPart := reference[:sep], reference[sep+1:]
	classGlob := strings.ContainsAny(classSelector, "*?")
	if classGlob {
		if !validGlobQualifiedName(classSelector) {
			return invalid("class selector must contain valid Java name components and glob operators")
		}
	} else if !validQualifiedName(classSelector, true) {
		return invalid("class selector must be a fully qualified Java name")
	}

	method := methodPart
	var parameters []string
	hasParameters := false
	if open := strings.IndexByte(methodPart, '('); open >= 0 || strings.Contains(methodPart, ")") {
		closePos := strings.IndexByte(methodPart, ')')
		if open <= 0 || closePos != len(methodPart)-1 || closePos < open ||
			strings.Contains(methodPart[open+1:closePos], "(") {
			return invalid("parameter list must be one final pair of parentheses")
		}
		hasParameters = true
		method = methodPart[:open]
		if open+1 < closePos {
			for parameter := range strings.SplitSeq(methodPart[open+1:closePos], ",") {
				if !validParameterType(parameter) {
					return invalid("parameter types must be fully qualified Java names or primitives")
				}
				parameters = append(parameters, parameter)
			}
		}
	}
	methodGlob := strings.ContainsAny(method, "*?")
	if methodGlob {
		if !validGlobIdentifier(method) {
			return invalid("method selector must contain valid identifier characters and glob operators")
		}
	} else if !validIdentifier(method) {
		return invalid("method selector must be a Java identifier")
	}

	return FunctionReference{
		ClassSelector:  classSelector,
		MethodSelector: method,
		ClassGlob:      classGlob,
		MethodGlob:     methodGlob,
		HasParameters:  hasParameters,
		Parameters:     parameters,
	}, nil
}

func validParameterType(value string) bool {
	base := value
	for strings.HasSuffix(base, "[]") {
		base = strings.TrimSuffix(base, "[]")
	}
	if base == "" || strings.ContainsAny(base, "[]") || base == "void" {
		return false
	}
	switch base {
	case "boolean", "byte", "short", "int", "long", "char", "float", "double":
		return true
	default:
		return validQualifiedName(base, true)
	}
}

func validQualifiedName(value string, requireDot bool) bool {
	if requireDot && !strings.Contains(value, ".") {
		return false
	}
	for part := range strings.SplitSeq(value, ".") {
		if !validIdentifier(part) {
			return false
		}
	}
	return true
}

func validGlobQualifiedName(value string) bool {
	for part := range strings.SplitSeq(value, ".") {
		if !validGlobIdentifier(part) {
			return false
		}
	}
	return true
}

func validGlobIdentifier(value string) bool {
	if value == "" {
		return false
	}
	first := true
	for _, r := range value {
		if r == '*' || r == '?' {
			first = false
			continue
		}
		if first {
			if !unicode.IsLetter(r) && r != '_' && r != '$' {
				return false
			}
			first = false
		} else if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '$' {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	if value == "" || javaKeyword(value) {
		return false
	}
	for i, r := range value {
		if i == 0 {
			if !unicode.IsLetter(r) && r != '_' && r != '$' {
				return false
			}
		} else if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '$' {
			return false
		}
	}
	return true
}

func javaKeyword(value string) bool {
	switch value {
	case "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "native", "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void", "volatile", "while", "true", "false", "null", "_":
		return true
	default:
		return false
	}
}
