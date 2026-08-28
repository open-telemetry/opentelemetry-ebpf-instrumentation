// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"bytes"
	"io"
	"regexp"
	"strings"

	"github.com/odvcencio/gotreesitter"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

var (
	gemNamePattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	gemVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
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

// parseGemspec extracts static identity fields from a specification such as:
//
//	Gem::Specification.new do |spec|
//	  spec.name = "orders"
//	  spec.version = "1.2.3"
//	end
func parseGemspec(data []byte) serviceMetadata {
	tree := parseRubyTree(data)
	if tree == nil {
		return serviceMetadata{}
	}
	defer tree.release()

	constructors := gemspecConstructors(tree)
	if len(constructors) != 1 || !topLevelFinalExpression(tree, constructors[0]) {
		return serviceMetadata{}
	}

	constructor := constructors[0]
	block := tree.child(constructor, "block")
	if tree.nodeType(block) != "do_block" {
		return serviceMetadata{}
	}
	variable, ok := gemspecBlockVariable(tree, block)
	if !ok {
		return serviceMetadata{}
	}

	argumentsNode := tree.child(constructor, "arguments")
	if argumentsNode != nil && argumentsNode.StartPoint().Row != argumentsNode.EndPoint().Row {
		return serviceMetadata{}
	}
	arguments := rubyNamedChildren(argumentsNode)
	if len(arguments) > 2 {
		return serviceMetadata{}
	}

	var name, version string
	constructorName := false
	constructorVersion := false
	if len(arguments) >= 1 {
		name, ok = staticRubyString(tree, arguments[0])
		if !ok {
			return serviceMetadata{}
		}
		constructorName = true
	}
	if len(arguments) == 2 {
		version, ok = staticRubyString(tree, arguments[1])
		if !ok {
			return serviceMetadata{}
		}
		constructorVersion = true
	}

	allowedReferences := map[*gotreesitter.Node]struct{}{}
	nameAssignments := 0
	versionAssignments := 0
	for _, statement := range rubyExecutableChildren(tree, tree.child(block, "body")) {
		field, value, reference, assignment := directGemspecAssignment(tree, statement, variable)
		if !assignment {
			continue
		}
		if !standaloneRubyStatement(tree.source, statement) {
			return serviceMetadata{}
		}

		allowedReferences[reference] = struct{}{}
		static, staticValue := staticRubyString(tree, value)
		switch field {
		case "name":
			nameAssignments++
			if staticValue {
				name = static
			}
		case "version":
			versionAssignments++
			if staticValue {
				version = static
			}
		}
	}

	if hasUnexpectedGemspecIdentityReference(
		tree,
		tree.child(block, "body"),
		variable,
		allowedReferences,
	) {
		return serviceMetadata{}
	}
	if nameAssignments > 1 || versionAssignments > 1 ||
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

func gemspecConstructors(tree *rubySyntaxTree) []*gotreesitter.Node {
	var constructors []*gotreesitter.Node
	var visit func(*gotreesitter.Node)
	visit = func(node *gotreesitter.Node) {
		if node == nil {
			return
		}
		if isGemspecConstructor(tree, node) {
			constructors = append(constructors, node)
		}
		for _, child := range rubyNamedChildren(node) {
			visit(child)
		}
	}
	visit(tree.root())
	return constructors
}

func isGemspecConstructor(tree *rubySyntaxTree, node *gotreesitter.Node) bool {
	if tree.nodeType(node) != "call" || tree.text(tree.child(node, "method")) != "new" ||
		tree.text(tree.child(node, "operator")) != "." {
		return false
	}
	receiver, ok := tree.constant(tree.child(node, "receiver"))
	return ok && strings.TrimPrefix(receiver, "::") == "Gem::Specification"
}

func topLevelFinalExpression(tree *rubySyntaxTree, candidate *gotreesitter.Node) bool {
	statements := rubyExecutableChildren(tree, tree.root())
	return len(statements) != 0 && statements[len(statements)-1] == candidate
}

func rubyExecutableChildren(tree *rubySyntaxTree, node *gotreesitter.Node) []*gotreesitter.Node {
	children := rubyNamedChildren(node)
	result := children[:0]
	for _, child := range children {
		if tree.nodeType(child) != "comment" && tree.nodeType(child) != "uninterpreted" {
			result = append(result, child)
		}
	}
	return result
}

func gemspecBlockVariable(tree *rubySyntaxTree, block *gotreesitter.Node) (string, bool) {
	parameters := tree.child(block, "parameters")
	if tree.nodeType(parameters) != "block_parameters" {
		return "", false
	}
	children := rubyNamedChildren(parameters)
	if len(children) != 1 || tree.nodeType(children[0]) != "identifier" {
		return "", false
	}
	return tree.text(children[0]), true
}

func directGemspecAssignment(
	tree *rubySyntaxTree,
	node *gotreesitter.Node,
	variable string,
) (string, *gotreesitter.Node, *gotreesitter.Node, bool) {
	if tree.nodeType(node) != "assignment" {
		return "", nil, nil, false
	}
	left := tree.child(node, "left")
	field, ok := gemspecIdentityReference(tree, left, variable)
	if !ok || tree.text(left) != variable+"."+field {
		return "", nil, nil, false
	}
	right := tree.child(node, "right")
	if right == nil {
		return "", nil, nil, false
	}
	return field, right, left, true
}

func hasUnexpectedGemspecIdentityReference(
	tree *rubySyntaxTree,
	node *gotreesitter.Node,
	variable string,
	allowed map[*gotreesitter.Node]struct{},
) bool {
	if node == nil {
		return false
	}
	if _, reference := gemspecIdentityReference(tree, node, variable); reference {
		if _, ok := allowed[node]; !ok {
			return true
		}
	}
	for _, child := range rubyNamedChildren(node) {
		if hasUnexpectedGemspecIdentityReference(tree, child, variable, allowed) {
			return true
		}
	}
	return false
}

func gemspecIdentityReference(
	tree *rubySyntaxTree,
	node *gotreesitter.Node,
	variable string,
) (string, bool) {
	if tree.nodeType(node) != "call" || !rubyVariableReceiver(tree, tree.child(node, "receiver"), variable) {
		return "", false
	}
	method := tree.text(tree.child(node, "method"))
	return method, method == "name" || method == "version"
}

func rubyVariableReceiver(tree *rubySyntaxTree, node *gotreesitter.Node, variable string) bool {
	if node == nil {
		return false
	}
	if tree.nodeType(node) == "identifier" {
		return tree.text(node) == variable
	}
	if tree.nodeType(node) != "parenthesized_statements" {
		return false
	}
	children := rubyExecutableChildren(tree, node)
	return len(children) == 1 && rubyVariableReceiver(tree, children[0], variable)
}

func staticRubyString(tree *rubySyntaxTree, node *gotreesitter.Node) (string, bool) {
	if tree.nodeType(node) == "call" && tree.text(tree.child(node, "method")) == "freeze" &&
		tree.text(tree.child(node, "operator")) == "." && tree.child(node, "arguments") == nil &&
		tree.child(node, "block") == nil {
		node = tree.child(node, "receiver")
	}
	if tree.nodeType(node) != "string" {
		return "", false
	}

	value := tree.text(node)
	if len(value) < 2 || value[0] != value[len(value)-1] || value[0] != '\'' && value[0] != '"' {
		return "", false
	}
	value = value[1 : len(value)-1]
	if strings.Contains(value, "\\") || strings.Contains(value, "#{") {
		return "", false
	}
	return value, true
}

func standaloneRubyStatement(source []byte, node *gotreesitter.Node) bool {
	start := int(node.StartByte())
	end := int(node.EndByte())
	lineStart := bytes.LastIndexByte(source[:start], '\n') + 1
	lineEndOffset := bytes.IndexByte(source[end:], '\n')
	lineEnd := len(source)
	if lineEndOffset >= 0 {
		lineEnd = end + lineEndOffset
	}

	if strings.TrimSpace(string(source[lineStart:start])) != "" {
		return false
	}
	remainder := strings.TrimSpace(string(source[end:lineEnd]))
	return remainder == "" || strings.HasPrefix(remainder, "#")
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
