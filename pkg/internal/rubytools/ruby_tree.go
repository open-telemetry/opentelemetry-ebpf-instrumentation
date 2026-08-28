// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

type rubySyntaxTree struct {
	source   []byte
	language *gotreesitter.Language
	tree     *gotreesitter.Tree
}

func parseRubyTree(source []byte) *rubySyntaxTree {
	language := grammars.RubyLanguage()
	tree, err := gotreesitter.NewParser(language).ParseStrict(source)
	if err != nil || tree == nil {
		if tree != nil {
			tree.Release()
		}
		return nil
	}

	root := tree.RootNode()
	if root == nil || root.HasError() {
		tree.Release()
		return nil
	}

	syntax := &rubySyntaxTree{source: source, language: language, tree: tree}
	if syntax.hasOrphanEnd(root) {
		tree.Release()
		return nil
	}

	return syntax
}

func (tree *rubySyntaxTree) release() {
	tree.tree.Release()
}

func (tree *rubySyntaxTree) root() *gotreesitter.Node {
	return tree.tree.RootNode()
}

func (tree *rubySyntaxTree) nodeType(node *gotreesitter.Node) string {
	if node == nil {
		return ""
	}

	return node.Type(tree.language)
}

func (tree *rubySyntaxTree) text(node *gotreesitter.Node) string {
	if node == nil {
		return ""
	}

	return node.Text(tree.source)
}

func (tree *rubySyntaxTree) child(node *gotreesitter.Node, field string) *gotreesitter.Node {
	if node == nil {
		return nil
	}

	return node.ChildByFieldName(field, tree.language)
}

func rubyNamedChildren(node *gotreesitter.Node) []*gotreesitter.Node {
	if node == nil {
		return nil
	}

	children := make([]*gotreesitter.Node, 0, node.NamedChildCount())
	for index := 0; index < node.NamedChildCount(); index++ {
		children = append(children, node.NamedChild(index))
	}

	return children
}

func (tree *rubySyntaxTree) constant(node *gotreesitter.Node) (string, bool) {
	if node == nil {
		return "", false
	}

	switch tree.nodeType(node) {
	case "constant":
		return tree.text(node), true
	case "scope_resolution":
		name := tree.child(node, "name")
		if tree.nodeType(name) != "constant" {
			return "", false
		}

		scope := tree.child(node, "scope")
		if scope == nil {
			return "::" + tree.text(name), true
		}

		prefix, ok := tree.constant(scope)
		if !ok {
			return "", false
		}

		return prefix + "::" + tree.text(name), true
	default:
		return "", false
	}
}

// hasOrphanEnd is required for an edge case found in the gotreesitter grammar. we might be
// able to remove it in the future if they fix the issue.
// end # orphaned: no matching opening construct
// Gem::Specification.new("orders", "1.2.3") do |spec|
// end
func (tree *rubySyntaxTree) hasOrphanEnd(node *gotreesitter.Node) bool {
	for _, child := range rubyNamedChildren(node) {
		if (tree.nodeType(node) == "program" || tree.nodeType(node) == "body_statement") &&
			tree.nodeType(child) == "identifier" && tree.text(child) == "end" {
			return true
		}

		if tree.hasOrphanEnd(child) {
			return true
		}
	}
	return false
}
