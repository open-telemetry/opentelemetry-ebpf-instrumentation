// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"io"
	"regexp"
	"strings"

	"github.com/odvcencio/gotreesitter"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

var (
	acronymBoundary = regexp.MustCompile(`([A-Z\d]+)([A-Z][a-z])`)
	wordBoundary    = regexp.MustCompile(`([a-z\d])([A-Z])`)
)

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

// parseRailsApplicationName extracts "orders" from a declaration such as:
//
//	module Orders
//	  class Application < Rails::Application
//	  end
//	end
func parseRailsApplicationName(data []byte) string {
	tree := parseRubyTree(data)
	if tree == nil {
		return ""
	}
	defer tree.release()

	scan := railsApplicationScan{}
	scanRailsApplication(tree, tree.root(), "", false, &scan)
	if scan.ambiguous || len(scan.candidates) != 1 {
		return ""
	}
	return railsServiceName(scan.candidates[0])
}

type railsApplicationScan struct {
	candidates []string
	ambiguous  bool
}

func scanRailsApplication(
	tree *rubySyntaxTree,
	node *gotreesitter.Node,
	namespace string,
	dynamic bool,
	scan *railsApplicationScan,
) {
	if node == nil || scan.ambiguous {
		return
	}

	switch tree.nodeType(node) {
	case "program", "body_statement":
		for _, child := range rubyNamedChildren(node) {
			scanRailsApplication(tree, child, namespace, dynamic, scan)
		}
	case "module":
		name, ok := tree.constant(tree.child(node, "name"))
		if !ok || ambiguousQualifiedConstant(name, namespace) {
			scan.ambiguous = true
			return
		}

		qualified := qualifiedRubyConstant(name, namespace)
		scanRailsApplication(tree, tree.child(node, "body"), qualified, dynamic, scan)
	case "class":
		name, nameOK := tree.constant(tree.child(node, "name"))
		superclass, superclassOK := railsSuperclass(tree, tree.child(node, "superclass"))
		if superclassOK && strings.TrimPrefix(superclass, "::") == "Rails::Application" {
			if dynamic || !nameOK || ambiguousQualifiedConstant(name, namespace) {
				scan.ambiguous = true
				return
			}
			scan.candidates = append(scan.candidates, qualifiedRubyConstant(name, namespace))
		} else if superclassOK && strings.Contains(superclass, "Rails::Application") {
			scan.ambiguous = true
			return
		}

		scanRailsApplication(tree, tree.child(node, "body"), namespace, true, scan)
	default:
		for _, child := range rubyNamedChildren(node) {
			scanRailsApplication(tree, child, namespace, true, scan)
		}
	}
}

func railsSuperclass(tree *rubySyntaxTree, superclass *gotreesitter.Node) (string, bool) {
	children := rubyNamedChildren(superclass)
	if len(children) != 1 {
		return "", false
	}
	return tree.constant(children[0])
}

func ambiguousQualifiedConstant(name, enclosing string) bool {
	return enclosing != "" && !strings.HasPrefix(name, "::") && strings.Contains(name, "::")
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
