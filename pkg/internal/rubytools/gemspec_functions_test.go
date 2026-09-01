// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

import (
	"testing"

	"github.com/odvcencio/gotreesitter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGemspec(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   serviceMetadata
	}{
		{
			name: "static identity",
			source: `Gem::Specification.new do |spec|
  spec.name = "orders"
  spec.version = "1.2.3"
end`,
			want: serviceMetadata{Name: "orders", Version: "1.2.3"},
		},
		{
			name: "invalid syntax",
			source: `Gem::Specification.new do |spec|
  spec.name = "orders"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, parseGemspec([]byte(test.source)))
		})
	}
}

func TestGemspecConstructors(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   int
	}{
		{
			name:   "no constructors",
			source: `Other::Specification.new`,
		},
		{
			name:   "top-level constructor",
			source: `Gem::Specification.new`,
			want:   1,
		},
		{
			name: "constructors at different depths",
			source: `if enabled
  Gem::Specification.new
end
::Gem::Specification.new`,
			want: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := parseRubyTestTree(t, test.source)
			assert.Len(t, gemspecConstructors(tree), test.want)
		})
	}
}

func TestIsGemspecConstructor(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "constant receiver", source: `Gem::Specification.new`, want: true},
		{name: "root-qualified receiver", source: `::Gem::Specification.new`, want: true},
		{name: "wrong receiver", source: `Other::Specification.new`},
		{name: "wrong method", source: `Gem::Specification.build`},
		{name: "safe navigation operator", source: `Gem::Specification&.new`},
		{name: "not a call", source: `Gem::Specification`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := parseRubyTestTree(t, test.source)
			node := requireSingleRubyStatement(t, tree)
			assert.Equal(t, test.want, isGemspecConstructor(tree, node))
		})
	}

	tree := parseRubyTestTree(t, "nil")
	assert.False(t, isGemspecConstructor(tree, nil))
}

func TestTopLevelFinalExpression(t *testing.T) {
	t.Run("final top-level expression", func(t *testing.T) {
		tree := parseRubyTestTree(t, `PRELUDE = true
Gem::Specification.new`)
		constructor := requireSingleGemspecConstructor(t, tree)

		assert.True(t, topLevelFinalExpression(tree, constructor))
	})

	t.Run("followed by another expression", func(t *testing.T) {
		tree := parseRubyTestTree(t, `Gem::Specification.new
nil`)
		constructor := requireSingleGemspecConstructor(t, tree)

		assert.False(t, topLevelFinalExpression(tree, constructor))
	})

	t.Run("nested expression", func(t *testing.T) {
		tree := parseRubyTestTree(t, `if enabled
  Gem::Specification.new
end`)
		constructor := requireSingleGemspecConstructor(t, tree)

		assert.False(t, topLevelFinalExpression(tree, constructor))
	})

	t.Run("no executable expressions", func(t *testing.T) {
		tree := parseRubyTestTree(t, "# comment")

		assert.False(t, topLevelFinalExpression(tree, nil))
	})
}

func TestRubyExecutableChildren(t *testing.T) {
	tree := parseRubyTestTree(t, `# comment
run
__END__
ignored`)

	children := rubyExecutableChildren(tree, tree.root())
	require.Len(t, children, 1)
	assert.Equal(t, "run", tree.text(children[0]))
	assert.Nil(t, rubyExecutableChildren(tree, nil))
}

func TestGemspecBlockVariable(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
		ok     bool
	}{
		{name: "one identifier", source: `Gem::Specification.new do |spec|
end`, want: "spec", ok: true},
		{name: "no parameters", source: `Gem::Specification.new do
end`},
		{name: "multiple parameters", source: `Gem::Specification.new do |spec, other|
end`},
		{name: "non-identifier parameter", source: `Gem::Specification.new do |*spec|
end`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := parseRubyTestTree(t, test.source)
			constructor := requireSingleGemspecConstructor(t, tree)
			block := tree.child(constructor, "block")

			got, ok := gemspecBlockVariable(tree, block)
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.want, got)
		})
	}

	tree := parseRubyTestTree(t, "nil")
	name, ok := gemspecBlockVariable(tree, nil)
	assert.False(t, ok)
	assert.Empty(t, name)
}

func TestDirectGemspecAssignment(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		wantField string
		wantValue string
		want      bool
	}{
		{name: "name", statement: `spec.name = "orders"`, wantField: "name", wantValue: `"orders"`, want: true},
		{name: "version", statement: `spec.version = "1.2.3"`, wantField: "version", wantValue: `"1.2.3"`, want: true},
		{name: "different variable", statement: `other.name = "orders"`},
		{name: "unrelated field", statement: `spec.summary = "Orders"`},
		{name: "spaced reference", statement: `spec .name = "orders"`},
		{name: "not an assignment", statement: `spec.name`},
		{name: "operator assignment", statement: `spec.name ||= "orders"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree, statement := parseGemspecStatement(t, test.statement)

			field, value, reference, ok := directGemspecAssignment(tree, statement, "spec")
			assert.Equal(t, test.want, ok)
			assert.Equal(t, test.wantField, field)
			if !test.want {
				assert.Nil(t, value)
				assert.Nil(t, reference)
				return
			}
			assert.Equal(t, test.wantValue, tree.text(value))
			assert.Equal(t, "spec."+test.wantField, tree.text(reference))
		})
	}
}

func TestHasUnexpectedGemspecIdentityReference(t *testing.T) {
	t.Run("nil node", func(t *testing.T) {
		tree := parseRubyTestTree(t, "nil")
		assert.False(t, hasUnexpectedGemspecIdentityReference(tree, nil, "spec", nil))
	})

	t.Run("allowed direct assignment", func(t *testing.T) {
		tree, statement := parseGemspecStatement(t, `spec.name = "orders"`)
		_, _, reference, ok := directGemspecAssignment(tree, statement, "spec")
		require.True(t, ok)

		allowed := map[*gotreesitter.Node]struct{}{reference: {}}
		assert.False(t, hasUnexpectedGemspecIdentityReference(tree, statement, "spec", allowed))
	})

	t.Run("unlisted direct assignment", func(t *testing.T) {
		tree, statement := parseGemspecStatement(t, `spec.name = "orders"`)

		assert.True(t, hasUnexpectedGemspecIdentityReference(tree, statement, "spec", nil))
	})

	t.Run("nested identity reference", func(t *testing.T) {
		tree, statement := parseGemspecStatement(t, `consume(spec.version)`)

		assert.True(t, hasUnexpectedGemspecIdentityReference(tree, statement, "spec", nil))
	})

	t.Run("different receiver", func(t *testing.T) {
		tree, statement := parseGemspecStatement(t, `consume(other.name)`)

		assert.False(t, hasUnexpectedGemspecIdentityReference(tree, statement, "spec", nil))
	})
}

func TestGemspecIdentityReference(t *testing.T) {
	tests := []struct {
		name   string
		source string
		field  string
		want   bool
	}{
		{name: "name", source: `spec.name`, field: "name", want: true},
		{name: "version", source: `spec.version`, field: "version", want: true},
		{name: "parenthesized receiver", source: `(spec).name`, field: "name", want: true},
		{name: "safe navigation", source: `spec&.name`, field: "name", want: true},
		{name: "unrelated field", source: `spec.summary`, field: "summary"},
		{name: "different receiver", source: `other.name`},
		{name: "not a call", source: `spec`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := parseRubyTestTree(t, test.source)
			node := requireSingleRubyStatement(t, tree)

			field, ok := gemspecIdentityReference(tree, node, "spec")
			assert.Equal(t, test.want, ok)
			assert.Equal(t, test.field, field)
		})
	}

	tree := parseRubyTestTree(t, "nil")
	field, ok := gemspecIdentityReference(tree, nil, "spec")
	assert.False(t, ok)
	assert.Empty(t, field)
}

func TestRubyVariableReceiver(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "identifier", source: `spec.name`, want: true},
		{name: "different identifier", source: `other.name`},
		{name: "parenthesized identifier", source: `(spec).name`, want: true},
		{name: "nested parentheses", source: `((spec)).name`, want: true},
		{name: "multiple parenthesized expressions", source: `(spec; other).name`},
		{name: "non-identifier", source: `"spec".name`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := parseRubyTestTree(t, test.source)
			call := requireSingleRubyStatement(t, tree)
			receiver := tree.child(call, "receiver")

			assert.Equal(t, test.want, rubyVariableReceiver(tree, receiver, "spec"))
		})
	}

	tree := parseRubyTestTree(t, "nil")
	assert.False(t, rubyVariableReceiver(tree, nil, "spec"))
}

func TestStaticRubyString(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
		ok     bool
	}{
		{name: "double quoted", source: `"orders"`, want: "orders", ok: true},
		{name: "single quoted", source: `'orders'`, want: "orders", ok: true},
		{name: "empty", source: `""`, ok: true},
		{name: "frozen", source: `"orders".freeze`, want: "orders", ok: true},
		{name: "freeze with arguments", source: `"orders".freeze()`},
		{name: "chained freeze", source: `"orders".freeze.freeze`},
		{name: "interpolated", source: `"orders#{suffix}"`},
		{name: "escaped", source: `"orders\-api"`},
		{name: "percent literal", source: `%q{orders}`},
		{name: "constant", source: `Orders::NAME`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := parseRubyTestTree(t, test.source)
			node := requireSingleRubyStatement(t, tree)

			got, ok := staticRubyString(tree, node)
			assert.Equal(t, test.ok, ok)
			assert.Equal(t, test.want, got)
		})
	}

	tree := parseRubyTestTree(t, "nil")
	value, ok := staticRubyString(tree, nil)
	assert.False(t, ok)
	assert.Empty(t, value)
}

func TestStandaloneRubyStatement(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "only statement", source: `spec.name = "orders"`, want: true},
		{name: "indented statement", source: `  spec.name = "orders"`, want: true},
		{name: "trailing comment", source: `spec.name = "orders" # identity`, want: true},
		{name: "previous line is ignored", source: "log\nspec.name = \"orders\"", want: true},
		{name: "preceded on same line", source: `log; spec.name = "orders"`},
		{name: "followed on same line", source: `spec.name = "orders"; log`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := parseRubyTestTree(t, test.source)
			assignment := firstRubyTestNode(tree, tree.root(), "assignment")
			require.NotNil(t, assignment)

			assert.Equal(t, test.want, standaloneRubyStatement(tree.source, assignment))
		})
	}
}

func TestValidGemName(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "letters", value: "orders", want: true},
		{name: "supported punctuation", value: "Orders.api-v2", want: true},
		{name: "trailing punctuation", value: "orders._-", want: true},
		{name: "empty"},
		{name: "numeric only", value: "123"},
		{name: "leading dot", value: ".orders"},
		{name: "leading dash", value: "-orders"},
		{name: "leading underscore", value: "_orders"},
		{name: "space", value: "orders api"},
		{name: "slash", value: "orders/api"},
		{name: "non-ASCII", value: "café"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, validGemName(test.value))
		})
	}
}

func TestValidGemVersion(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "integer", value: "1", want: true},
		{name: "semantic version", value: "1.2.3", want: true},
		{name: "prerelease segments", value: "1.2.3.pre.1", want: true},
		{name: "dash prerelease", value: "1.2.3-rc.1", want: true},
		{name: "empty"},
		{name: "leading v", value: "v1.2.3"},
		{name: "leading dot", value: ".1"},
		{name: "trailing dot", value: "1."},
		{name: "empty segment", value: "1..2"},
		{name: "build metadata", value: "1.2.3+build"},
		{name: "non-ASCII digits", value: "١.٢.٣"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, validGemVersion(test.value))
		})
	}
}

func parseRubyTestTree(t *testing.T, source string) *rubySyntaxTree {
	t.Helper()

	tree := parseRubyTree([]byte(source))
	require.NotNil(t, tree)
	t.Cleanup(tree.release)
	return tree
}

func requireSingleRubyStatement(t *testing.T, tree *rubySyntaxTree) *gotreesitter.Node {
	t.Helper()

	statements := rubyExecutableChildren(tree, tree.root())
	require.Len(t, statements, 1)
	return statements[0]
}

func requireSingleGemspecConstructor(t *testing.T, tree *rubySyntaxTree) *gotreesitter.Node {
	t.Helper()

	constructors := gemspecConstructors(tree)
	require.Len(t, constructors, 1)
	return constructors[0]
}

func parseGemspecStatement(t *testing.T, statement string) (*rubySyntaxTree, *gotreesitter.Node) {
	t.Helper()

	tree := parseRubyTestTree(t, "Gem::Specification.new do |spec|\n  "+statement+"\nend")
	constructor := requireSingleGemspecConstructor(t, tree)
	body := tree.child(tree.child(constructor, "block"), "body")
	statements := rubyExecutableChildren(tree, body)
	require.Len(t, statements, 1)
	return tree, statements[0]
}

func firstRubyTestNode(
	tree *rubySyntaxTree,
	node *gotreesitter.Node,
	nodeType string,
) *gotreesitter.Node {
	if tree.nodeType(node) == nodeType {
		return node
	}

	for _, child := range rubyNamedChildren(node) {
		if result := firstRubyTestNode(tree, child, nodeType); result != nil {
			return result
		}
	}
	return nil
}
