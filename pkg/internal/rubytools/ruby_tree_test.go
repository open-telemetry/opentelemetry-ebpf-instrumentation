// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

import (
	"testing"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRubyTree(t *testing.T) {
	t.Run("accepts valid ruby", func(t *testing.T) {
		tree := parseRubyTree([]byte("module Outer\n  class Inner\n  end\nend\n"))
		require.NotNil(t, tree)
		assert.NotNil(t, tree.root())
		assert.Equal(t, "program", tree.nodeType(tree.root()))
		t.Cleanup(tree.release)
	})

	t.Run("rejects orphaned end", func(t *testing.T) {
		assert.Nil(t, parseRubyTree([]byte("end\n")))
	})
}

func TestRubySyntaxTreeHelpers(t *testing.T) {
	tree := parseRubyTree([]byte("module A::B\nend\n"))
	require.NotNil(t, tree)
	t.Cleanup(tree.release)

	assert.Empty(t, tree.nodeType(nil))
	assert.Empty(t, tree.text(nil))

	root := tree.root()
	require.NotNil(t, root)
	assert.Equal(t, "program", tree.nodeType(root))
	assert.Equal(t, "module A::B\nend\n", tree.text(root))

	moduleNode := root.NamedChild(0)
	require.NotNil(t, moduleNode)
	assert.Equal(t, "module", tree.nodeType(moduleNode))

	scope := tree.child(moduleNode, "name")
	require.NotNil(t, scope)
	assert.Equal(t, "scope_resolution", tree.nodeType(scope))
	assert.Equal(t, "A::B", tree.text(scope))

	name := tree.child(scope, "name")
	require.NotNil(t, name)
	assert.Equal(t, "constant", tree.nodeType(name))
	assert.Equal(t, "B", tree.text(name))
}

func TestRubyNamedChildren(t *testing.T) {
	t.Run("nil node returns nil", func(t *testing.T) {
		assert.Nil(t, rubyNamedChildren(nil))
	})

	t.Run("returns only named children", func(t *testing.T) {
		tree := parseRubyTree([]byte("module A::B\n  run\nend\n"))
		require.NotNil(t, tree)
		t.Cleanup(tree.release)

		moduleNode := tree.root().NamedChild(0)
		require.NotNil(t, moduleNode)
		children := rubyNamedChildren(moduleNode)
		require.Len(t, children, 2)
		assert.Equal(t, "scope_resolution", tree.nodeType(children[0]))
		assert.Equal(t, "body_statement", tree.nodeType(children[1]))
	})
}

func TestRubySyntaxTreeConstant(t *testing.T) {
	tree := parseRubyTree([]byte("module A::B\nend\n"))
	require.NotNil(t, tree)
	t.Cleanup(tree.release)

	moduleNode := tree.root().NamedChild(0)
	require.NotNil(t, moduleNode)

	name, ok := tree.constant(nil)
	assert.Empty(t, name)
	assert.False(t, ok)

	scope := tree.child(moduleNode, "name")
	require.NotNil(t, scope)

	resolved, ok := tree.constant(scope)
	assert.True(t, ok)
	assert.Equal(t, "A::B", resolved)

	leaf, ok := tree.constant(tree.child(scope, "name"))
	assert.True(t, ok)
	assert.Equal(t, "B", leaf)

	invalid, ok := tree.constant(tree.root())
	assert.Empty(t, invalid)
	assert.False(t, ok)
}

func TestRubySyntaxTreeHasOrphanEnd(t *testing.T) {
	t.Run("valid tree is clean", func(t *testing.T) {
		tree := parseRubyTree([]byte("module A\nend\n"))
		require.NotNil(t, tree)
		t.Cleanup(tree.release)
		assert.False(t, tree.hasOrphanEnd(tree.root()))
	})

	t.Run("orphan end is detected", func(t *testing.T) {
		language := grammars.RubyLanguage()
		parsed, err := gotreesitter.NewParser(language).ParseStrict([]byte("end\n"))
		require.NoError(t, err)
		require.NotNil(t, parsed)
		t.Cleanup(parsed.Release)

		syntax := &rubySyntaxTree{source: []byte("end\n"), language: language, tree: parsed}
		assert.True(t, syntax.hasOrphanEnd(syntax.root()))
	})
}
