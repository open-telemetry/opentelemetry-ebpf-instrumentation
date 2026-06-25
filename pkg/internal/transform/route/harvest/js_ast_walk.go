// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"reflect"

	"github.com/dop251/goja/ast"
)

// walk performs a depth-first traversal of the AST rooted at n, invoking fn for
// every node visited (including n itself).
func walk(n ast.Node, fn func(ast.Node)) {
	if n == nil {
		return
	}
	fn(n)
	for _, c := range children(n) {
		walk(c, fn)
	}
}

// children returns the direct child nodes of n. It only needs to descend
// through the container nodes that can hold route registrations or variable
// declarations; leaf nodes return nil.
func children(n ast.Node) []ast.Node {
	switch v := n.(type) {
	case *ast.Program:
		return statements(v.Body)
	case *ast.BlockStatement:
		return statements(v.List)
	case *ast.ExpressionStatement:
		return []ast.Node{v.Expression}
	case *ast.VariableStatement:
		return bindings(v.List)
	case *ast.VariableDeclaration:
		return bindings(v.List)
	case *ast.LexicalDeclaration:
		return bindings(v.List)
	case *ast.Binding:
		return nodes(v.Initializer)
	case *ast.IfStatement:
		return nodes(v.Test, v.Consequent, v.Alternate)
	case *ast.ForStatement:
		return nodes(v.Initializer, v.Test, v.Update, v.Body)
	case *ast.ForInStatement:
		return nodes(v.Into, v.Source, v.Body)
	case *ast.ForOfStatement:
		return nodes(v.Into, v.Source, v.Body)
	case *ast.WhileStatement:
		return nodes(v.Test, v.Body)
	case *ast.DoWhileStatement:
		return nodes(v.Test, v.Body)
	case *ast.ReturnStatement:
		return nodes(v.Argument)
	case *ast.ThrowStatement:
		return nodes(v.Argument)
	case *ast.LabelledStatement:
		return nodes(v.Statement)
	case *ast.WithStatement:
		return nodes(v.Object, v.Body)
	case *ast.SwitchStatement:
		out := nodes(v.Discriminant)
		for _, c := range v.Body {
			out = append(out, c)
		}
		return out
	case *ast.CaseStatement:
		return append(nodes(v.Test), statements(v.Consequent)...)
	case *ast.TryStatement:
		out := nodes(v.Body, v.Finally)
		if v.Catch != nil {
			out = append(out, v.Catch)
		}
		return out
	case *ast.CatchStatement:
		return nodes(v.Body)
	case *ast.FunctionDeclaration:
		if v.Function != nil {
			return []ast.Node{v.Function}
		}
	case *ast.FunctionLiteral:
		return nodes(v.Body)
	case *ast.ArrowFunctionLiteral:
		return nodes(v.Body)
	case *ast.ExpressionBody:
		return nodes(v.Expression)
	case *ast.CallExpression:
		return append(nodes(v.Callee), expressions(v.ArgumentList)...)
	case *ast.NewExpression:
		return append(nodes(v.Callee), expressions(v.ArgumentList)...)
	case *ast.AssignExpression:
		return nodes(v.Left, v.Right)
	case *ast.BinaryExpression:
		return nodes(v.Left, v.Right)
	case *ast.ConditionalExpression:
		return nodes(v.Test, v.Consequent, v.Alternate)
	case *ast.SequenceExpression:
		return expressions(v.Sequence)
	case *ast.UnaryExpression:
		return nodes(v.Operand)
	case *ast.AwaitExpression:
		return nodes(v.Argument)
	case *ast.YieldExpression:
		return nodes(v.Argument)
	case *ast.DotExpression:
		return nodes(v.Left)
	case *ast.BracketExpression:
		return nodes(v.Left, v.Member)
	case *ast.TemplateLiteral:
		return expressions(v.Expressions)
	case *ast.ArrayLiteral:
		return expressions(v.Value)
	case *ast.ObjectLiteral:
		out := make([]ast.Node, 0, len(v.Value))
		for _, p := range v.Value {
			if kv, ok := p.(*ast.PropertyKeyed); ok {
				out = append(out, kv.Value)
			}
		}
		return out
	}
	return nil
}

func statements(in []ast.Statement) []ast.Node {
	out := make([]ast.Node, 0, len(in))
	for _, s := range in {
		if s != nil {
			out = append(out, s)
		}
	}
	return out
}

func expressions(in []ast.Expression) []ast.Node {
	out := make([]ast.Node, 0, len(in))
	for _, e := range in {
		if e != nil {
			out = append(out, e)
		}
	}
	return out
}

func bindings(in []*ast.Binding) []ast.Node {
	out := make([]ast.Node, 0, len(in))
	for _, b := range in {
		if b != nil {
			out = append(out, b)
		}
	}
	return out
}

// nodes builds a child slice from individual nodes, skipping nil interfaces.
func nodes(in ...ast.Node) []ast.Node {
	out := make([]ast.Node, 0, len(in))
	for _, n := range in {
		if isNil(n) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// isNil reports whether n is either an untyped nil interface or an interface
// wrapping a nil pointer, both of which goja uses for absent optional nodes.
func isNil(n ast.Node) bool {
	if n == nil {
		return true
	}
	v := reflect.ValueOf(n)
	return v.Kind() == reflect.Ptr && v.IsNil()
}
