// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package collectt detects incorrect use of *testing.T inside EventuallyWithT callbacks.
package collectt // import "go.opentelemetry.io/obi/internal/test/analyzer/collectt"

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var Analyzer = &analysis.Analyzer{
	Name:     "collectt",
	Doc:      "checks that EventuallyWithT callbacks use *assert.CollectT, not *testing.T, for assertions",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// Look for call expressions only.
	nodeFilter := []ast.Node{(*ast.CallExpr)(nil)}

	insp.Preorder(nodeFilter, func(n ast.Node) {
		call := n.(*ast.CallExpr)

		// Match *.EventuallyWithT(t, func(ct *assert.CollectT) { ... }, ...)
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "EventuallyWithT" {
			return
		}

		// Need at least 2 args: the testing.T and the callback.
		if len(call.Args) < 2 {
			return
		}

		// The first argument should be the outer *testing.T.
		outerT := call.Args[0]
		outerTObj := resolveIdentFromInfo(pass, outerT)
		if outerTObj == nil {
			return
		}

		// The second argument should be a function literal.
		funcLit, ok := call.Args[1].(*ast.FuncLit)
		if !ok {
			return
		}

		// The function literal's first parameter is the *assert.CollectT.
		if funcLit.Type.Params == nil || len(funcLit.Type.Params.List) == 0 {
			return
		}
		collectTParam := funcLit.Type.Params.List[0]
		if len(collectTParam.Names) == 0 {
			return
		}
		collectTObj := pass.TypesInfo.ObjectOf(collectTParam.Names[0])
		if collectTObj == nil {
			return
		}

		// Walk the callback body looking for assert/require calls whose
		// first argument is the outer *testing.T instead of the CollectT param.
		ast.Inspect(funcLit.Body, func(n ast.Node) bool {
			innerCall, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			innerSel, ok := innerCall.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			// Check the receiver is an assert or require package.
			if !isAssertOrRequire(pass, innerSel) {
				return true
			}

			// The first argument to assert/require methods is the TestingT.
			if len(innerCall.Args) == 0 {
				return true
			}

			argObj := resolveIdentFromInfo(pass, innerCall.Args[0])
			if argObj == nil {
				return true
			}

			// Flag if the first arg resolves to the outer *testing.T
			// rather than the callback's *assert.CollectT parameter.
			if argObj == outerTObj && argObj != collectTObj {
				pass.Reportf(innerCall.Args[0].Pos(),
					"use %s instead of %s inside EventuallyWithT callback",
					collectTParam.Names[0].Name,
					outerT.(*ast.Ident).Name,
				)
			}

			return true
		})
	})

	return nil, nil
}

// resolveIdentFromInfo looks up the types.Object for an expression via TypesInfo.
func resolveIdentFromInfo(pass *analysis.Pass, expr ast.Expr) types.Object {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return nil
	}
	return pass.TypesInfo.ObjectOf(ident)
}

// isAssertOrRequire checks whether a selector expression refers to a
// testify assert or require package function.
func isAssertOrRequire(pass *analysis.Pass, sel *ast.SelectorExpr) bool {
	// Package-level call: assert.Equal(ct, ...) or require.Len(ct, ...)
	if ident, ok := sel.X.(*ast.Ident); ok {
		if obj := pass.TypesInfo.ObjectOf(ident); obj != nil {
			if pkgName, ok := obj.(*types.PkgName); ok {
				path := pkgName.Imported().Path()
				return path == "github.com/stretchr/testify/assert" ||
					path == "github.com/stretchr/testify/require"
			}
		}
	}
	return false
}
