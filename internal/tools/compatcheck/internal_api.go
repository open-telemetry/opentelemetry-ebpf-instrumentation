// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/exp/apidiff"
)

func compareInternalAPI(old, candidate map[string]*types.Package, version, platform string) []finding {
	beforeTypes := exposedInternalTypes(old)
	afterTypes := exposedInternalTypes(candidate)
	var findings []finding
	for key, before := range beforeTypes {
		after, ok := afterTypes[key]
		if !ok {
			// The public declaration or containing type reports lost reachability.
			continue
		}
		for _, change := range apidiff.Changes(internalTypeAPI(before), internalTypeAPI(after)).Changes {
			identifier, message, _ := strings.Cut(change.Message, ":")
			name := types.TypeString(before, types.RelativeTo(before.Obj().Pkg()))
			identifier = strings.Replace(identifier, "Exposed", name, 1)
			findings = append(findings, finding{
				Baseline: version, Platform: platform, Package: before.Obj().Pkg().Path(), Identifier: identifier,
				Before:  types.ObjectString(before.Obj(), types.RelativeTo(before.Obj().Pkg())),
				After:   types.ObjectString(after.Obj(), types.RelativeTo(after.Obj().Pkg())),
				Message: identifier + ":" + message, Compatible: change.Compatible, Rule: goAPIRule,
			})
		}
	}
	return findings
}

func exposedInternalTypes(roots map[string]*types.Package) map[string]*types.Named {
	result := map[string]*types.Named{}
	seen := map[types.Type]bool{}
	for _, pkg := range roots {
		for _, name := range pkg.Scope().Names() {
			obj := pkg.Scope().Lookup(name)
			if obj.Exported() {
				visitExposedType(obj.Type(), seen, result)
			}
		}
	}
	return result
}

func visitExposedType(t types.Type, seen map[types.Type]bool, result map[string]*types.Named) {
	if t == nil || seen[t] {
		return
	}
	seen[t] = true
	visit := func(t types.Type) { visitExposedType(t, seen, result) }
	switch t := t.(type) {
	case *types.Alias:
		visit(t.Rhs())
	case *types.Named:
		pkg := t.Obj().Pkg()
		if pkg == nil || (pkg.Path() != coreModule && !strings.HasPrefix(pkg.Path(), coreModule+"/")) {
			return
		}
		if internalPackage(pkg.Path()) {
			result[types.TypeString(t, nil)] = t
		}
		visit(t.Underlying())
		for param := range t.TypeParams().TypeParams() {
			visit(param)
		}
		for arg := range t.TypeArgs().Types() {
			visit(arg)
		}
		for method := range t.Methods() {
			if method.Exported() {
				visit(method.Type())
			}
		}
	case *types.Pointer:
		visit(t.Elem())
	case *types.Slice:
		visit(t.Elem())
	case *types.Array:
		visit(t.Elem())
	case *types.Chan:
		visit(t.Elem())
	case *types.Map:
		visit(t.Key())
		visit(t.Elem())
	case *types.Struct:
		for field := range t.Fields() {
			if field.Exported() || field.Embedded() {
				visit(field.Type())
			}
		}
	case *types.Signature:
		visit(t.Params())
		visit(t.Results())
		for param := range t.TypeParams().TypeParams() {
			visit(param)
		}
	case *types.Tuple:
		for v := range t.Variables() {
			visit(v.Type())
		}
	case *types.Interface:
		for method := range t.Methods() {
			if method.Exported() {
				visit(method.Type())
			}
		}
		for embedded := range t.EmbeddedTypes() {
			visit(embedded)
		}
	case *types.TypeParam:
		visit(t.Constraint())
	case *types.Union:
		for term := range t.Terms() {
			visit(term.Type())
		}
	}
}

// apidiff treats named types owned by another package as opaque. Project each
// reachable internal type into its own package without changing the loaded types.
func internalTypeAPI(t *types.Named) *types.Package {
	pkg := types.NewPackage(t.Obj().Pkg().Path(), t.Obj().Pkg().Name())
	obj := types.NewTypeName(token.NoPos, pkg, "Exposed", nil)
	named := types.NewNamed(obj, t.Underlying(), nil)
	if t.TypeArgs().Len() == 0 {
		var params []*types.TypeParam
		for param := range t.TypeParams().TypeParams() {
			params = append(params, types.NewTypeParam(types.NewTypeName(token.NoPos, pkg, param.Obj().Name(), nil), param.Constraint()))
		}
		named.SetTypeParams(params)
	}
	for method := range t.Methods() {
		sig := method.Type().(*types.Signature)
		var recvType types.Type = named
		if _, pointer := sig.Recv().Type().(*types.Pointer); pointer {
			recvType = types.NewPointer(named)
		}
		recv := types.NewVar(token.NoPos, pkg, "", recvType)
		named.AddMethod(types.NewFunc(token.NoPos, pkg, method.Name(),
			types.NewSignatureType(recv, nil, nil, sig.Params(), sig.Results(), sig.Variadic())))
	}
	pkg.Scope().Insert(obj)
	return pkg
}
