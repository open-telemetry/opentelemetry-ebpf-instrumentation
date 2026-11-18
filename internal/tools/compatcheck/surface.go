// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"fmt"
	"go/token"
	"go/types"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// apidiff follows correspondence within one package. Compare public module
// declarations together so aliases and exposed types share that correspondence.
// Private members retain their original package identities.
type apiSurface struct {
	pkg       *types.Package
	source    *apiSnapshot
	roots     map[string]*types.Package
	types     map[types.Type]types.Type
	named     map[string]*types.Named
	originals map[string]types.Object
	context   *types.Context
	ifaces    []*types.Interface
	owner     types.Object
	anonymous map[*types.Interface]types.Object
}

func newAPISurface(api *apiSnapshot) *apiSurface {
	roots := api.Packages
	s := &apiSurface{
		pkg: types.NewPackage(coreModule, "obi"), roots: roots, source: api,
		named: map[string]*types.Named{}, types: map[types.Type]types.Type{},
		originals: map[string]types.Object{}, context: types.NewContext(),
		anonymous: map[*types.Interface]types.Object{},
	}
	// Generated C layouts are outside this comparison, including through aliases
	// and handwritten types defined from those layouts. Erase them before apidiff
	// so padding and comparability changes cannot leak through public wrappers.
	for obj := range api.BPFGenerated {
		if name, ok := obj.(*types.TypeName); ok {
			t := types.Unalias(name.Type())
			opaque := types.NewStruct(nil, nil)
			s.types[t] = opaque
			switch underlying := t.Underlying().(type) {
			case *types.Struct, *types.Array:
				s.types[underlying] = opaque
			}
		}
	}
	for _, path := range slices.Sorted(maps.Keys(roots)) {
		pkg := roots[path]
		for _, name := range pkg.Scope().Names() {
			obj := pkg.Scope().Lookup(name)
			if !obj.Exported() || api.BPFGenerated[obj] {
				continue
			}
			var projected types.Object
			id := s.name(obj)
			s.owner = obj
			switch obj := obj.(type) {
			case *types.TypeName:
				t := s.typ(obj.Type())
				if named, ok := t.(*types.Named); ok && named.Obj().Name() == id {
					projected = named.Obj()
				} else {
					alias := types.NewTypeName(token.NoPos, s.pkg, id, nil)
					a := types.NewAlias(alias, t)
					if original, ok := obj.Type().(*types.Alias); ok {
						a.SetTypeParams(s.params(original.TypeParams()))
					}
					projected = alias
					if named, ok := types.Unalias(t).(*types.Named); ok {
						s.named[id] = named
					}
				}
			case *types.Const:
				projected = types.NewConst(token.NoPos, s.pkg, id, s.typ(obj.Type()), obj.Val())
			case *types.Var:
				projected = types.NewVar(token.NoPos, s.pkg, id, s.typ(obj.Type()))
			case *types.Func:
				projected = types.NewFunc(token.NoPos, s.pkg, id, s.typ(obj.Type()).(*types.Signature))
			}
			s.pkg.Scope().Insert(projected)
		}
	}
	for _, iface := range s.ifaces {
		iface.Complete()
	}
	return s
}

func (s *apiSurface) name(obj types.Object) string {
	prefix := "p"
	if s.roots[obj.Pkg().Path()] != nil && obj.Exported() {
		prefix = "P"
	}
	digest := sha256.Sum256([]byte(obj.Pkg().Path()))
	name := fmt.Sprintf("%s%x_%s", prefix, digest[:8], obj.Name())
	if s.originals[name] == nil {
		s.originals[name] = obj
	}
	return name
}

func (s *apiSurface) params(list *types.TypeParamList) []*types.TypeParam {
	var result []*types.TypeParam
	for param := range list.TypeParams() {
		result = append(result, s.typ(param).(*types.TypeParam))
	}
	return result
}

func (s *apiSurface) variable(v *types.Var) *types.Var {
	if v == nil {
		return nil
	}
	return types.NewVar(token.NoPos, v.Pkg(), v.Name(), s.typ(v.Type()))
}

func (s *apiSurface) method(f *types.Func) *types.Func {
	name := f.Name()
	if !f.Exported() {
		name = s.name(f)
	}
	return types.NewFunc(token.NoPos, s.pkg, name, s.typ(f.Type()).(*types.Signature))
}

func (s *apiSurface) typ(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	t = types.Unalias(t)
	if previous, ok := s.types[t]; ok {
		return previous
	}
	var result types.Type
	switch t := t.(type) {
	case *types.Basic:
		return t
	case *types.Named:
		if t.Obj().Pkg() == nil {
			return t
		}
		if t != t.Origin() {
			var args []types.Type
			for arg := range t.TypeArgs().Types() {
				args = append(args, s.typ(arg))
			}
			instance, err := types.Instantiate(s.context, s.typ(t.Origin()), args, false)
			if err != nil {
				panic(err)
			}
			result = instance
			break
		}
		id := s.name(t.Obj())
		if named := s.named[id]; named != nil {
			s.types[t] = named
			return named
		}
		obj := types.NewTypeName(token.NoPos, s.pkg, id, nil)
		named := types.NewNamed(obj, nil, nil)
		s.named[id] = named
		s.types[t] = named
		// Bind parameters before traversing recursive generic types.
		var params []*types.TypeParam
		for param := range t.TypeParams().TypeParams() {
			p := types.NewTypeParam(types.NewTypeName(token.NoPos, s.pkg, fmt.Sprintf("T%d", param.Index()), nil), nil)
			s.types[param] = p
			params = append(params, p)
		}
		named.SetTypeParams(params)
		previousOwner := s.owner
		s.owner = t.Obj()
		defer func() { s.owner = previousOwner }()
		for i, param := range params {
			param.SetConstraint(s.typ(t.TypeParams().At(i).Constraint()))
		}
		named.SetUnderlying(s.typ(t.Underlying()))
		for method := range t.Methods() {
			named.AddMethod(s.method(method))
		}
		return named
	case *types.TypeParam:
		param := types.NewTypeParam(types.NewTypeName(token.NoPos, s.pkg, fmt.Sprintf("T%d", t.Index()), nil), nil)
		s.types[t] = param
		param.SetConstraint(s.typ(t.Constraint()))
		return param
	case *types.Pointer:
		result = types.NewPointer(s.typ(t.Elem()))
	case *types.Slice:
		result = types.NewSlice(s.typ(t.Elem()))
	case *types.Array:
		result = types.NewArray(s.typ(t.Elem()), t.Len())
	case *types.Map:
		result = types.NewMap(s.typ(t.Key()), s.typ(t.Elem()))
	case *types.Chan:
		result = types.NewChan(t.Dir(), s.typ(t.Elem()))
	case *types.Struct:
		var fields []*types.Var
		var tags []string
		for i := range t.NumFields() {
			field := t.Field(i)
			fields = append(fields, types.NewField(token.NoPos, field.Pkg(), field.Name(), s.typ(field.Type()), field.Embedded()))
			tags = append(tags, t.Tag(i))
		}
		result = types.NewStruct(fields, tags)
	case *types.Tuple:
		var vars []*types.Var
		for v := range t.Variables() {
			vars = append(vars, s.variable(v))
		}
		result = types.NewTuple(vars...)
	case *types.Signature:
		params, recvParams := s.params(t.TypeParams()), s.params(t.RecvTypeParams())
		result = types.NewSignatureType(s.variable(t.Recv()), recvParams, params, s.typ(t.Params()).(*types.Tuple), s.typ(t.Results()).(*types.Tuple), t.Variadic())
	case *types.Interface:
		var methods []*types.Func
		for method := range t.ExplicitMethods() {
			sig := method.Type().(*types.Signature)
			name := method.Name()
			if !method.Exported() {
				name = s.name(method)
			}
			var recv *types.Var
			if sig.Recv() != nil && sig.Recv().Type() != t {
				recv = s.variable(sig.Recv())
			}
			methods = append(methods, types.NewFunc(token.NoPos, s.pkg, name, types.NewSignatureType(recv, nil, nil, s.typ(sig.Params()).(*types.Tuple), s.typ(sig.Results()).(*types.Tuple), sig.Variadic())))
		}
		var embedded []types.Type
		for e := range t.EmbeddedTypes() {
			embedded = append(embedded, s.typ(e))
		}
		iface := types.NewInterfaceType(methods, embedded)
		if t.IsImplicit() {
			iface.MarkImplicit()
		}
		s.ifaces = append(s.ifaces, iface)
		s.anonymous[iface] = s.owner
		result = iface
	case *types.Union:
		var terms []*types.Term
		for term := range t.Terms() {
			terms = append(terms, types.NewTerm(term.Tilde(), s.typ(term.Type())))
		}
		result = types.NewUnion(terms)
	default:
		panic(fmt.Sprintf("unsupported API type %T", t))
	}
	s.types[t] = result
	return result
}

var surfaceName = regexp.MustCompile(`[Pp][0-9a-f]{16}_[\pL_][\pL\pN_]*`)

func (s *apiSurface) describe(text string) string {
	return surfaceName.ReplaceAllStringFunc(text, func(name string) string {
		if obj := s.originals[name]; obj != nil {
			return obj.Pkg().Path() + "." + obj.Name()
		}
		return name
	})
}

func (s *apiSurface) object(identifier string) types.Object {
	root := strings.TrimLeft(identifier, "(*")
	root, _, _ = strings.Cut(root, ".")
	root, _, _ = strings.Cut(root, "[")
	if obj := s.originals[strings.TrimRight(root, ")")]; obj != nil {
		return obj
	}
	var owner types.Object
	for iface, obj := range s.anonymous {
		if obj != nil && strings.HasPrefix(identifier, types.TypeString(iface, types.RelativeTo(s.pkg))+".") {
			if owner == nil || obj.Pkg().Path()+"."+obj.Name() < owner.Pkg().Path()+"."+owner.Name() {
				owner = obj
			}
		}
	}
	return owner
}
