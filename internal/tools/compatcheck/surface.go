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

func newAPISurface(api *apiSnapshot) (*apiSurface, error) {
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
			id := s.name(obj)
			s.owner = obj
			t, err := s.typ(obj.Type())
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", path, obj.Name(), err)
			}
			var projected types.Object
			switch obj := obj.(type) {
			case *types.TypeName:
				if named, ok := t.(*types.Named); ok && named.Obj().Name() == id {
					projected = named.Obj()
				} else {
					alias := types.NewTypeName(token.NoPos, s.pkg, id, nil)
					a := types.NewAlias(alias, t)
					if original, ok := obj.Type().(*types.Alias); ok {
						params, err := s.params(original.TypeParams())
						if err != nil {
							return nil, fmt.Errorf("%s.%s: %w", path, obj.Name(), err)
						}
						a.SetTypeParams(params)
					}
					projected = alias
					if named, ok := types.Unalias(t).(*types.Named); ok {
						s.named[id] = named
					}
				}
			case *types.Const:
				projected = types.NewConst(token.NoPos, s.pkg, id, t, obj.Val())
			case *types.Var:
				projected = types.NewVar(token.NoPos, s.pkg, id, t)
			case *types.Func:
				projected = types.NewFunc(token.NoPos, s.pkg, id, t.(*types.Signature))
			}
			s.pkg.Scope().Insert(projected)
		}
	}
	for _, iface := range s.ifaces {
		iface.Complete()
	}
	return s, nil
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

func (s *apiSurface) params(list *types.TypeParamList) ([]*types.TypeParam, error) {
	var result []*types.TypeParam
	for param := range list.TypeParams() {
		t, err := s.typ(param)
		if err != nil {
			return nil, err
		}
		result = append(result, t.(*types.TypeParam))
	}
	return result, nil
}

func (s *apiSurface) variable(v *types.Var) (*types.Var, error) {
	if v == nil {
		return nil, nil
	}
	t, err := s.typ(v.Type())
	if err != nil {
		return nil, err
	}
	return types.NewVar(token.NoPos, v.Pkg(), v.Name(), t), nil
}

func (s *apiSurface) method(f *types.Func) (*types.Func, error) {
	name := f.Name()
	if !f.Exported() {
		name = s.name(f)
	}
	t, err := s.typ(f.Type())
	if err != nil {
		return nil, err
	}
	return types.NewFunc(token.NoPos, s.pkg, name, t.(*types.Signature)), nil
}

func (s *apiSurface) typ(t types.Type) (types.Type, error) {
	if t == nil {
		return nil, nil
	}
	t = types.Unalias(t)
	if previous, ok := s.types[t]; ok {
		return previous, nil
	}
	var result types.Type
	switch t := t.(type) {
	case *types.Basic:
		return t, nil
	case *types.Named:
		if t.Obj().Pkg() == nil {
			return t, nil
		}
		if t != t.Origin() {
			var args []types.Type
			for arg := range t.TypeArgs().Types() {
				projected, err := s.typ(arg)
				if err != nil {
					return nil, err
				}
				args = append(args, projected)
			}
			origin, err := s.typ(t.Origin())
			if err != nil {
				return nil, err
			}
			instance, err := types.Instantiate(s.context, origin, args, false)
			if err != nil {
				return nil, fmt.Errorf("instantiate %s: %w", t.Obj().Name(), err)
			}
			result = instance
			break
		}
		id := s.name(t.Obj())
		if named := s.named[id]; named != nil {
			s.types[t] = named
			return named, nil
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
			constraint, err := s.typ(t.TypeParams().At(i).Constraint())
			if err != nil {
				return nil, err
			}
			param.SetConstraint(constraint)
		}
		underlying, err := s.typ(t.Underlying())
		if err != nil {
			return nil, err
		}
		named.SetUnderlying(underlying)
		for method := range t.Methods() {
			projected, err := s.method(method)
			if err != nil {
				return nil, err
			}
			named.AddMethod(projected)
		}
		return named, nil
	case *types.TypeParam:
		param := types.NewTypeParam(types.NewTypeName(token.NoPos, s.pkg, fmt.Sprintf("T%d", t.Index()), nil), nil)
		s.types[t] = param
		constraint, err := s.typ(t.Constraint())
		if err != nil {
			return nil, err
		}
		param.SetConstraint(constraint)
		return param, nil
	case *types.Pointer:
		elem, err := s.typ(t.Elem())
		if err != nil {
			return nil, err
		}
		result = types.NewPointer(elem)
	case *types.Slice:
		elem, err := s.typ(t.Elem())
		if err != nil {
			return nil, err
		}
		result = types.NewSlice(elem)
	case *types.Array:
		elem, err := s.typ(t.Elem())
		if err != nil {
			return nil, err
		}
		result = types.NewArray(elem, t.Len())
	case *types.Map:
		key, err := s.typ(t.Key())
		if err != nil {
			return nil, err
		}
		elem, err := s.typ(t.Elem())
		if err != nil {
			return nil, err
		}
		result = types.NewMap(key, elem)
	case *types.Chan:
		elem, err := s.typ(t.Elem())
		if err != nil {
			return nil, err
		}
		result = types.NewChan(t.Dir(), elem)
	case *types.Struct:
		var fields []*types.Var
		var tags []string
		for i := range t.NumFields() {
			field := t.Field(i)
			fieldType, err := s.typ(field.Type())
			if err != nil {
				return nil, err
			}
			fields = append(fields, types.NewField(token.NoPos, field.Pkg(), field.Name(), fieldType, field.Embedded()))
			tags = append(tags, t.Tag(i))
		}
		result = types.NewStruct(fields, tags)
	case *types.Tuple:
		var vars []*types.Var
		for v := range t.Variables() {
			projected, err := s.variable(v)
			if err != nil {
				return nil, err
			}
			vars = append(vars, projected)
		}
		result = types.NewTuple(vars...)
	case *types.Signature:
		params, err := s.params(t.TypeParams())
		if err != nil {
			return nil, err
		}
		recvParams, err := s.params(t.RecvTypeParams())
		if err != nil {
			return nil, err
		}
		recv, err := s.variable(t.Recv())
		if err != nil {
			return nil, err
		}
		in, err := s.typ(t.Params())
		if err != nil {
			return nil, err
		}
		out, err := s.typ(t.Results())
		if err != nil {
			return nil, err
		}
		result = types.NewSignatureType(recv, recvParams, params, in.(*types.Tuple), out.(*types.Tuple), t.Variadic())
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
				var err error
				recv, err = s.variable(sig.Recv())
				if err != nil {
					return nil, err
				}
			}
			in, err := s.typ(sig.Params())
			if err != nil {
				return nil, err
			}
			out, err := s.typ(sig.Results())
			if err != nil {
				return nil, err
			}
			methods = append(methods, types.NewFunc(token.NoPos, s.pkg, name, types.NewSignatureType(recv, nil, nil, in.(*types.Tuple), out.(*types.Tuple), sig.Variadic())))
		}
		var embedded []types.Type
		for e := range t.EmbeddedTypes() {
			projected, err := s.typ(e)
			if err != nil {
				return nil, err
			}
			embedded = append(embedded, projected)
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
			projected, err := s.typ(term.Type())
			if err != nil {
				return nil, err
			}
			terms = append(terms, types.NewTerm(term.Tilde(), projected))
		}
		result = types.NewUnion(terms)
	default:
		return nil, fmt.Errorf("unsupported API type %T", t)
	}
	s.types[t] = result
	return result, nil
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
