// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"go/types"
	"os"
	"slices"
	"strings"

	"golang.org/x/exp/apidiff"
	"golang.org/x/tools/go/packages"
)

func loadAPI(ctx context.Context, root, arch string) (map[string]*types.Package, error) {
	path, err := modulePath(root)
	if err != nil {
		return nil, err
	}
	cfg := &packages.Config{
		Context: ctx,
		Dir:     root,
		Mode:    packages.NeedName | packages.NeedModule,
		Env:     goEnvironment(arch),
	}
	listed, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, pkg := range listed {
		if pkg.Name != "main" && !internalPackage(pkg.PkgPath) && len(pkg.Errors) > 0 {
			var errs []error
			for _, e := range pkg.Errors {
				errs = append(errs, e)
			}
			return nil, errors.Join(errs...)
		}
		if pkg.Module != nil && pkg.Module.Path == path && pkg.Name != "main" && !internalPackage(pkg.PkgPath) {
			paths = append(paths, pkg.PkgPath)
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no public packages found for %s", path)
	}
	cfg.Mode = packages.LoadTypes | packages.NeedImports | packages.NeedDeps | packages.NeedModule
	loaded, err := packages.Load(cfg, paths...)
	if err != nil {
		return nil, err
	}
	var errs []error
	packages.Visit(loaded, func(p *packages.Package) bool {
		for _, e := range p.Errors {
			errs = append(errs, e)
		}
		return true
	}, nil)
	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}
	result := make(map[string]*types.Package, len(loaded))
	for _, pkg := range loaded {
		if pkg.Types == nil || pkg.IllTyped || pkg.Module == nil || pkg.Module.Path != path {
			return nil, fmt.Errorf("incomplete type information for %s", pkg.PkgPath)
		}
		result[pkg.PkgPath] = pkg.Types
	}
	if len(result) != len(paths) {
		return nil, fmt.Errorf("loaded %d public packages, expected %d", len(result), len(paths))
	}
	return result, nil
}

func internalPackage(path string) bool {
	return slices.Contains(strings.Split(path, "/"), "internal")
}

func goEnvironment(arch string) []string {
	overrides := map[string]string{
		"GOOS": "linux", "GOARCH": arch, "CGO_ENABLED": "0", "GOWORK": "off",
		"GOFLAGS": "-mod=readonly", "GOPACKAGESDRIVER": "off",
	}
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if _, overridden := overrides[key]; !overridden {
			env = append(env, item)
		}
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	return env
}

func compareAPI(old, candidate map[string]*types.Package, version, platform string) (findings []finding, err error) {
	defer func() {
		if failure := recover(); failure != nil {
			findings = nil
			err = fmt.Errorf("go API comparison incomplete: %v", failure)
		}
	}()
	for path, before := range old {
		after, exists := candidate[path]
		if !exists {
			findings = append(findings, finding{
				Baseline: version, Platform: platform, Package: path, Identifier: path,
				Before: "package " + path, Message: "package removed", Rule: goAPIRule,
			})
			continue
		}
		if before.Name() != after.Name() {
			findings = append(findings, finding{
				Baseline: version, Platform: platform, Package: path, Identifier: path,
				Before: before.Name(), After: after.Name(), Message: "package name changed", Rule: goAPIRule,
			})
		}
	}
	for path := range candidate {
		if _, exists := old[path]; !exists {
			findings = append(findings, finding{
				Baseline: version, Platform: platform, Package: path, Identifier: path,
				After: "package " + path, Message: "package added", Compatible: true, Rule: goAPIRule,
			})
		}
	}
	beforeSurface, afterSurface := newAPISurface(old), newAPISurface(candidate)
	for _, change := range apidiff.Changes(beforeSurface.pkg, afterSurface.pkg).Changes {
		identifier, _, _ := strings.Cut(change.Message, ":")
		beforeObj, afterObj := beforeSurface.object(identifier), afterSurface.object(identifier)
		obj := beforeObj
		if obj == nil {
			obj = afterObj
		}
		if obj == nil {
			panic("API finding has no source declaration: " + change.Message)
		}
		path := obj.Pkg().Path()
		if (old[path] != nil && candidate[path] == nil) || (old[path] == nil && candidate[path] != nil) {
			continue
		}
		message := afterSurface.describe(beforeSurface.describe(change.Message))
		readable, detail, _ := strings.Cut(message, ":")
		readable = strings.TrimPrefix(readable, path+".")
		findings = append(findings, finding{
			Baseline: version, Platform: platform, Package: path, Identifier: readable,
			Before: describeAPIObject(apiMember(beforeObj, identifier)), After: describeAPIObject(apiMember(afterObj, identifier)),
			Message: readable + ":" + detail, Compatible: change.Compatible, Rule: goAPIRule,
			Unsupported: uncertainTypeIdentity(beforeObj, afterObj, readable),
		})
	}
	findings = append(findings, compareConstraints(beforeSurface, afterSurface, version, platform)...)
	return findings, nil
}

func apiMember(obj types.Object, identifier string) types.Object {
	if obj == nil {
		return nil
	}
	root, members, hasMembers := strings.Cut(identifier, ".")
	root, _, _ = strings.Cut(strings.TrimLeft(root, "(*"), "[")
	root = strings.TrimRight(root, ")")
	if !hasMembers || surfaceName.FindString(root) != root {
		return obj
	}
	for member := range strings.SplitSeq(members, ".") {
		obj, _, _ = types.LookupFieldOrMethod(obj.Type(), true, obj.Pkg(), member)
		if obj == nil {
			return nil
		}
	}
	return obj
}

func describeAPIObject(obj types.Object) string {
	if obj == nil {
		return ""
	}
	text := types.ObjectString(obj, types.RelativeTo(obj.Pkg()))
	if constant, ok := obj.(*types.Const); ok {
		text += " = " + constant.Val().ExactString()
	}
	return text
}

// Consumers cannot spell an anonymous struct containing another package's
// private fields. apidiff's nominal-type warning alone cannot establish whether
// naming that struct breaks source compatibility, so leave it unclassified.
func uncertainTypeIdentity(before, after types.Object, identifier string) bool {
	if before == nil || after == nil {
		return false
	}
	_, members, found := strings.Cut(identifier, ".")
	if !found {
		return false
	}
	oldType, newType := before.Type(), after.Type()
	for member := range strings.SplitSeq(members, ".") {
		oldField, _, _ := types.LookupFieldOrMethod(oldType, true, before.Pkg(), member)
		newField, _, _ := types.LookupFieldOrMethod(newType, true, after.Pkg(), member)
		if oldField == nil || newField == nil {
			return false
		}
		oldType, newType = types.Unalias(oldField.Type()), types.Unalias(newField.Type())
	}
	oldStruct, anonymous := oldType.(*types.Struct)
	newNamed, named := newType.(*types.Named)
	if !anonymous || !named {
		return false
	}
	if _, ok := newNamed.Underlying().(*types.Struct); !ok {
		return false
	}
	for field := range oldStruct.Fields() {
		if !field.Exported() {
			return true
		}
	}
	return false
}

func objectParams(obj types.Object) *types.TypeParamList {
	switch obj := obj.(type) {
	case *types.TypeName:
		switch t := obj.Type().(type) {
		case *types.Named:
			return t.TypeParams()
		case *types.Alias:
			return t.TypeParams()
		}
	case *types.Func:
		return obj.Type().(*types.Signature).TypeParams()
	}
	return nil
}

func compareConstraints(before, after *apiSurface, version, platform string) []finding {
	var findings []finding
	for id, old := range before.originals {
		current := after.originals[id]
		if current == nil || before.pkg.Scope().Lookup(id) == nil {
			continue
		}
		oldParams, newParams := objectParams(old), objectParams(current)
		if oldType, ok := old.(*types.TypeName); ok {
			oldIface, oldIsIface := oldType.Type().Underlying().(*types.Interface)
			newIface, newIsIface := current.Type().Underlying().(*types.Interface)
			if oldIsIface && newIsIface && (!oldIface.IsMethodSet() || !newIface.IsMethodSet()) {
				compatible, changed := constraintRelation(after.constraint(oldIface), after.constraint(newIface))
				if changed {
					findings = append(findings, constraintFinding(old, current, after, version, platform, compatible))
				}
			}
		}
		compatible, changed := true, false
		if oldParams.Len() != newParams.Len() {
			compatible, changed = false, true
		} else {
			for i := range oldParams.Len() {
				oldConstraint := after.constraint(oldParams.At(i).Constraint())
				newConstraint := after.constraint(newParams.At(i).Constraint())
				allowed, differs := constraintRelation(oldConstraint, newConstraint)
				compatible = compatible && allowed
				changed = changed || differs
			}
		}
		if changed {
			findings = append(findings, constraintFinding(old, current, after, version, platform, compatible))
		}
	}
	return findings
}

func constraintFinding(old, current types.Object, surface *apiSurface, version, platform string, compatible bool) finding {
	return finding{Baseline: version, Platform: platform, Package: old.Pkg().Path(), Identifier: old.Name(), Before: describeAPIObject(old), After: describeAPIObject(current), Message: fmt.Sprintf("%s: constraints changed from %s to %s", old.Name(), describeConstraints(old, surface), describeConstraints(current, surface)), Compatible: compatible, Rule: goAPIRule}
}

func describeConstraints(obj types.Object, surface *apiSurface) string {
	if iface, ok := obj.Type().Underlying().(*types.Interface); ok {
		return surface.describe(types.TypeString(surface.constraint(iface), types.RelativeTo(surface.pkg)))
	}
	var constraints []string
	for param := range objectParams(obj).TypeParams() {
		constraints = append(constraints, surface.describe(types.TypeString(surface.constraint(param.Constraint()), types.RelativeTo(surface.pkg))))
	}
	return "[" + strings.Join(constraints, ", ") + "]"
}

func constraintRelation(old, current *types.Interface) (compatible, changed bool) {
	probe := types.NewTypeParam(types.NewTypeName(0, nil, "T", nil), old)
	reverse := types.NewTypeParam(types.NewTypeName(0, nil, "T", nil), current)
	compatible = types.Satisfies(probe, current)
	return compatible, !compatible || !types.Satisfies(reverse, old)
}

// Expand named constraint interfaces before mapping concrete named types into
// the candidate graph; otherwise a changed named constraint would compare equal
// to itself and conceal a narrowed type set.
func (s *apiSurface) constraint(t types.Type) *types.Interface {
	iface := t.Underlying().(*types.Interface)
	var methods []*types.Func
	for method := range iface.ExplicitMethods() {
		methods = append(methods, s.method(method))
	}
	var embedded []types.Type
	for e := range iface.EmbeddedTypes() {
		if _, ok := e.Underlying().(*types.Interface); ok {
			embedded = append(embedded, s.constraint(e))
		} else {
			embedded = append(embedded, s.typ(e))
		}
	}
	return types.NewInterfaceType(methods, embedded).Complete()
}
