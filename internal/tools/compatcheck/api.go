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

func compareAPI(old, candidate map[string]*types.Package, version, platform string) []finding {
	var findings []finding
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
		for _, change := range apidiff.Changes(before, after).Changes {
			identifier, _, _ := strings.Cut(change.Message, ":")
			findings = append(findings, finding{
				Baseline: version, Platform: platform, Package: path, Identifier: identifier,
				Before: describeObject(before, identifier), After: describeObject(after, identifier),
				Message: change.Message, Compatible: change.Compatible, Rule: goAPIRule,
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
	return append(findings, compareInternalAPI(old, candidate, version, platform)...)
}

func describeObject(pkg *types.Package, identifier string) string {
	name, _, _ := strings.Cut(identifier, ".")
	obj := pkg.Scope().Lookup(name)
	if obj == nil {
		return ""
	}
	text := types.ObjectString(obj, types.RelativeTo(pkg))
	if constant, ok := obj.(*types.Const); ok {
		text += " = " + constant.Val().ExactString()
	}
	return text
}
