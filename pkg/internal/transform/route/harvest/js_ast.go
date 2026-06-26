// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
)

// readJSFileForScan returns the bounded contents of a JS/TS file using the same
// safety guards as the line scanner. ok is false for non-regular or oversized
// files that should be skipped.
func readJSFileForScan(path string) (string, bool, error) {
	f, ok, err := openJSFileForScan(path)
	if err != nil || !ok {
		return "", ok, err
	}
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, MaxJSFileScanBytes))
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

// astRouteMethods maps the JS route-registration method name to the HTTP method
// it represents. It mirrors the verbs handled by the regex harvesters.
var astRouteMethods = map[string]string{
	"get":     "GET",
	"post":    "POST",
	"put":     "PUT",
	"patch":   "PATCH",
	"delete":  "DELETE",
	"del":     "DELETE",
	"head":    "HEAD",
	"options": "OPTIONS",
	"all":     "ALL",
}

// resolveASTRoutes parses a JS source file and extracts routes whose path is
// supplied through a string variable or a template literal. The line-based
// regex harvesters only match quoted string literals, so this acts as a
// fallback for the cases highlighted in
// https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/929.
//
// It returns nil when the source cannot be parsed (for example TypeScript),
// leaving the regex-based results untouched.
func (e *RouteExtractor) resolveASTRoutes(filePath, src string) []RoutePattern {
	return e.resolveASTRoutesInner(filePath, src, map[string]bool{filePath: true})
}

func (e *RouteExtractor) resolveASTRoutesInner(filePath, src string, visited map[string]bool) []RoutePattern {
	prog, err := parser.ParseFile(nil, filePath, src, 0)
	if err != nil {
		return nil
	}

	dir := filepath.Dir(filePath)

	// First pass: collect all possible string values for each variable.
	// Repeated until stable to resolve chained dependencies.
	// strVars stores both simple names ("x" → values) and flattened object
	// property access ("obj.key" → values) for dot-notation and destructuring.
	strVars := map[string][]string{}
	for {
		added := 0
		walk(prog, func(n ast.Node) {
			switch v := n.(type) {
			case *ast.Binding:
				added += e.firstPassBinding(v, strVars, dir, visited)
			case *ast.AssignExpression:
				id, ok := v.Left.(*ast.Identifier)
				if !ok {
					return
				}
				name := id.Name.String()
				if _, exists := strVars[name]; exists {
					return
				}
				if vals := stringValues(v.Right, strVars); len(vals) > 0 {
					strVars[name] = vals
					added++
				}
			case *ast.ForOfStatement:
				name := loopVarName(v.Into)
				if name == "" || strVars[name] != nil {
					return
				}
				vals := stringValues(v.Source, strVars)
				if len(vals) > 0 {
					strVars[name] = vals
					added++
				} else if e.log != nil {
					e.log.Debug("unresolvable loop source", "file", filePath)
				}
			}
		})
		if added == 0 {
			break
		}
	}

	// Second pass: find route registration calls whose first argument is a
	// variable, template literal, or expression — resolve to all possible paths.
	var routes []RoutePattern
	walk(prog, func(n ast.Node) {
		call, ok := n.(*ast.CallExpression)
		if !ok || len(call.ArgumentList) == 0 {
			return
		}
		method, ok := routeMethod(call.Callee)
		if !ok {
			return
		}
		first := call.ArgumentList[0]
		// Plain string literals and no-interpolation template literals are already
		// handled by the regex pass.
		if _, isLit := first.(*ast.StringLiteral); isLit {
			return
		}
		if tmpl, isTmpl := first.(*ast.TemplateLiteral); isTmpl && len(tmpl.Expressions) == 0 {
			return
		}
		paths := stringValues(first, strVars)
		if len(paths) == 0 && e.log != nil {
			e.log.Debug("unresolvable route path", "file", filePath, "line", lineOf(prog, call.Idx0()))
		}
		for _, path := range paths {
			if !strings.HasPrefix(path, "/") {
				continue
			}
			routes = append(routes, RoutePattern{
				Method: method,
				Path:   path,
				File:   filePath,
				Line:   lineOf(prog, call.Idx0()),
			})
		}
	})
	return routes
}

// firstPassBinding processes a single *ast.Binding node during the first pass,
// updating strVars with newly resolvable string values. Returns the number of
// new entries added so the caller can detect fixpoint.
func (e *RouteExtractor) firstPassBinding(v *ast.Binding, strVars map[string][]string, dir string, visited map[string]bool) int {
	added := 0
	switch target := v.Target.(type) {
	case *ast.Identifier:
		name := target.Name.String()
		if obj, ok := v.Initializer.(*ast.ObjectLiteral); ok {
			for _, prop := range obj.Value {
				kv, ok := prop.(*ast.PropertyKeyed)
				if !ok {
					continue
				}
				key := propKeyName(kv.Key)
				if key == "" {
					continue
				}
				flatKey := name + "." + key
				if _, exists := strVars[flatKey]; exists {
					continue
				}
				if vals := stringValues(kv.Value, strVars); len(vals) > 0 {
					strVars[flatKey] = vals
					added++
				}
			}
			return added
		}
		if reqPath := requireLiteralPath(v.Initializer); reqPath != "" {
			exports := e.requireExports(dir, reqPath, visited)
			for key, vals := range exports {
				flatKey := name + "." + key
				if _, exists := strVars[flatKey]; exists {
					continue
				}
				strVars[flatKey] = vals
				added++
			}
			return added
		}
		if _, exists := strVars[name]; exists {
			return 0
		}
		if vals := stringValues(v.Initializer, strVars); len(vals) > 0 {
			strVars[name] = vals
			added++
		}

	case *ast.ObjectPattern:
		var exportMap map[string][]string
		srcName := ""

		if reqPath := requireLiteralPath(v.Initializer); reqPath != "" {
			exportMap = e.requireExports(dir, reqPath, visited)
		} else if id, ok := v.Initializer.(*ast.Identifier); ok {
			srcName = id.Name.String()
		}

		for _, prop := range target.Properties {
			switch p := prop.(type) {
			case *ast.PropertyShort:
				key := p.Name.Name.String()
				localName := key
				var vals []string
				if exportMap != nil {
					vals = exportMap[key]
				} else if srcName != "" {
					vals = strVars[srcName+"."+key]
				}
				if len(vals) > 0 {
					if _, exists := strVars[localName]; !exists {
						strVars[localName] = vals
						added++
					}
				}
			case *ast.PropertyKeyed:
				objKey := propKeyName(p.Key)
				if objKey == "" {
					continue
				}
				localName := identName(p.Value)
				if localName == "" {
					continue
				}
				var vals []string
				if exportMap != nil {
					vals = exportMap[objKey]
				} else if srcName != "" {
					vals = strVars[srcName+"."+objKey]
				}
				if len(vals) > 0 {
					if _, exists := strVars[localName]; !exists {
						strVars[localName] = vals
						added++
					}
				}
			}
		}
	}
	return added
}

// requireExports reads and parses a required JS file, returning its exported
// string values keyed by export name. Only handles relative paths and the
// common module.exports = {...} / exports.key = '...' patterns.
func (e *RouteExtractor) requireExports(dir, reqPath string, visited map[string]bool) map[string][]string {
	if !strings.HasPrefix(reqPath, "./") && !strings.HasPrefix(reqPath, "../") {
		return nil
	}
	base := filepath.Join(dir, reqPath)
	candidates := []string{base, base + ".js", base + "/index.js"}

	var src, resolved string
	for _, candidate := range candidates {
		if visited[candidate] {
			continue
		}
		s, ok, err := readJSFileForScan(candidate)
		if err != nil || !ok {
			continue
		}
		src = s
		resolved = candidate
		break
	}
	if resolved == "" {
		return nil
	}

	// Extend visited to prevent circular requires in deeper recursion.
	inner := make(map[string]bool, len(visited)+1)
	for k := range visited {
		inner[k] = true
	}
	inner[resolved] = true

	prog, err := parser.ParseFile(nil, resolved, src, 0)
	if err != nil {
		return nil
	}

	exports := map[string][]string{}
	walk(prog, func(n ast.Node) {
		assign, ok := n.(*ast.AssignExpression)
		if !ok {
			return
		}
		dot, ok := assign.Left.(*ast.DotExpression)
		if !ok {
			return
		}
		leftID, ok := dot.Left.(*ast.Identifier)
		if !ok {
			return
		}
		prop := dot.Identifier.Name.String()
		switch leftID.Name.String() {
		case "module":
			if prop != "exports" {
				return
			}
			obj, ok := assign.Right.(*ast.ObjectLiteral)
			if !ok {
				return
			}
			for _, p := range obj.Value {
				kv, ok := p.(*ast.PropertyKeyed)
				if !ok {
					continue
				}
				key := propKeyName(kv.Key)
				if key == "" {
					continue
				}
				if vals := stringValues(kv.Value, nil); len(vals) > 0 {
					exports[key] = vals
				}
			}
		case "exports":
			if vals := stringValues(assign.Right, nil); len(vals) > 0 {
				exports[prop] = vals
			}
		}
	})
	return exports
}

// routeMethod reports whether callee is a method call like `app.get` /
// `router.post` and, if so, returns the corresponding HTTP method.
func routeMethod(callee ast.Expression) (string, bool) {
	dot, ok := callee.(*ast.DotExpression)
	if !ok {
		return "", false
	}
	method, ok := astRouteMethods[strings.ToLower(dot.Identifier.Name.String())]
	return method, ok
}

// stringValues returns all possible string values for expr. Most expressions
// yield 0 or 1 values; ConditionalExpressions yield one per branch.
func stringValues(expr ast.Expression, vars map[string][]string) []string {
	if expr == nil {
		return nil
	}
	switch v := expr.(type) {
	case *ast.StringLiteral:
		return []string{v.Value.String()}
	case *ast.Identifier:
		if vars == nil {
			return nil
		}
		return vars[v.Name.String()]
	case *ast.DotExpression:
		if vars == nil {
			return nil
		}
		if id, ok := v.Left.(*ast.Identifier); ok {
			return vars[id.Name.String()+"."+v.Identifier.Name.String()]
		}
	case *ast.TemplateLiteral:
		return templateValues(v, vars)
	case *ast.BinaryExpression:
		if v.Operator == token.PLUS {
			return concatProduct(stringValues(v.Left, vars), stringValues(v.Right, vars))
		}
	case *ast.ConditionalExpression:
		return append(stringValues(v.Consequent, vars), stringValues(v.Alternate, vars)...)
	case *ast.ArrayLiteral:
		var out []string
		for _, el := range v.Value {
			out = append(out, stringValues(el, vars)...)
		}
		return out
	}
	return nil
}

// templateValues renders a template literal into all possible route paths.
// When an interpolation resolves to multiple values the results are expanded
// via cartesian product. Unresolvable interpolations become :name or :param.
func templateValues(tmpl *ast.TemplateLiteral, vars map[string][]string) []string {
	results := []string{""}
	for i, el := range tmpl.Elements {
		static := el.Parsed.String()
		for j := range results {
			results[j] += static
		}
		if i >= len(tmpl.Expressions) {
			continue
		}
		expr := tmpl.Expressions[i]
		vals := stringValues(expr, vars)
		if len(vals) == 0 {
			placeholder := ":param"
			if id, ok := expr.(*ast.Identifier); ok {
				placeholder = ":" + id.Name.String()
			}
			for j := range results {
				results[j] += placeholder
			}
		} else {
			results = concatProduct(results, vals)
		}
	}
	return results
}

// concatProduct returns the pairwise concatenation of every element in lefts
// with every element in rights — the cartesian product under string addition.
func concatProduct(lefts, rights []string) []string {
	out := make([]string, 0, len(lefts)*len(rights))
	for _, l := range lefts {
		for _, r := range rights {
			out = append(out, l+r)
		}
	}
	return out
}

// loopVarName extracts the simple identifier name from a for-of / for-in
// Into clause. Returns "" for complex patterns (destructuring, etc.).
func loopVarName(into ast.ForInto) string {
	switch v := into.(type) {
	case *ast.ForDeclaration:
		if id, ok := v.Target.(*ast.Identifier); ok {
			return id.Name.String()
		}
	case *ast.ForIntoVar:
		if v.Binding != nil {
			if id, ok := v.Binding.Target.(*ast.Identifier); ok {
				return id.Name.String()
			}
		}
	case *ast.ForIntoExpression:
		if id, ok := v.Expression.(*ast.Identifier); ok {
			return id.Name.String()
		}
	}
	return ""
}

// requireLiteralPath returns the argument string if expr is a require('...') call
// with a single string literal argument, otherwise "".
func requireLiteralPath(expr ast.Expression) string {
	call, ok := expr.(*ast.CallExpression)
	if !ok || len(call.ArgumentList) != 1 {
		return ""
	}
	callee, ok := call.Callee.(*ast.Identifier)
	if !ok || callee.Name.String() != "require" {
		return ""
	}
	str, ok := call.ArgumentList[0].(*ast.StringLiteral)
	if !ok {
		return ""
	}
	return str.Value.String()
}

// propKeyName returns the string key from a PropertyKeyed.Key expression.
// goja represents all static property keys as StringLiteral. Returns "" for
// computed keys (e.g. { [expr]: value }).
func propKeyName(key ast.Expression) string {
	if str, ok := key.(*ast.StringLiteral); ok {
		return str.Value.String()
	}
	return ""
}

// identName returns the identifier name if expr is a plain *ast.Identifier.
func identName(expr ast.Expression) string {
	if id, ok := expr.(*ast.Identifier); ok {
		return id.Name.String()
	}
	return ""
}

// lineOf returns the 1-based source line for idx within prog.
func lineOf(prog *ast.Program, idx file.Idx) int {
	if prog.File == nil {
		return 0
	}
	return prog.File.Position(int(idx) - prog.File.Base()).Line
}
