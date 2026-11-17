// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func typedPackage(t *testing.T, path, source string) *types.Package {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "api.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := types.Config{}
	pkg, err := cfg.Check(path, fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func TestCompareAPI(t *testing.T) {
	for _, tc := range []struct {
		name       string
		before     string
		after      string
		compatible bool
		message    string
	}{
		{name: "unchanged", before: "func F() {}", after: "func F() {}"},
		{name: "implementation", before: "func F() int { return 1 }", after: "func F() int { return 2 }"},
		{name: "removed function", before: "func F() {}", message: "F: removed"},
		{name: "signature", before: "func F(int) {}", after: "func F(string) {}", message: "changed"},
		{name: "interface method", before: "type I interface { A() }", after: "type I interface { A(); B() }", message: "B: added"},
		{name: "constant", before: "const C = 1", after: "const C = 2", message: "value changed"},
		{name: "addition", after: "func F() {}", compatible: true, message: "F: added"},
		{name: "optional field", before: "type S struct { A int }", after: "type S struct { A, B int }", compatible: true, message: "B: added"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := typedPackage(t, coreModule+"/pkg/example", "package example; "+tc.before)
			after := typedPackage(t, coreModule+"/pkg/example", "package example; "+tc.after)
			findings := compareAPI(map[string]*types.Package{before.Path(): before}, map[string]*types.Package{after.Path(): after}, "v1.0.0", "linux/amd64")
			wantRelease := "major"
			if tc.message == "" {
				wantRelease = "patch"
			} else if tc.compatible {
				wantRelease = "minor"
			}
			if got := minimumRelease(findings, "v1.0.0"); got != wantRelease {
				t.Fatalf("required release=%s, want %s", got, wantRelease)
			}
			if tc.message == "" {
				if len(findings) != 0 {
					t.Fatalf("unexpected findings: %+v", findings)
				}
				return
			}
			found := false
			for _, f := range findings {
				if strings.Contains(f.Message, tc.message) && f.Compatible == tc.compatible {
					found = true
					if f.Baseline != "v1.0.0" || f.Platform != "linux/amd64" || f.Rule != goAPIRule {
						t.Fatalf("missing finding context: %+v", f)
					}
				}
			}
			if !found {
				t.Fatalf("expected %q (compatible=%t), got %+v", tc.message, tc.compatible, findings)
			}
		})
	}
}

func TestPackageAdditionAndRemoval(t *testing.T) {
	pkg := typedPackage(t, coreModule+"/pkg/example", "package example; func F() {}")
	for _, removed := range []bool{false, true} {
		before := map[string]*types.Package{}
		after := map[string]*types.Package{pkg.Path(): pkg}
		if removed {
			before, after = after, before
		}
		got := compareAPI(before, after, "v1.0.0", "linux/arm64")
		if len(got) != 1 || got[0].Compatible == removed {
			t.Fatalf("removed=%t: %+v", removed, got)
		}
	}
}

func TestLoadAPI(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string]string{
		"go.mod":                          "module " + coreModule + "\n\ngo 1.26.0\n",
		"pkg/public/public.go":            "package public; type Interface interface { Do() }; const Value = 1\n",
		"pkg/public/native_amd64.go":      "package public; const Native = 64\n",
		"pkg/public/native_arm64.go":      "package public; const Native = 32\n",
		"pkg/internal/private/private.go": "package private; func Hidden() {}\n",
		"cmd/example/main.go":             "package main; func main() {}\n",
		"nested/go.mod":                   "module example.com/separate\n\ngo 1.26.0\n",
		"nested/api.go":                   "package separate; func Independent() {}\n",
	} {
		writeFile(t, filepath.Join(root, path), body)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		loaded, err := loadAPI(t.Context(), root, arch)
		if err != nil {
			t.Fatal(err)
		}
		if len(loaded) != 1 || loaded[coreModule+"/pkg/public"] == nil {
			t.Fatalf("unexpected public surface: %v", loaded)
		}
		want := "64"
		if arch == "arm64" {
			want = "32"
		}
		native := loaded[coreModule+"/pkg/public"].Scope().Lookup("Native").(*types.Const)
		if native.Val().ExactString() != want {
			t.Fatalf("%s captured the wrong platform: %s", arch, native.Val())
		}
	}
	writeFile(t, filepath.Join(root, "pkg/public/public.go"), "package public; var Broken MissingType\n")
	if _, err := loadAPI(t.Context(), root, "amd64"); err == nil {
		t.Fatal("type errors must fail extraction")
	}
}

func TestEmptyPublicSurfaceFails(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module "+coreModule+"\n\ngo 1.26.0\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main; func main() {}\n")
	if _, err := loadAPI(t.Context(), root, "amd64"); err == nil {
		t.Fatal("an empty API capture must fail")
	}
}

func TestInvalidInputProducesIncompleteReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	var output bytes.Buffer
	code := run(t.Context(), []string{"--repo-root", t.TempDir(), "--report", path}, &output, &output)
	if code != exitError {
		t.Fatalf("exit=%d, output=%s", code, &output)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.Error == "" || !strings.Contains(output.String(), "INCOMPLETE") {
		t.Fatalf("execution failure was hidden: %s", data)
	}
}

func TestProposedVersionAndArchitectures(t *testing.T) {
	for _, version := range []string{"v1.1", "v2.0.0", "invalid"} {
		if err := validateProposed(version, "v1.0.0"); err == nil {
			t.Fatalf("accepted invalid or different-major release %q", version)
		}
	}
	for _, version := range []string{"", "v1.0.1", "v1.1.0-rc.1", "v1.1.0+build.1"} {
		if err := validateProposed(version, "v1.0.0"); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"", "ppc64le", "amd64,"} {
		if _, err := parseArchitectures(arch); err == nil {
			t.Fatalf("accepted unsupported architecture %q", arch)
		}
	}
}

func TestTargetVersionUsesCommittedBase(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "versions.yaml")
	writeFile(t, path, "module-sets:\n  obi:\n    version: v1.0.0\n")
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"add", "versions.yaml"},
		{"-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Establish trusted baseline"},
	} {
		if _, err := git(t.Context(), root, args...); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, path, "module-sets:\n  obi:\n    version: v2.0.0\n")
	got, err := targetVersion(t.Context(), root, "HEAD")
	if err != nil || got != "v1.0.0" {
		t.Fatalf("candidate version edit changed the trusted release line: version=%q, err=%v", got, err)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
