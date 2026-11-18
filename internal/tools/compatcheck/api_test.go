// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func typedPackage(t *testing.T, source string) *types.Package {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "api.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := types.Config{}
	pkg, err := cfg.Check(coreModule+"/pkg/example", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func TestCompareAPI(t *testing.T) {
	for _, tc := range []struct {
		name         string
		before       string
		after        string
		compatible   bool
		unclassified bool
		message      string
	}{
		{name: "unchanged", before: "func F() {}", after: "func F() {}"},
		{name: "implementation", before: "func F() int { return 1 }", after: "func F() int { return 2 }"},
		{name: "removed function", before: "func F() {}", message: "F: removed"},
		{name: "signature", before: "func F(int) {}", after: "func F(string) {}", message: "changed"},
		{name: "interface method", before: "type I interface { A() }", after: "type I interface { A(); B() }", message: "B: added"},
		{name: "constant meaning needs review", before: "const C = 1", after: "const C = 2", message: "value changed", unclassified: true},
		{name: "addition", after: "func F() {}", compatible: true, message: "F: added"},
		{name: "optional field", before: "type S struct { A int }", after: "type S struct { A, B int }", compatible: true, message: "B: added"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := typedPackage(t, "package example; "+tc.before)
			after := typedPackage(t, "package example; "+tc.after)
			changes, compareErr := compareAPI(apiTestSnapshot(before), apiTestSnapshot(after), "v1.0.0", "linux/amd64")
			if compareErr != nil {
				t.Fatal(compareErr)
			}
			wantRelease := "major"
			if tc.message == "" || tc.unclassified {
				wantRelease = "patch"
			} else if tc.compatible {
				wantRelease = "minor"
			}
			if got := minimumRelease(changes, "v1.0.0"); got != wantRelease {
				t.Fatalf("required release=%s, want %s", got, wantRelease)
			}
			if tc.message == "" {
				if len(changes) != 0 {
					t.Fatalf("unexpected changes: %+v", changes)
				}
				return
			}
			found := false
			for _, f := range changes {
				if strings.Contains(f.Message, tc.message) && f.Compatible == tc.compatible && f.Unsupported == tc.unclassified {
					found = true
					if f.Baseline != "v1.0.0" || f.Platform != "linux/amd64" {
						t.Fatalf("missing change context: %+v", f)
					}
				}
			}
			if !found {
				t.Fatalf("expected %q (compatible=%t), got %+v", tc.message, tc.compatible, changes)
			}
		})
	}
}

func TestPackageAdditionAndRemoval(t *testing.T) {
	pkg := typedPackage(t, "package example; func F() {}")
	for _, removed := range []bool{false, true} {
		before := apiTestSnapshot()
		after := apiTestSnapshot(pkg)
		if removed {
			before, after = after, before
		}
		got, compareErr := compareAPI(before, after, "v1.0.0", "linux/arm64")
		if compareErr != nil {
			t.Fatal(compareErr)
		}
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
		"pkg/public/only_test.go":         "package public;var TestOnly MissingType\n",
		"pkg/test/integration/api.go":     "package integration;func DownstreamHelper(){}\n",
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
		if len(loaded.Packages) != 2 || loaded.Packages[coreModule+"/pkg/public"] == nil || loaded.Packages[coreModule+"/pkg/test/integration"] == nil {
			t.Fatalf("unexpected public surface: %v", loaded)
		}
		if loaded.Packages[coreModule+"/pkg/public"].Scope().Lookup("TestOnly") != nil {
			t.Fatal("test file entered the public API capture")
		}
		want := "64"
		if arch == "arm64" {
			want = "32"
		}
		native := loaded.Packages[coreModule+"/pkg/public"].Scope().Lookup("Native").(*types.Const)
		if native.Val().ExactString() != want {
			t.Fatalf("%s captured the wrong platform: %s", arch, native.Val())
		}
	}
	writeFile(t, filepath.Join(root, "pkg/public/public.go"), "package public; var Broken MissingType\n")
	if _, err := loadAPI(t.Context(), root, "amd64"); err == nil {
		t.Fatal("type errors must fail extraction")
	}
}

func TestBPFGeneratedAPI(t *testing.T) {
	const header = "// Code generated by bpf2go; DO NOT EDIT.\n"
	const before = `type BpfEvent struct { Pad [11]byte; Pid struct { _ int; ID int } }
type BpfKind uint8
const BpfCount = 1
type BpfRemoved struct{}
func (BpfEvent) GeneratedMethod() {}`
	const after = `type BpfEvent struct { Pad [9]byte; Pid BpfPid; Values []int }
type BpfPid struct { _ int; ID int }
type BpfKind uint16
const BpfCount = 2
type BpfAdded struct{}`
	const public = `package public
%s
type Alias = %sBpfEvent
type Defined %sBpfEvent
type Envelope struct { Event %sBpfEvent; Name string }
func Read(%sBpfEvent) {}
func Stable(uint8) {}`
	for _, tc := range []struct {
		name, filename, header      string
		internal, changeAPI, rename bool
		want                        string
	}{
		{name: "public declarations and wrappers", filename: "bpf_bpfel.go", header: header, want: "patch"},
		{name: "custom output suffix", filename: "bpf_x86_bpfel_generated.go", header: header, want: "patch"},
		{name: "renamed generated file", filename: "bindings.go", header: header, want: "patch"},
		{name: "exposed internal declarations", filename: "bpf_bpfel.go", header: header, internal: true, want: "patch"},
		{name: "renamed generated type", filename: "bpf_bpfel.go", header: header, rename: true, want: "patch"},
		{name: "handwritten signature still protected", filename: "bpf_bpfel.go", header: header, changeAPI: true, want: "major"},
		{name: "handwritten Bpf prefix", filename: "api.go", want: "major"},
		{name: "filename without generator header", filename: "bpf_bpfel.go", want: "major"},
		{name: "other generator", filename: "types.pb.go", header: "// Code generated by protoc-gen-go. DO NOT EDIT.\n", want: "major"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var snapshots []*apiSnapshot
			for i, generated := range []string{before, after} {
				root := t.TempDir()
				writeFile(t, filepath.Join(root, "go.mod"), "module "+coreModule+"\n\ngo 1.26.0\n")
				pkg, dir, imports, prefix := "public", "pkg/public", "", ""
				if tc.internal {
					pkg, dir = "options", "pkg/internal/options"
					imports, prefix = `import "go.opentelemetry.io/obi/pkg/internal/options"`, "options."
				}
				api := fmt.Sprintf(public, imports, prefix, prefix, prefix, prefix)
				if i == 1 && tc.changeAPI {
					api = strings.Replace(api, "func Stable(uint8)", "func Stable(uint16)", 1)
				}
				if i == 1 && tc.rename {
					generated = strings.ReplaceAll(generated, "BpfEvent", "BpfRenamed")
					api = strings.ReplaceAll(api, "BpfEvent", "BpfRenamed")
				}
				writeFile(t, filepath.Join(root, "pkg/public/public.go"), api)
				writeFile(t, filepath.Join(root, dir, tc.filename), tc.header+"package "+pkg+"\n"+generated)
				loaded, err := loadAPI(t.Context(), root, "amd64")
				if err != nil {
					t.Fatal(err)
				}
				snapshots = append(snapshots, loaded)
			}
			changes, err := compareAPI(snapshots[0], snapshots[1], "v1.0.0", "linux/amd64")
			if err != nil {
				t.Fatal(err)
			}
			if got := minimumRelease(changes, "v1.0.0"); got != tc.want || (tc.want == "patch" && len(changes) != 0) {
				t.Fatalf("minimum release=%s, want %s; changes=%+v", got, tc.want, changes)
			}
		})
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
	if r.Error == "" || r.RequiredRelease != "incomplete" || !strings.Contains(output.String(), "INCOMPLETE") {
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

func TestFieldFindingShowsChangedMember(t *testing.T) {
	old := typedPackage(t, "package example; type Config struct { Value int; Unrelated string }")
	current := typedPackage(t, "package example; type Config struct { Value string; Unrelated string }")
	changes, err := compareAPI(apiTestSnapshot(old), apiTestSnapshot(current), "v1.0.0", "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Before != "field Value int" || changes[0].After != "field Value string" {
		t.Fatalf("expected changed field signatures, got %+v", changes)
	}
}

func apiTestSnapshot(pkgs ...*types.Package) *apiSnapshot {
	s := &apiSnapshot{Packages: map[string]*types.Package{}, Modules: map[string]string{}}
	for _, p := range pkgs {
		s.Packages[p.Path()] = p
		s.Modules[p.Path()] = coreModule
	}
	return s
}
