// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimumReleaseAcrossBaselines(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changes []apiChange
		want    string
	}{
		{name: "unchanged", want: "patch"},
		{name: "compatible dependency API addition", changes: []apiChange{{Baseline: "v1.1.1", Package: "example.com/dependency", Compatible: true}}, want: "patch"},
		{name: "exposed dependency API break", changes: []apiChange{{Baseline: "v1.1.1", Package: "example.com/dependency"}}, want: "major"},
		{
			name:    "addition already released in minor",
			changes: []apiChange{{Module: coreModule, Package: coreModule, Baseline: "v1.0.0", Compatible: true}},
			want:    "patch",
		},
		{
			name:    "addition already released in patch",
			changes: []apiChange{{Module: coreModule, Package: coreModule, Baseline: "v1.1.0", Compatible: true}},
			want:    "patch",
		},
		{
			name:    "new addition",
			changes: []apiChange{{Module: coreModule, Package: coreModule, Baseline: "v1.0.0", Compatible: true}, {Module: coreModule, Package: coreModule, Baseline: "v1.1.1", Compatible: true}},
			want:    "minor",
		},
		{
			name:    "older contract breaks",
			changes: []apiChange{{Module: coreModule, Package: coreModule, Baseline: "v1.0.0", Compatible: false}, {Module: coreModule, Package: coreModule, Baseline: "v1.1.1", Compatible: true}},
			want:    "major",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := minimumRelease(tc.changes, "v1.1.1"); got != tc.want {
				t.Fatalf("minimum release=%s, want %s", got, tc.want)
			}
		})
	}
}

func TestFindingAttribution(t *testing.T) {
	inherited := apiChange{Baseline: "v1.0.0", Platform: "linux/amd64", Package: coreModule + "/pkg/public", Identifier: "Old", Message: "Old: removed"}
	introduced := inherited
	introduced.Identifier = "New"
	introduced.Message = "New: removed"
	relocated := inherited
	relocated.Location = "pkg/public/api.go:20:6"
	worsened := inherited
	worsened.Message = "Old: changed from int to string"
	for _, tc := range []struct {
		name                    string
		head                    []apiChange
		newCount, existingCount int
	}{
		{"tooling-only PR", []apiChange{inherited}, 0, 1},
		{"source line moved", []apiChange{relocated}, 0, 1},
		{"new violation", []apiChange{inherited, introduced}, 1, 1},
		{"changed violation", []apiChange{worsened}, 1, 0},
		{"fixed violation", nil, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newFindings, existing := attributeChanges(tc.head, []apiChange{inherited})
			if len(newFindings) != tc.newCount || len(existing) != tc.existingCount {
				t.Fatalf("new=%+v existing=%+v", newFindings, existing)
			}
			if tc.name == "tooling-only PR" {
				if minimumRelease(newFindings, "v1.0.0") != "patch" || minimumRelease(existing, "v1.0.0") != "major" {
					t.Fatal("inherited break must affect release, not PR")
				}
			}
		})
	}
}

func TestTargetWorktreeLifecycle(t *testing.T) {
	const original = "package public; func F(int) {}"
	mockRelease(t, original)
	root := publicAPIFixture(t, original, "")
	writeFile(t, filepath.Join(root, "versions.yaml"), "module-sets:\n  obi:\n    version: v1.0.0\n")
	writeFile(t, filepath.Join(root, "generation-input"), "target")
	writeFile(t, filepath.Join(root, "Makefile"), "docker-generate:\n\t@test \"$$(cat generation-input)\" = target\n\t@test \"$(BPF_TARGETS)\" = amd64\n")
	for _, args := range [][]string{{"init", "--quiet"}, {"add", "."}, {"-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Establish target"}} {
		if _, err := git(t.Context(), root, args...); err != nil {
			t.Fatal(err)
		}
	}
	head, err := git(t.Context(), root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "pkg/public/api.go"), "package public; func F(string) {}")
	writeFile(t, filepath.Join(root, "generation-input"), "candidate")
	status, err := git(t.Context(), root, "status", "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	worktrees, err := git(t.Context(), root, "worktree", "list", "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code := run(t.Context(), []string{"-repo", filepath.Join(root, "pkg/public"), "-target", head, "-arch", "amd64", "-cache-dir", t.TempDir()}, &output, &output)
	if code != exitBreak || !strings.Contains(output.String(), "F: changed") {
		t.Fatalf("exit=%d, want %d: %s", code, exitBreak, &output)
	}
	artifacts := t.TempDir()
	writeFile(t, filepath.Join(artifacts, "pkg/public/api.go"), "package public")
	output.Reset()
	code = run(t.Context(), []string{"-repo", root, "-target", head, "-arch", "amd64", "-target-bpf", artifacts}, &output, &output)
	if code != exitError || !strings.Contains(output.String(), "no bpf2go generator header") {
		t.Fatalf("exit=%d, want %d: %s", code, exitError, &output)
	}
	bin := t.TempDir()
	makePath := filepath.Join(bin, "make")
	writeFile(t, makePath, "#!/bin/sh\nexit 1\n")
	if err := os.Chmod(makePath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	output.Reset()
	code = run(t.Context(), []string{"-repo", root, "-target", head, "-arch", "amd64"}, &output, &output)
	if code != exitError || !strings.Contains(output.String(), "generate target BPF artifacts") {
		t.Fatalf("exit=%d, want %d: %s", code, exitError, &output)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"rev-parse", "HEAD"}, head},
		{[]string{"status", "--porcelain"}, status},
		{[]string{"worktree", "list", "--porcelain"}, worktrees},
	} {
		got, err := git(t.Context(), root, tc.args...)
		if err != nil || got != tc.want {
			t.Fatalf("git %v = %q, %v; want %q", tc.args, got, err, tc.want)
		}
	}
}

func TestAttributionOfExposedConstraint(t *testing.T) {
	const public = `package public; import "go.opentelemetry.io/obi/pkg/internal/options"; func F[T options.Number](v T) {}`
	var snapshots []*apiSnapshot
	for _, constraint := range []string{"~int | ~string | ~float64", "~int | ~string", "~int"} {
		root := publicAPIFixture(t, public, "type Number interface { "+constraint+" }")
		api, err := loadAPI(t.Context(), root, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		snapshots = append(snapshots, api)
	}
	base, err := compareAPI(snapshots[0], snapshots[1], "v1.0.0", "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	head, err := compareAPI(snapshots[0], snapshots[2], "v1.0.0", "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	introduced, _ := attributeChanges(head, base)
	if minimumRelease(introduced, "v1.0.0") != "major" {
		t.Fatalf("further narrowing hidden as inherited: head=%+v base=%+v", head, base)
	}
}

func TestDiagnosticOutput(t *testing.T) {
	var output bytes.Buffer
	printDiagnostic(&output, apiChange{
		Package: coreModule + "/pkg/public", Identifier: "F",
		Baseline: "v1.0.0", Platform: "linux/amd64", Location: "pkg/public/api.go:4:6",
		Message: "F: changed from func(int) to func(string)",
		Before:  "func F(int)", After: "func F(string)",
	})
	want := `
error: F: changed from func(int) to func(string)
  --> pkg/public/api.go:4:6
   = API: go.opentelemetry.io/obi/pkg/public.F
   = baseline: v1.0.0 (linux/amd64)
   = released:  func F(int)
   = candidate: func F(string)
   = help: Keep the released declaration so existing callers compile; add a new API for the new behavior.
`
	if output.String() != want {
		t.Fatalf("diagnostic:\n%s\nwant:\n%s", &output, want)
	}
}
