// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/types"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimumReleaseAcrossBaselines(t *testing.T) {
	for _, tc := range []struct {
		name     string
		findings []finding
		want     string
	}{
		{name: "unchanged", want: "patch"},
		{
			name:     "addition already released in minor",
			findings: []finding{{Baseline: "v1.0.0", Compatible: true}},
			want:     "patch",
		},
		{
			name:     "addition already released in patch",
			findings: []finding{{Baseline: "v1.1.0", Compatible: true}},
			want:     "patch",
		},
		{
			name:     "new addition",
			findings: []finding{{Baseline: "v1.0.0", Compatible: true}, {Baseline: "v1.1.1", Compatible: true}},
			want:     "minor",
		},
		{
			name:     "older contract breaks",
			findings: []finding{{Baseline: "v1.0.0", Compatible: false}, {Baseline: "v1.1.1", Compatible: true}},
			want:     "major",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := minimumRelease(tc.findings, "v1.1.1"); got != tc.want {
				t.Fatalf("minimum release=%s, want %s", got, tc.want)
			}
		})
	}
}

func TestFindingAttribution(t *testing.T) {
	inherited := finding{Baseline: "v1.0.0", Platform: "linux/amd64", Package: coreModule + "/pkg/public", Identifier: "Old", Message: "Old: removed"}
	introduced := inherited
	introduced.Identifier = "New"
	introduced.Message = "New: removed"
	worsened := inherited
	worsened.Message = "Old: changed from int to string"
	for _, tc := range []struct {
		name                    string
		head                    []finding
		newCount, existingCount int
	}{
		{"tooling-only PR", []finding{inherited}, 0, 1},
		{"new violation", []finding{inherited, introduced}, 1, 1},
		{"changed violation", []finding{worsened}, 1, 0},
		{"fixed violation", nil, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newFindings, existing := attributeFindings(tc.head, []finding{inherited})
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

func TestTargetCheckoutValidation(t *testing.T) {
	root := publicAPIFixture(t, "package public; func F() {}", "")
	writeFile(t, filepath.Join(root, "versions.yaml"), "module-sets:\n  obi:\n    version: v1.0.0\n")
	for _, args := range [][]string{{"init", "--quiet"}, {"add", "."}, {"-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Establish target"}} {
		if _, err := git(t.Context(), root, args...); err != nil {
			t.Fatal(err)
		}
	}
	first, err := git(t.Context(), root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "pkg/public/api.go"), "package public; func Changed() {}")
	for _, tc := range []struct{ baseDir, want string }{{"", "--base-dir must identify"}, {root, "base-dir must have a clean working tree"}} {
		var r report
		err := check(t.Context(), options{repoRoot: root, baseRef: "HEAD", headRef: "HEAD", baseDir: tc.baseDir}, &r, io.Discard)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("error=%v, want %s", err, tc.want)
		}
	}
	for _, args := range [][]string{{"add", "."}, {"-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Change candidate"}} {
		if _, err := git(t.Context(), root, args...); err != nil {
			t.Fatal(err)
		}
	}
	var r report
	err = check(t.Context(), options{repoRoot: root, baseRef: first, headRef: "HEAD", baseDir: root}, &r, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "base-dir does not match base-ref") {
		t.Fatalf("error=%v", err)
	}
}

func TestAttributionOfExposedConstraint(t *testing.T) {
	const public = `package public; import "go.opentelemetry.io/obi/pkg/internal/options"; func F[T options.Number](v T) {}`
	var snapshots []map[string]*types.Package
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
	introduced, _ := attributeFindings(head, base)
	if minimumRelease(introduced, "v1.0.0") != "major" {
		t.Fatalf("further narrowing hidden as inherited: head=%+v base=%+v", head, base)
	}
}
