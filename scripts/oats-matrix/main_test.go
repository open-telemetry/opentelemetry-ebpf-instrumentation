// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestBuildMatrixPreservesFixtureGroupsAndCoversCasesOnce(t *testing.T) {
	root := t.TempDir()
	writeSuite(t, root, "http", []string{"oats_*.yaml"}, map[string]string{
		"oats_a.yaml": "name: a\nfixture:\n  compose:\n    file: compose-a.yml\n    app_port: 8080\n",
		"oats_b.yaml": "name: b\nfixture:\n  compose:\n    app_port: 8080\n    file: compose-a.yml\n",
		"oats_c.yaml": "name: c\nfixture:\n  compose:\n    file: compose-c.yml\n",
		"oats_d.yaml": "name: d\nfixture:\n  compose:\n    file: compose-d.yml\n",
	})
	writeSuite(t, root, "redis", []string{"oats_*.yaml"}, map[string]string{
		"oats_one.yaml": "name: one\nfixture:\n  compose:\n    file: compose.yml\n",
		"oats_two.yaml": "name: two\nfixture:\n  compose:\n    file: compose.yml\n",
	})

	got, err := buildMatrix(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Include) != 3 {
		t.Fatalf("got %d matrix rows, want 3: %#v", len(got.Include), got.Include)
	}
	if got.Include[0].ID != 0 || got.Include[1].ID != 1 || got.Include[2].ID != 2 {
		t.Fatalf("IDs are not contiguous: %#v", got.Include)
	}

	var httpShards []shard
	var observed []string
	for _, row := range got.Include {
		switch row.Suite {
		case "http":
			httpShards = append(httpShards, row)
			if row.Basename != "http-1" && row.Basename != "http-2" {
				t.Errorf("unexpected HTTP basename %q", row.Basename)
			}
			observed = append(observed, row.Cases...)
		case "redis":
			if row.Basename != "redis" || !reflect.DeepEqual(row.Cases, []string{"oats_one.yaml", "oats_two.yaml"}) {
				t.Errorf("short suite should remain one shard with both cases: %#v", row)
			}
		}
	}
	if len(httpShards) != 2 {
		t.Fatalf("HTTP should use two shards, got %#v", httpShards)
	}
	sort.Strings(observed)
	if want := []string{"oats_a.yaml", "oats_b.yaml", "oats_c.yaml", "oats_d.yaml"}; !reflect.DeepEqual(observed, want) {
		t.Fatalf("HTTP case coverage = %v, want %v", observed, want)
	}
	for _, row := range httpShards {
		containsA := contains(row.Cases, "oats_a.yaml")
		containsB := contains(row.Cases, "oats_b.yaml")
		if containsA != containsB {
			t.Errorf("fixture-sharing cases were split across shards: %#v", httpShards)
		}
	}
}

func TestBuildMatrixIsDeterministic(t *testing.T) {
	root := t.TempDir()
	writeSuite(t, root, "sql", []string{"oats_*.yaml"}, map[string]string{
		"oats_z.yaml": "fixture:\n  compose:\n    file: z.yml\n",
		"oats_a.yaml": "fixture:\n  compose:\n    file: a.yml\n",
		"oats_b.yaml": "fixture:\n  compose:\n    file: b.yml\n",
	})

	first, err := buildMatrix(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildMatrix(root)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("matrix changed between runs:\n%s\n%s", firstJSON, secondJSON)
	}
}

func TestFixtureGroupsIncludeRelativeDirectoryWhenUsingRelativeFiles(t *testing.T) {
	root := t.TempDir()
	firstPath := filepath.Join(root, "oats_case.yaml")
	secondPath := filepath.Join(root, "oats_other.yaml")
	for _, path := range []string{firstPath, secondPath} {
		if err := os.WriteFile(path, []byte("fixture:\n  compose:\n    file: compose.yml\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	firstFixture, err := readFixture(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	secondFixture, err := readFixture(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	firstKey, err := fixtureKey(firstFixture, "nested/one/oats_case.yaml")
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := fixtureKey(secondFixture, "nested/two/oats_case.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if firstKey == secondKey {
		t.Fatal("identical relative fixture files in different directories were grouped together")
	}

	absoluteFixture, err := readFixtureFileContents("fixture:\n  compose:\n    file: /tmp/compose.yml\n")
	if err != nil {
		t.Fatal(err)
	}
	firstAbsoluteKey, err := fixtureKey(absoluteFixture, "nested/one/oats_case.yaml")
	if err != nil {
		t.Fatal(err)
	}
	secondAbsoluteKey, err := fixtureKey(absoluteFixture, "nested/two/oats_case.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if firstAbsoluteKey != secondAbsoluteKey {
		t.Fatal("absolute fixture paths should not be scoped by the case directory")
	}
}

func TestLoadFixtureGroupsRejectsEmptyAndInvalidCasePatterns(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		files   map[string]string
	}{
		{name: "unknown", pattern: "does-not-exist.yaml"},
		{name: "escape", pattern: "../outside.yaml"},
		{name: "absolute", pattern: filepath.Join(string(filepath.Separator), "outside.yaml")},
		{name: "nested case path", pattern: "nested/*.yaml", files: map[string]string{"nested/oats_case.yaml": "fixture: {}\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			files := tc.files
			if files == nil {
				files = map[string]string{"oats_case.yaml": "fixture: {}\n"}
			}
			writeSuite(t, root, "sql", []string{tc.pattern}, files)
			if _, err := loadFixtureGroups(filepath.Join(root, "sql")); err == nil {
				t.Fatal("expected invalid case pattern error")
			}
		})
	}
}

func TestAssignGroupsDoesNotEmitEmptyShardForOneGroup(t *testing.T) {
	got := assignGroups("http", []fixtureGroup{{key: "same", cases: []string{"a.yaml", "b.yaml"}}})
	if len(got) != 1 || got[0].Basename != "http" {
		t.Fatalf("unsplittable suite should remain one unsuffixed shard: %#v", got)
	}
}

func TestRepositoryOATSMatrixKeepsEveryFixtureGroupTogether(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "test", "oats")
	got, err := buildMatrix(root)
	if err != nil {
		t.Fatal(err)
	}
	shardByCase := map[string]string{}
	for _, row := range got.Include {
		for _, name := range row.Cases {
			key := row.Suite + "/" + name
			if previous, exists := shardByCase[key]; exists {
				t.Fatalf("case %s appears in shards %s and %s", key, previous, row.Basename)
			}
			shardByCase[key] = row.Basename
		}
	}

	suiteDirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, suite := range suiteDirs {
		if !suite.IsDir() {
			continue
		}
		groups, err := loadFixtureGroups(filepath.Join(root, suite.Name()))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			t.Fatal(err)
		}
		for _, group := range groups {
			var assigned string
			for _, name := range group.cases {
				current := shardByCase[suite.Name()+"/"+name]
				if current == "" {
					t.Fatalf("case %s/%s is missing from matrix", suite.Name(), name)
				}
				if assigned == "" {
					assigned = current
				} else if assigned != current {
					t.Fatalf("fixture group %v split between %s and %s", group.cases, assigned, current)
				}
			}
		}
	}
}

func writeSuite(t *testing.T, root, name string, patterns []string, cases map[string]string) {
	t.Helper()
	suite := filepath.Join(root, name)
	if err := os.MkdirAll(suite, 0o755); err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	manifest.WriteString("meta:\n  version: 3\ncases:\n")
	for _, pattern := range patterns {
		fmt.Fprintf(&manifest, "  - %s\n", pattern)
	}
	if err := os.WriteFile(filepath.Join(suite, "oats-config.yaml"), []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, contents := range cases {
		path := filepath.Join(suite, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func contains(values []string, value string) bool {
	return slices.Contains(values, value)
}

func readFixtureFileContents(contents string) (*yaml.Node, error) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(contents), &document); err != nil {
		return nil, err
	}
	root := document.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "fixture" {
			return root.Content[i+1], nil
		}
	}
	return nil, errors.New("fixture missing")
}
