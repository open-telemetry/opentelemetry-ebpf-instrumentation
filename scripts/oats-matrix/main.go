// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Command oats-matrix creates a deterministic GitHub Actions matrix for OATS
// suites, keeping cases that share a fixture in the same shard.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

var splitSuites = map[string]bool{
	"ai": true, "http": true, "kafka": true, "sql": true,
}

var safeCaseName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

type matrix struct {
	Include []shard `json:"include"`
}

type shard struct {
	ID       int      `json:"id"`
	Suite    string   `json:"suite"`
	Basename string   `json:"basename"`
	Cases    []string `json:"cases"`
}

type suiteConfig struct {
	Cases []string `yaml:"cases"`
}

type fixtureGroup struct {
	key   string
	cases []string
}

func main() {
	root := flag.String("suite-root", "internal/test/oats", "directory containing OATS suite directories")
	flag.Parse()
	if flag.NArg() > 1 {
		fatalf("expected at most one positional suite root")
	}
	if flag.NArg() == 1 {
		if *root != "internal/test/oats" {
			fatalf("suite root was provided both positionally and with --suite-root")
		}
		*root = flag.Arg(0)
	}

	result, err := buildMatrix(*root)
	if err != nil {
		fatalf("build OATS matrix: %v", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fatalf("encode OATS matrix: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func buildMatrix(root string) (matrix, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return matrix{}, err
	}
	var suiteNames []string
	for _, entry := range entries {
		if entry.IsDir() {
			if _, err := os.Stat(filepath.Join(root, entry.Name(), "oats-config.yaml")); err == nil {
				suiteNames = append(suiteNames, entry.Name())
			} else if !errors.Is(err, fs.ErrNotExist) {
				return matrix{}, fmt.Errorf("inspect %s manifest: %w", entry.Name(), err)
			}
		}
	}
	sort.Strings(suiteNames)
	if len(suiteNames) == 0 {
		return matrix{}, fmt.Errorf("no suite manifests found under %s", root)
	}
	for _, suite := range suiteNames {
		if !safeCaseName.MatchString(suite) {
			return matrix{}, fmt.Errorf("suite directory %q contains unsupported characters", suite)
		}
	}

	var result matrix
	for _, suite := range suiteNames {
		groups, err := loadFixtureGroups(filepath.Join(root, suite))
		if err != nil {
			return matrix{}, fmt.Errorf("suite %s: %w", suite, err)
		}
		shards := assignGroups(suite, groups)
		for _, item := range shards {
			item.ID = len(result.Include)
			result.Include = append(result.Include, item)
		}
	}
	return result, nil
}

func loadFixtureGroups(suiteDir string) ([]fixtureGroup, error) {
	contents, err := os.ReadFile(filepath.Join(suiteDir, "oats-config.yaml"))
	if err != nil {
		return nil, err
	}
	var config suiteConfig
	if err := yaml.Unmarshal(contents, &config); err != nil {
		return nil, fmt.Errorf("parse oats-config.yaml: %w", err)
	}
	if len(config.Cases) == 0 {
		return nil, errors.New("oats-config.yaml has no cases")
	}

	cases := map[string]string{}
	for _, pattern := range config.Cases {
		if err := validateRelativePath(pattern); err != nil {
			return nil, fmt.Errorf("invalid case pattern %q: %w", pattern, err)
		}
		matches, err := filepath.Glob(filepath.Join(suiteDir, filepath.FromSlash(pattern)))
		if err != nil {
			return nil, fmt.Errorf("invalid case glob %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("case pattern %q matches no files", pattern)
		}
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() || filepath.Ext(match) != ".yaml" {
				return nil, fmt.Errorf("case %q is not a regular YAML file", match)
			}
			rel, err := filepath.Rel(suiteDir, match)
			if err != nil {
				return nil, err
			}
			rel = filepath.ToSlash(rel)
			if err := validateRelativePath(rel); err != nil {
				return nil, fmt.Errorf("case path %q: %w", rel, err)
			}
			if filepath.Dir(filepath.FromSlash(rel)) != "." {
				return nil, fmt.Errorf("case %q is not in the suite directory; matrix cases must be basenames", rel)
			}
			if !safeCaseName.MatchString(filepath.Base(rel)) {
				return nil, fmt.Errorf("case basename %q contains unsupported characters", filepath.Base(rel))
			}
			if _, exists := cases[rel]; exists {
				return nil, fmt.Errorf("case %q is listed by more than one manifest pattern", rel)
			}
			cases[rel] = match
		}
	}

	casePaths := make([]string, 0, len(cases))
	for rel := range cases {
		casePaths = append(casePaths, rel)
	}
	sort.Strings(casePaths)
	groupsByKey := map[string]*fixtureGroup{}
	for _, rel := range casePaths {
		fixture, err := readFixture(cases[rel])
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", rel, err)
		}
		key, err := fixtureKey(fixture, rel)
		if err != nil {
			return nil, fmt.Errorf("case %s fixture: %w", rel, err)
		}
		group := groupsByKey[key]
		if group == nil {
			group = &fixtureGroup{key: key}
			groupsByKey[key] = group
		}
		group.cases = append(group.cases, filepath.Base(rel))
	}
	groups := make([]fixtureGroup, 0, len(groupsByKey))
	for _, group := range groupsByKey {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].key < groups[j].key })
	return groups, nil
}

func validateRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) {
		return errors.New("must be a non-empty relative path")
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("path escapes the suite directory")
	}
	return nil
}

func readFixture(path string) (*yaml.Node, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return nil, err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("case must be a YAML mapping")
	}
	root := document.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "fixture" {
			return root.Content[i+1], nil
		}
	}
	// OATS uses the same implicit fixture when the case omits fixture entirely.
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
}

func fixtureKey(fixture *yaml.Node, casePath string) (string, error) {
	canonical, hasRelativePaths, err := canonicalNode(fixture)
	if err != nil {
		return "", err
	}
	if hasRelativePaths {
		canonical += "\x00dir=" + filepath.ToSlash(filepath.Dir(casePath))
	}
	return canonical, nil
}

func canonicalNode(node *yaml.Node) (string, bool, error) {
	if node == nil {
		return "null", false, nil
	}
	switch node.Kind {
	case yaml.AliasNode:
		return canonicalNode(node.Alias)
	case yaml.MappingNode:
		type entry struct {
			key   string
			value string
		}
		entries := make([]entry, 0, len(node.Content)/2)
		hasRelativePaths := false
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode, valueNode := node.Content[i], node.Content[i+1]
			key, _, err := canonicalNode(keyNode)
			if err != nil {
				return "", false, err
			}
			value, nestedPaths, err := canonicalNode(valueNode)
			if err != nil {
				return "", false, err
			}
			pathField := keyNode.Value == "file" || keyNode.Value == "files" || keyNode.Value == "k8s_dir" || keyNode.Value == "app_docker_file" || keyNode.Value == "app_docker_context"
			finalizerField := keyNode.Value == "finalize"
			hasRelativePaths = hasRelativePaths || nestedPaths || finalizerField || (pathField && hasRelativePath(valueNode))
			entries = append(entries, entry{key: key, value: value})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
		var builder strings.Builder
		builder.WriteString("map{")
		for _, item := range entries {
			builder.WriteString(item.key)
			builder.WriteByte(':')
			builder.WriteString(item.value)
			builder.WriteByte(';')
		}
		builder.WriteByte('}')
		return builder.String(), hasRelativePaths, nil
	case yaml.SequenceNode:
		var builder strings.Builder
		builder.WriteString("seq[")
		hasRelativePaths := false
		for _, child := range node.Content {
			value, nestedPaths, err := canonicalNode(child)
			if err != nil {
				return "", false, err
			}
			hasRelativePaths = hasRelativePaths || nestedPaths
			builder.WriteString(value)
			builder.WriteByte(';')
		}
		builder.WriteByte(']')
		return builder.String(), hasRelativePaths, nil
	case yaml.ScalarNode:
		encoded, err := json.Marshal(struct {
			Tag   string `json:"tag"`
			Value string `json:"value"`
		}{Tag: node.Tag, Value: node.Value})
		return string(encoded), false, err
	default:
		return "", false, fmt.Errorf("unsupported YAML node kind %d", node.Kind)
	}
}

func hasRelativePath(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode {
		return node.Tag == "!!str" && node.Value != "" && !filepath.IsAbs(filepath.FromSlash(node.Value))
	}
	return slices.ContainsFunc(node.Content, hasRelativePath)
}

func assignGroups(suite string, groups []fixtureGroup) []shard {
	count := 1
	if splitSuites[suite] && len(groups) > 1 {
		count = 2
	}
	assignments := make([][]fixtureGroup, count)
	weights := make([]int, count)
	ordered := append([]fixtureGroup(nil), groups...)
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i].cases) != len(ordered[j].cases) {
			return len(ordered[i].cases) > len(ordered[j].cases)
		}
		return ordered[i].key < ordered[j].key
	})
	for _, group := range ordered {
		shardIndex := 0
		for index := 1; index < count; index++ {
			if weights[index] < weights[shardIndex] {
				shardIndex = index
			}
		}
		assignments[shardIndex] = append(assignments[shardIndex], group)
		weights[shardIndex] += len(group.cases)
	}

	result := make([]shard, 0, count)
	for index, shardGroups := range assignments {
		if len(shardGroups) == 0 {
			continue
		}
		var cases []string
		for _, group := range shardGroups {
			cases = append(cases, group.cases...)
		}
		sort.Strings(cases)
		basename := suite
		if count > 1 {
			basename = fmt.Sprintf("%s-%d", suite, index+1)
		}
		result = append(result, shard{Suite: suite, Basename: basename, Cases: cases})
	}
	return result
}
