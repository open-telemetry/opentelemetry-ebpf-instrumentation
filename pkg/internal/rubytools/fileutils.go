// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

func projectDirectoryForFile(path string) string {
	dir := filepath.Dir(path)

	if filepath.Base(path) == "environment.rb" && filepath.Base(dir) == "config" {
		return filepath.Dir(dir)
	}

	return dir
}

func projectPathLooksLikeFile(path string) bool {
	base := filepath.Base(path)
	return base == "config.ru" || filepath.Ext(base) != ""
}

func gemDependencyRoots(cwd string, env map[string]string) []string {
	var roots []string
	if root := cleanDependencyRoot(cwd, env[gemHome]); root != "" {
		roots = append(roots, root)
	}

	for _, root := range filepath.SplitList(env[gemPath]) {
		if root = cleanDependencyRoot(cwd, root); root != "" {
			roots = append(roots, root)
		}
	}

	return roots
}

func pathInDependencyRoot(cwd, path string, roots []string) bool {
	path = absoluteProcessPath(cwd, path)
	for _, root := range roots {
		if pathWithinBoundary(root, path) {
			return true
		}
	}

	return false
}

func cleanDependencyRoot(cwd, path string) string {
	if path == "" {
		return ""
	}

	path = absoluteProcessPath(cwd, path)
	if !filepath.IsAbs(path) {
		return ""
	}

	return path
}

func absoluteProcessPath(cwd, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}

	return filepath.Clean(filepath.Join(cwd, path))
}

func regularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func pathEntryExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

func serviceNameFromEntryPoint(path string) string {
	name := filepath.Base(path)
	name = strings.TrimSuffix(name, ".rb")
	if _, tooling := rubyTooling[name]; tooling {
		return ""
	}

	if !validServiceName(name) || name == "config.ru" {
		return ""
	}
	return name
}

func serviceNameFromProjectDirectory(dir, boundary string) string {
	if dir == boundary {
		return ""
	}

	name := filepath.Base(dir)
	if !validServiceName(name) {
		return ""
	}

	return name
}

func validServiceName(value string) bool {
	return value != "" && value != "." && value != ".." && value != "-" &&
		value != string(filepath.Separator) && !strings.ContainsFunc(value, unicode.IsControl)
}

func firstValidName(values ...string) string {
	for _, value := range values {
		if validServiceName(value) {
			return value
		}
	}

	return ""
}

func pathWithinBoundary(boundary, path string) bool {
	relative, err := filepath.Rel(boundary, path)

	if err != nil {
		return false
	}

	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
