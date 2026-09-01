// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/langtools"
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
	path = langtools.AbsoluteProcessPath(cwd, path)
	for _, root := range roots {
		if langtools.PathWithinBoundary(root, path) {
			return true
		}
	}

	return false
}

func cleanDependencyRoot(cwd, path string) string {
	if path == "" {
		return ""
	}

	path = langtools.AbsoluteProcessPath(cwd, path)
	if !filepath.IsAbs(path) {
		return ""
	}

	return path
}

func regularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func pathEntryExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("checking Ruby project marker %q: %w", path, err)
}

func serviceNameFromEntryPoint(path string) string {
	name := filepath.Base(path)
	name = strings.TrimSuffix(name, ".rb")
	if _, tooling := rubyTooling[name]; tooling {
		return ""
	}

	if !langtools.ValidServiceName(name) || name == "config.ru" {
		return ""
	}
	return name
}

func serviceNameFromProjectDirectory(dir, boundary string) string {
	if dir == boundary {
		return ""
	}

	name := filepath.Base(dir)
	if !langtools.ValidServiceName(name) {
		return ""
	}

	return name
}

func firstValidName(values ...string) string {
	for _, value := range values {
		if langtools.ValidServiceName(value) {
			return value
		}
	}

	return ""
}
