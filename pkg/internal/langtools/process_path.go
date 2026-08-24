// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package langtools // import "go.opentelemetry.io/obi/pkg/internal/langtools"

import (
	"os"
	"path/filepath"
	"strings"
)

func ResolveProcessPath(root, cwd, path string) (string, bool) {
	if root == "" || path == "" {
		return "", false
	}

	var containerPath string
	if filepath.IsAbs(path) {
		containerPath = filepath.Clean(path)
	} else {
		containerPath = filepath.Clean(filepath.Join(cwd, path))
	}
	if !filepath.IsAbs(containerPath) {
		return "", false
	}

	hostPath := filepath.Join(root, strings.TrimPrefix(containerPath, string(filepath.Separator)))
	if !pathInRoot(root, hostPath) {
		return "", false
	}

	if procRootPath(root) {
		if pathHasSymlink(root, containerPath) {
			return "", false
		}
		if _, err := os.Stat(hostPath); err != nil {
			return "", false
		}
		return hostPath, true
	}

	rootEval, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	hostEval, err := filepath.EvalSymlinks(hostPath)
	if err != nil {
		return "", false
	}
	if !pathInRoot(rootEval, hostEval) {
		return "", false
	}

	return hostEval, true
}

var procRootPath = IsProcRoot

func pathHasSymlink(root, containerPath string) bool {
	parts := strings.Split(strings.TrimPrefix(containerPath, string(filepath.Separator)), string(filepath.Separator))
	path := root
	for _, part := range parts {
		if part == "" {
			continue
		}

		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func IsProcRoot(root string) bool {
	root = filepath.Clean(root)
	if !strings.HasPrefix(root, "/proc/") || !strings.HasSuffix(root, "/root") {
		return false
	}

	pid := strings.TrimSuffix(strings.TrimPrefix(root, "/proc/"), "/root")
	if pid == "" {
		return false
	}
	for _, r := range pid {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func pathInRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
