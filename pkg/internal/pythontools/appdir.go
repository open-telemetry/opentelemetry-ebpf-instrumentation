// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools // import "go.opentelemetry.io/obi/pkg/internal/pythontools"

import (
	"fmt"
	"path/filepath"
	"slices"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
	"go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"
)

type AppDirs struct {
	App         string
	ImportRoots []string
	Target      string
}

// AppDirsForPID returns the local application directory for a Python process,
// the existing directories on its import path in the order Python searches
// them, and the file of its launch target when it can be resolved.
func AppDirsForPID(pid app.PID, env map[string]string) (AppDirs, error) {
	exe, args, err := cmdlineForPID(pid)
	if err != nil {
		return AppDirs{}, fmt.Errorf("read Python command line: %w", err)
	}
	cwd, err := cwdForPID(pid)
	if err != nil {
		return AppDirs{}, fmt.Errorf("read Python working directory: %w", err)
	}

	launch := parsePythonLaunch(exe, args, env)
	root := rootDirForPID(pid)
	dir, err := appDir(root, cwd, launch)
	if err != nil {
		return AppDirs{}, err
	}
	target, _, _ := resolveTargetPath(root, cwd, launch, env)
	return AppDirs{
		App:         dir,
		ImportRoots: importRootDirs(root, cwd, importSearchPaths(cwd, launch, env)),
		Target:      target,
	}, nil
}

// importRootDirs resolves the import path entries that are directories. The
// filesystem root is skipped: it holds far more than the application, and the
// scan would spend its file limit on the system.
func importRootDirs(root, cwd string, paths []string) []string {
	var dirs []string
	for _, entry := range paths {
		if entry == string(filepath.Separator) {
			continue
		}
		path, info, ok := langtools.StatProcessPath(root, cwd, entry)
		if !ok || !info.IsDir() || slices.Contains(dirs, path) {
			continue
		}
		dirs = append(dirs, path)
	}
	return dirs
}

func appDir(root, cwd string, launch frameworks.PythonLaunch) (string, error) {
	dir := launch.AppDir
	if launch.ScriptDir != "" {
		dir = launch.ScriptDir
	}
	if launch.TargetKind == frameworks.TargetFile || launch.TargetKind == frameworks.TargetScriptPath {
		target := frameworks.TargetReference(launch.Target)
		if target != "" {
			dir = filepath.Dir(target)
		}
	}
	if dir == "" {
		dir = cwd
	}

	path, info, ok := langtools.StatProcessPath(root, cwd, dir)
	if !ok || !info.IsDir() {
		return "", fmt.Errorf("resolve Python application directory %q", dir)
	}
	return path, nil
}
