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

// AppDirsForPID returns the local application directory for a Python process,
// followed by the existing directories on its PYTHONPATH.
func AppDirsForPID(pid app.PID, env map[string]string) ([]string, error) {
	exe, args, err := cmdlineForPID(pid)
	if err != nil {
		return nil, fmt.Errorf("read Python command line: %w", err)
	}
	cwd, err := cwdForPID(pid)
	if err != nil {
		return nil, fmt.Errorf("read Python working directory: %w", err)
	}

	launch := parsePythonLaunch(exe, args, env)
	root := rootDirForPID(pid)
	dir, err := appDir(root, cwd, launch)
	if err != nil {
		return nil, err
	}
	return append([]string{dir}, pythonPathDirs(root, cwd, launch.PathConfig, env["PYTHONPATH"])...), nil
}

// pythonPathDirs resolves the PYTHONPATH entries that are directories, with an
// empty entry standing for the working directory as it does for Python. The
// filesystem root is skipped: it holds far more than the application, and the
// scan would spend its file limit on the system.
func pythonPathDirs(root, cwd string, pathConfig frameworks.PythonPathConfig, pythonPath string) []string {
	if pathConfig.IgnorePythonEnvironment {
		return nil
	}
	var dirs []string
	for _, entry := range targetSearchRoots(cwd, nil, pythonPath, false) {
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
