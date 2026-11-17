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
	App             string
	PythonPath      []string
	AppOnImportPath bool
}

// AppDirsForPID returns the local application directory for a Python process,
// the existing directories on its PYTHONPATH, and whether the application
// directory is on the import path.
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
	return AppDirs{
		App:             dir,
		PythonPath:      pythonPathDirs(root, cwd, launch.PathConfig, env["PYTHONPATH"]),
		AppOnImportPath: appOnImportPath(launch, env),
	}, nil
}

func appOnImportPath(launch frameworks.PythonLaunch, env map[string]string) bool {
	safePath := launch.PathConfig.SafePath ||
		!launch.PathConfig.IgnorePythonEnvironment && env["PYTHONSAFEPATH"] != ""
	return !safePath || len(launch.SearchPaths) > 0
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
