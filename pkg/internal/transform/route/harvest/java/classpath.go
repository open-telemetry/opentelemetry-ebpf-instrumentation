// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/java"

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

const envClasspath = "CLASSPATH"

type scanRoot struct {
	path string
	dir  bool
}

type javaLaunch struct {
	jar       string
	classpath string
}

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

func (e *Extractor) findScanRoots(fileInfo *exec.FileInfo) ([]scanRoot, error) {
	pid := fileInfo.Pid()
	root := rootDirForPID(pid)
	_, args, err := cmdlineForPID(pid)
	if err != nil {
		return nil, fmt.Errorf("error finding Java cmd line: %w", err)
	}

	cwd, err := cwdForPID(pid)
	if err != nil {
		return nil, fmt.Errorf("error finding Java cwd: %w", err)
	}

	launch := parseJavaLaunch(args, fileInfo.ServiceAttrs().EnvVars)
	if launch.jar != "" {
		root, ok := resolveProcessPath(root, cwd, launch.jar)
		if !ok {
			return nil, fmt.Errorf("invalid Java jar path %q", launch.jar)
		}
		if isRegularFile(root) {
			return []scanRoot{{path: root}}, nil
		}
		return nil, fmt.Errorf("java jar path %q is not a regular file", launch.jar)
	}

	if launch.classpath == "" {
		return nil, fmt.Errorf("no Java jar or classpath found for pid %d", pid)
	}

	return scanRootsFromClasspath(root, cwd, launch.classpath), nil
}

func parseJavaLaunch(args []string, env map[string]string) javaLaunch {
	var classpath string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-jar":
			if i+1 < len(args) {
				return javaLaunch{jar: args[i+1]}
			}
			return javaLaunch{}
		case arg == "-cp" || arg == "-classpath" || arg == "--class-path":
			if i+1 < len(args) {
				classpath = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--class-path="):
			classpath = strings.TrimPrefix(arg, "--class-path=")
		}
	}

	if classpath != "" {
		return javaLaunch{classpath: classpath}
	}

	if env != nil {
		return javaLaunch{classpath: env[envClasspath]}
	}
	return javaLaunch{}
}

func scanRootsFromClasspath(root, cwd, classpath string) []scanRoot {
	var dirs []scanRoot
	var jars []scanRoot
	for _, entry := range filepath.SplitList(classpath) {
		if entry == "" || strings.Contains(entry, "*") {
			continue
		}

		path, ok := resolveProcessPath(root, cwd, entry)
		if !ok {
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			dirs = append(dirs, scanRoot{path: path, dir: true})
			continue
		}
		if info.Mode().IsRegular() && isJavaArchive(path) {
			jars = append(jars, scanRoot{path: path})
		}
	}

	if len(dirs) > 0 {
		return dirs
	}
	return jars
}

func resolveProcessPath(root, cwd, path string) (string, bool) {
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

	if isProcRoot(root) {
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

func isProcRoot(root string) bool {
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

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func isJavaArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".jar" || ext == ".war"
}
