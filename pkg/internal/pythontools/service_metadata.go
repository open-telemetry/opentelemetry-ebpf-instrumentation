// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools // import "go.opentelemetry.io/obi/pkg/internal/pythontools"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxProjectFileBytes int64 = 2 * 1024 * 1024
	serviceVersion            = attr.Name("service.version")
)

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

type projectMetadata struct {
	name    string
	version string
}

type pyprojectData struct {
	metadata       projectMetadata
	entryPoint     string
	recognized     bool
	fastAPISection bool
}

func ResolveServiceMetadata(fileInfo *exec.FileInfo) error {
	if fileInfo == nil {
		return errors.New("python service metadata requires process file info")
	}

	service := fileInfo.ServiceAttrs()
	resolveName := service.UID.Name == ""
	resolveVersion := service.Metadata[serviceVersion] == ""
	if !resolveName && !resolveVersion {
		return nil
	}

	pid := fileInfo.Pid()
	executable, args, cmdlineErr := cmdlineForPID(pid)
	cwd, cwdErr := cwdForPID(pid)
	if err := errors.Join(cmdlineErr, cwdErr); err != nil {
		return err
	}

	root := rootDirForPID(pid)
	launch := parsePythonLaunch(executable, args, service.EnvVars)
	var resolutionErr error
	if launch.fastAPIAuto {
		var configDir string
		launch.target, configDir, resolutionErr = findFastAPIEntryPoint(root, cwd)
		if launch.target != "" {
			launch.targetKind = classifyTarget(launch.target)
			launch.searchPaths = append([]string{configDir}, launch.searchPaths...)
		}
	}

	metadata := projectMetadata{}
	if targetPath, ok := resolveTargetPath(root, cwd, launch, service.EnvVars); ok {
		var err error
		metadata, err = findProjectMetadata(root, targetPath)
		resolutionErr = errors.Join(resolutionErr, err)
	}

	if resolveName {
		name := metadata.name
		if name == "" {
			name = targetName(launch.target)
		}
		if name == "" {
			name = cleanValue(launch.fallbackName)
		}
		if name != "" {
			fileInfo.SetAutoServiceName(name)
		}
	}

	if resolveVersion && metadata.version != "" {
		if service.Metadata == nil {
			service.Metadata = map[attr.Name]string{}
		}
		service.Metadata[serviceVersion] = metadata.version
		fileInfo.SetMetadata(service.Metadata)
	}

	return resolutionErr
}

func resolveTargetPath(root, cwd string, launch pythonLaunch, env map[string]string) (string, bool) {
	target := targetReference(launch.target)
	if target == "" {
		return "", false
	}

	roots := targetSearchRoots(cwd, launch.searchPaths, env["PYTHONPATH"])
	var candidates []string
	switch launch.targetKind {
	case targetFile:
		candidates = append(candidates, target)
		if filepath.Ext(target) == "" {
			candidates = append(candidates, target+".py", filepath.Join(target, "__init__.py"))
		}
	case targetModule:
		modulePath := filepath.FromSlash(strings.ReplaceAll(target, ".", "/"))
		candidates = append(candidates, modulePath+".py", filepath.Join(modulePath, "__init__.py"))
	default:
		return "", false
	}

	for _, base := range roots {
		for _, candidate := range candidates {
			path, ok := langtools.ResolveProcessPath(root, base, candidate)
			if !ok {
				continue
			}
			info, err := os.Stat(path)
			if err == nil && info.Mode().IsRegular() {
				return path, true
			}
		}
	}
	return "", false
}

func targetSearchRoots(cwd string, launcherPaths []string, pythonPath string) []string {
	roots := make([]string, 0, len(launcherPaths)+2)
	for _, path := range launcherPaths {
		roots = appendProcessPath(roots, cwd, path)
	}
	roots = appendProcessPath(roots, cwd, cwd)
	for _, path := range filepath.SplitList(pythonPath) {
		if path == "" {
			path = cwd
		}
		roots = appendProcessPath(roots, cwd, path)
	}
	return roots
}

func appendProcessPath(paths []string, cwd, path string) []string {
	if path == "" {
		return paths
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	if !slices.Contains(paths, path) {
		paths = append(paths, path)
	}
	return paths
}

func findProjectMetadata(root, targetPath string) (projectMetadata, error) {
	boundary, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return projectMetadata{}, nil
	}

	for dir := filepath.Dir(targetPath); pathWithin(boundary, dir); dir = filepath.Dir(dir) {
		pyproject, found, err := readPyproject(filepath.Join(dir, "pyproject.toml"))
		if err != nil {
			return projectMetadata{}, err
		}
		pyprojectFound := found
		if found && pyproject.recognized {
			return pyproject.metadata, nil
		}

		setup, found, err := readSetupConfig(filepath.Join(dir, "setup.cfg"))
		if err != nil {
			return projectMetadata{}, err
		}
		if found && setup.recognized {
			return setup.metadata, nil
		}
		if pyprojectFound || found {
			return projectMetadata{}, nil
		}

		if dir == boundary || filepath.Dir(dir) == dir {
			break
		}
	}
	return projectMetadata{}, nil
}

func findFastAPIEntryPoint(root, cwd string) (string, string, error) {
	boundary, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return "", "", nil
	}
	dir, ok := langtools.ResolveProcessPath(root, "/", cwd)
	if !ok {
		return "", "", nil
	}

	for pathWithin(boundary, dir) {
		pyproject, found, err := readPyproject(filepath.Join(dir, "pyproject.toml"))
		if err != nil {
			return "", "", err
		}
		pyprojectFound := found
		if found {
			if pyproject.entryPoint != "" {
				return pyproject.entryPoint, processPath(boundary, dir), nil
			}
			if pyproject.recognized || pyproject.fastAPISection {
				return "", "", nil
			}
		}

		setup, found, err := readSetupConfig(filepath.Join(dir, "setup.cfg"))
		if err != nil {
			return "", "", err
		}
		if found && setup.recognized {
			return "", "", nil
		}
		if pyprojectFound || found {
			return "", "", nil
		}
		if dir == boundary || filepath.Dir(dir) == dir {
			break
		}
		dir = filepath.Dir(dir)
	}
	return "", "", nil
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func processPath(root, hostPath string) string {
	rel, err := filepath.Rel(root, hostPath)
	if err != nil || rel == "." {
		return "/"
	}
	return string(filepath.Separator) + rel
}

func readPyproject(path string) (pyprojectData, bool, error) {
	data, found, err := readProjectFile(path)
	if err != nil || !found {
		return pyprojectData{}, found, err
	}

	var file struct {
		Project *struct {
			Name    string   `toml:"name"`
			Version string   `toml:"version"`
			Dynamic []string `toml:"dynamic"`
		} `toml:"project"`
		Tool struct {
			Poetry *struct {
				Name    string `toml:"name"`
				Version string `toml:"version"`
			} `toml:"poetry"`
			FastAPI *struct {
				EntryPoint string `toml:"entrypoint"`
			} `toml:"fastapi"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(data, &file); err != nil {
		return pyprojectData{}, true, fmt.Errorf("parsing %s: %w", path, err)
	}

	result := pyprojectData{fastAPISection: file.Tool.FastAPI != nil}
	if file.Tool.FastAPI != nil {
		result.entryPoint = cleanValue(file.Tool.FastAPI.EntryPoint)
	}
	if file.Project != nil {
		result.recognized = true
		result.metadata.name = cleanProjectName(file.Project.Name)
		if !slices.Contains(file.Project.Dynamic, "version") {
			result.metadata.version = cleanValue(file.Project.Version)
		}
	} else if file.Tool.Poetry != nil {
		result.recognized = true
		result.metadata.name = cleanProjectName(file.Tool.Poetry.Name)
		result.metadata.version = cleanValue(file.Tool.Poetry.Version)
	}
	return result, true, nil
}

func readSetupConfig(path string) (pyprojectData, bool, error) {
	data, found, err := readProjectFile(path)
	if err != nil || !found {
		return pyprojectData{}, found, err
	}

	result := pyprojectData{}
	section := ""
	for lineNumber, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return pyprojectData{}, true, fmt.Errorf("parsing %s:%d: malformed section", path, lineNumber+1)
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "metadata" {
				result.recognized = true
			}
			continue
		}
		if section != "metadata" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			result.metadata.name = cleanProjectName(value)
		case "version":
			value = strings.TrimSpace(value)
			lowerValue := strings.ToLower(value)
			if !strings.HasPrefix(lowerValue, "attr:") && !strings.HasPrefix(lowerValue, "file:") &&
				!strings.Contains(value, "%(") {
				result.metadata.version = cleanValue(value)
			}
		}
	}
	return result, true, nil
}

func readProjectFile(path string) ([]byte, bool, error) {
	file, found, err := openProjectFile(path)
	if err != nil || file == nil {
		return nil, found, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxProjectFileBytes+1))
	if err != nil {
		return nil, true, err
	}
	if int64(len(data)) > maxProjectFileBytes {
		return nil, true, fmt.Errorf("project metadata file %s exceeds %d bytes", path, maxProjectFileBytes)
	}
	return data, true, nil
}

func cleanProjectName(value string) string {
	value = cleanValue(value)
	for i := range len(value) {
		char := value[i]
		alphanumeric := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if alphanumeric {
			continue
		}
		if i == 0 || i == len(value)-1 || char != '-' && char != '_' && char != '.' {
			return ""
		}
	}
	return value
}
