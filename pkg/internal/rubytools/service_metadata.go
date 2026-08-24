// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxRubyMetadataBytes int64 = 2 * 1024 * 1024
	maxProjectEntries          = 4096
	bundleGemfile              = "BUNDLE_GEMFILE"
	gemHome                    = "GEM_HOME"
	gemPath                    = "GEM_PATH"
	serviceVersion             = attr.Name("service.version")
)

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

type serviceMetadata struct {
	Name    string
	Version string
}

type projectKind uint8

const (
	projectNone projectKind = iota
	projectRails
	projectGemspec
	projectMarker
)

func ResolveServiceMetadata(fileInfo *exec.FileInfo) error {
	if fileInfo == nil {
		return errors.New("ruby service metadata requires process file info")
	}

	service := fileInfo.ServiceAttrs()
	resolveName := service.UID.Name == ""
	resolveVersion := service.Metadata[serviceVersion] == ""
	if !resolveName && !resolveVersion {
		return nil
	}

	pid := fileInfo.Pid()
	command, args, cmdlineErr := cmdlineForPID(pid)
	cwd, cwdErr := cwdForPID(pid)
	if err := errors.Join(cmdlineErr, cwdErr); err != nil {
		return err
	}

	root := rootDirForPID(pid)
	boundary, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return nil
	}

	launch := ParseRubyLaunch(command, args)
	metadata, found := findRubyMetadata(root, boundary, cwd, launch, service.EnvVars)
	if !found {
		return nil
	}

	if resolveName && validServiceName(metadata.Name) {
		fileInfo.SetAutoServiceName(metadata.Name)
	}
	if resolveVersion && validGemVersion(metadata.Version) {
		if service.Metadata == nil {
			service.Metadata = map[attr.Name]string{}
		}
		service.Metadata[serviceVersion] = metadata.Version
		fileInfo.SetMetadata(service.Metadata)
	}
	return nil
}

func findRubyMetadata(
	root, boundary, cwd string,
	launch RubyLaunch,
	env map[string]string,
) (serviceMetadata, bool) {
	dependencyRoots := gemDependencyRoots(cwd, env)

	if launch.EntryPoint != "" && !pathInDependencyRoot(cwd, launch.EntryPoint, dependencyRoots) {
		fallback := serviceNameFromEntryPoint(launch.EntryPoint)
		if start, ok := searchStart(root, cwd, launch.EntryPoint, true); ok {
			if metadata, found := findProjectMetadata(start, boundary, fallback, false); found {
				return metadata, true
			}
		}
		if fallback != "" {
			return serviceMetadata{Name: fallback}, true
		}
	}

	if launch.ProjectPath != "" {
		dependencyPath := pathInDependencyRoot(cwd, launch.ProjectPath, dependencyRoots)
		if !dependencyPath {
			if start, ok := searchStart(
				root, cwd, launch.ProjectPath, projectPathLooksLikeFile(launch.ProjectPath),
			); ok {
				if metadata, found := findProjectMetadata(
					start, boundary, "", launch.projectPathAuthoritative,
				); found {
					return metadata, true
				}
			}
			if launch.projectPathAuthoritative {
				return serviceMetadata{}, false
			}
		}
	}

	if !pathInDependencyRoot("/", cwd, dependencyRoots) {
		if start, ok := langtools.ResolveProcessPath(root, "/", cwd); ok {
			if metadata, found := findProjectMetadata(start, boundary, "", false); found {
				return metadata, true
			}
		}
	}

	return findBundlerMetadata(root, boundary, cwd, env, dependencyRoots)
}

func findBundlerMetadata(
	root, boundary, cwd string,
	env map[string]string,
	dependencyRoots []string,
) (serviceMetadata, bool) {
	if path := env[bundleGemfile]; path != "" && !pathInDependencyRoot(cwd, path, dependencyRoots) {
		if resolved, ok := langtools.ResolveProcessPath(root, cwd, path); ok && regularFile(resolved) {
			if metadata, found := findProjectMetadata(filepath.Dir(resolved), boundary, "", true); found {
				return metadata, true
			}
		}
	}

	return serviceMetadata{}, false
}

func findProjectMetadata(
	start, boundary, directFallback string,
	firstDirectoryIsProject bool,
) (serviceMetadata, bool) {
	if !pathWithinBoundary(boundary, start) {
		return serviceMetadata{}, false
	}

	first := true
	for dir := start; ; dir = filepath.Dir(dir) {
		kind, metadata := inspectProjectDirectory(dir)
		if kind != projectNone || (first && firstDirectoryIsProject) {
			switch kind {
			case projectRails:
				if metadata.Name == "" {
					metadata.Name = serviceNameFromProjectDirectory(dir, boundary)
				}
			case projectGemspec:
				if metadata.Name == "" {
					metadata.Name = firstValidName(
						directFallback,
						serviceNameFromProjectDirectory(dir, boundary),
					)
				}
			default:
				metadata.Name = firstValidName(
					directFallback,
					serviceNameFromProjectDirectory(dir, boundary),
				)
			}
			return metadata, true
		}

		if dir == boundary || filepath.Dir(dir) == dir {
			return serviceMetadata{}, false
		}
		first = false
	}
}

func inspectProjectDirectory(dir string) (projectKind, serviceMetadata) {
	configPath := filepath.Join(dir, "config")
	if configInfo, err := os.Lstat(configPath); err == nil {
		if configInfo.Mode()&os.ModeSymlink != 0 {
			return projectRails, serviceMetadata{}
		}
		if configInfo.IsDir() {
			applicationPath := filepath.Join(configPath, "application.rb")
			if applicationInfo, err := os.Lstat(applicationPath); err == nil {
				if applicationInfo.Mode().IsRegular() {
					return projectRails, serviceMetadata{Name: readRailsApplicationName(applicationPath)}
				}
				return projectRails, serviceMetadata{}
			}
		}
	}

	gemspecs, boundary := rootGemspecs(dir)
	if boundary {
		if len(gemspecs) == 1 {
			return projectGemspec, readGemspec(gemspecs[0])
		}
		return projectGemspec, serviceMetadata{}
	}

	for _, name := range [...]string{"Gemfile", "Gemfile.lock", "config.ru"} {
		if pathEntryExists(filepath.Join(dir, name)) {
			return projectMarker, serviceMetadata{}
		}
	}
	return projectNone, serviceMetadata{}
}

func rootGemspecs(dir string) ([]string, bool) {
	directory, err := os.Open(dir)
	if err != nil {
		return nil, false
	}
	defer directory.Close()

	entries, err := directory.ReadDir(maxProjectEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false
	}
	if len(entries) > maxProjectEntries {
		return nil, true
	}

	var paths []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".gemspec") {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths, len(paths) != 0
}

func searchStart(root, cwd, path string, assumeFile bool) (string, bool) {
	if resolved, ok := langtools.ResolveProcessPath(root, cwd, path); ok {
		info, err := os.Stat(resolved)
		if err != nil {
			return "", false
		}
		if info.IsDir() {
			return resolved, true
		}
		return projectDirectoryForFile(resolved), true
	}

	containerPath := absoluteProcessPath(cwd, path)
	if !assumeFile {
		return "", false
	}
	return langtools.ResolveProcessPath(root, "/", projectDirectoryForFile(containerPath))
}

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
