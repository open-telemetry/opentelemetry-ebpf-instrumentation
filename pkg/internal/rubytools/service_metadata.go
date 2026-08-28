// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	var metadata serviceMetadata
	found := false
	first := true
	_ = langtools.WalkParentDirectories(start, boundary, func(dir string) (bool, error) {
		kind, candidate := inspectProjectDirectory(dir)
		if kind != projectNone || (first && firstDirectoryIsProject) {
			switch kind {
			case projectRails:
				if candidate.Name == "" {
					candidate.Name = firstValidName(
						directFallback,
						serviceNameFromProjectDirectory(dir, boundary),
					)
				}
			case projectGemspec:
				if candidate.Name == "" {
					candidate.Name = firstValidName(
						directFallback,
						serviceNameFromProjectDirectory(dir, boundary),
					)
				}
			default:
				candidate.Name = firstValidName(
					directFallback,
					serviceNameFromProjectDirectory(dir, boundary),
				)
			}

			metadata = candidate
			found = true
			return true, nil
		}

		first = false
		return false, nil
	})
	return metadata, found
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
	if resolved, info, ok := langtools.StatProcessPath(root, cwd, path); ok {
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
