// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"errors"
	"fmt"
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
	metadata, found, resolutionErr := findRubyMetadata(root, boundary, cwd, launch, service.EnvVars)
	if !found {
		return resolutionErr
	}

	if resolveName && langtools.ValidServiceName(metadata.Name) {
		fileInfo.SetAutoServiceName(metadata.Name)
	}
	if resolveVersion && validGemVersion(metadata.Version) {
		if service.Metadata == nil {
			service.Metadata = map[attr.Name]string{}
		}
		service.Metadata[serviceVersion] = metadata.Version
		fileInfo.SetMetadata(service.Metadata)
	}
	return resolutionErr
}

func findRubyMetadata(
	root, boundary, cwd string,
	launch RubyLaunch,
	env map[string]string,
) (serviceMetadata, bool, error) {
	dependencyRoots := gemDependencyRoots(cwd, env)

	if launch.EntryPoint != "" && !pathInDependencyRoot(cwd, launch.EntryPoint, dependencyRoots) {
		fallback := serviceNameFromEntryPoint(launch.EntryPoint)
		if start, ok := searchStart(root, cwd, launch.EntryPoint, true); ok {
			metadata, found, err := findProjectMetadata(start, boundary, fallback, false)
			if err != nil {
				return serviceMetadata{Name: fallback}, fallback != "", err
			}
			if found {
				return metadata, true, nil
			}
		}
		if fallback != "" {
			return serviceMetadata{Name: fallback}, true, nil
		}
	}

	if launch.ProjectPath != "" {
		dependencyPath := pathInDependencyRoot(cwd, launch.ProjectPath, dependencyRoots)
		if !dependencyPath {
			if start, ok := searchStart(
				root, cwd, launch.ProjectPath, projectPathLooksLikeFile(launch.ProjectPath),
			); ok {
				metadata, found, err := findProjectMetadata(
					start, boundary, "", launch.projectPathAuthoritative,
				)
				if err != nil {
					return serviceMetadata{}, false, err
				}
				if found {
					return metadata, true, nil
				}
			}
			if launch.projectPathAuthoritative {
				return serviceMetadata{}, false, nil
			}
		}
	}

	if !pathInDependencyRoot("/", cwd, dependencyRoots) {
		if start, ok := langtools.ResolveProcessPath(root, "/", cwd); ok {
			metadata, found, err := findProjectMetadata(start, boundary, "", false)
			if err != nil {
				return serviceMetadata{}, false, err
			}
			if found {
				return metadata, true, nil
			}
		}
	}

	return findBundlerMetadata(root, boundary, cwd, env, dependencyRoots)
}

func findBundlerMetadata(
	root, boundary, cwd string,
	env map[string]string,
	dependencyRoots []string,
) (serviceMetadata, bool, error) {
	if path := env[bundleGemfile]; path != "" && !pathInDependencyRoot(cwd, path, dependencyRoots) {
		if resolved, ok := langtools.ResolveProcessPath(root, cwd, path); ok && regularFile(resolved) {
			metadata, found, err := findProjectMetadata(filepath.Dir(resolved), boundary, "", true)
			if err != nil {
				return serviceMetadata{}, false, err
			}
			if found {
				return metadata, true, nil
			}
		}
	}

	return serviceMetadata{}, false, nil
}

func findProjectMetadata(
	start, boundary, directFallback string,
	firstDirectoryIsProject bool,
) (serviceMetadata, bool, error) {
	var metadata serviceMetadata
	found := false
	first := true
	err := langtools.WalkParentDirectories(start, boundary, func(dir string) (bool, error) {
		kind, candidate, err := inspectProjectDirectory(dir)
		if err != nil {
			return false, err
		}
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
	return metadata, found, err
}

func inspectProjectDirectory(dir string) (projectKind, serviceMetadata, error) {
	configPath := filepath.Join(dir, "config")
	if configInfo, err := os.Lstat(configPath); err == nil {
		if configInfo.Mode()&os.ModeSymlink != 0 {
			return projectRails, serviceMetadata{}, nil
		}

		if configInfo.IsDir() {
			applicationPath := filepath.Join(configPath, "application.rb")
			if applicationInfo, err := os.Lstat(applicationPath); err == nil {
				if applicationInfo.Mode().IsRegular() {
					return projectRails, serviceMetadata{Name: readRailsApplicationName(applicationPath)}, nil
				}
				return projectRails, serviceMetadata{}, nil
			}
		}
	}

	gemspecs, boundary, err := rootGemspecs(dir)
	if err != nil {
		return projectNone, serviceMetadata{}, err
	}
	if boundary {
		if len(gemspecs) == 1 {
			return projectGemspec, readGemspec(gemspecs[0]), nil
		}

		return projectGemspec, serviceMetadata{}, nil
	}

	for _, name := range [...]string{"Gemfile", "Gemfile.lock", "config.ru"} {
		exists, err := pathEntryExists(filepath.Join(dir, name))
		if err != nil {
			return projectNone, serviceMetadata{}, err
		}
		if exists {
			return projectMarker, serviceMetadata{}, nil
		}
	}
	return projectNone, serviceMetadata{}, nil
}

func rootGemspecs(dir string) ([]string, bool, error) {
	directory, err := os.Open(dir)

	if err != nil {
		return nil, false, fmt.Errorf("opening Ruby project directory %q: %w", dir, err)
	}

	defer directory.Close()

	entries, err := directory.ReadDir(maxProjectEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("reading Ruby project directory %q: %w", dir, err)
	}

	if len(entries) > maxProjectEntries {
		return nil, true, nil
	}

	var paths []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".gemspec") {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths, len(paths) != 0, nil
}

func searchStart(root, cwd, path string, assumeFile bool) (string, bool) {
	if resolved, info, ok := langtools.StatProcessPath(root, cwd, path); ok {
		if info.IsDir() {
			return resolved, true
		}
		return projectDirectoryForFile(resolved), true
	}

	containerPath := langtools.AbsoluteProcessPath(cwd, path)
	if !assumeFile {
		return "", false
	}
	return langtools.ResolveProcessPath(root, "/", projectDirectoryForFile(containerPath))
}
