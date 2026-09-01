// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools // import "go.opentelemetry.io/obi/pkg/internal/rubytools"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
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

type serviceMetadataResult struct {
	metadata serviceMetadata
	found    bool
	err      error
}

type projectKind uint8

const (
	projectNone projectKind = iota
	projectRails
	projectGemspec
	projectMarker
)

func ResolveServiceMetadata(ctx context.Context, fileInfo *exec.FileInfo) error {
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
	result := make(chan serviceMetadataResult, 1)
	go func() {
		metadata, found, err := discoverServiceMetadata(ctx, pid, service.EnvVars)
		result <- serviceMetadataResult{metadata: metadata, found: found, err: err}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case resolved := <-result:
		if err := ctx.Err(); err != nil {
			return err
		}
		if !resolved.found {
			return resolved.err
		}

		if resolveName && langtools.ValidServiceName(resolved.metadata.Name) {
			fileInfo.SetAutoServiceName(resolved.metadata.Name)
		}
		if resolveVersion && validGemVersion(resolved.metadata.Version) {
			if service.Metadata == nil {
				service.Metadata = map[attr.Name]string{}
			}
			service.Metadata[serviceVersion] = resolved.metadata.Version
			fileInfo.SetMetadata(service.Metadata)
		}
		return resolved.err
	}
}

func discoverServiceMetadata(
	ctx context.Context,
	pid app.PID,
	env map[string]string,
) (serviceMetadata, bool, error) {
	if err := ctx.Err(); err != nil {
		return serviceMetadata{}, false, err
	}

	command, args, cmdlineErr := cmdlineForPID(pid)
	if err := ctx.Err(); err != nil {
		return serviceMetadata{}, false, err
	}

	cwd, cwdErr := cwdForPID(pid)
	if err := errors.Join(cmdlineErr, cwdErr); err != nil {
		return serviceMetadata{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return serviceMetadata{}, false, err
	}

	root := rootDirForPID(pid)
	if err := ctx.Err(); err != nil {
		return serviceMetadata{}, false, err
	}

	boundary, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return serviceMetadata{}, false, ctx.Err()
	}

	launch := ParseRubyLaunch(command, args)
	return findRubyMetadata(ctx, root, boundary, cwd, launch, env)
}

func findRubyMetadata(
	ctx context.Context,
	root, boundary, cwd string,
	launch RubyLaunch,
	env map[string]string,
) (serviceMetadata, bool, error) {
	if err := ctx.Err(); err != nil {
		return serviceMetadata{}, false, err
	}

	dependencyRoots := gemDependencyRoots(cwd, env)

	if launch.EntryPoint != "" && !pathInDependencyRoot(cwd, launch.EntryPoint, dependencyRoots) {
		fallback := serviceNameFromEntryPoint(launch.EntryPoint)
		if start, ok := searchStart(root, cwd, launch.EntryPoint, true); ok {
			metadata, found, err := findProjectMetadata(ctx, start, boundary, fallback, false)
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
					ctx, start, boundary, "", launch.projectPathAuthoritative,
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
			metadata, found, err := findProjectMetadata(ctx, start, boundary, "", false)
			if err != nil {
				return serviceMetadata{}, false, err
			}
			if found {
				return metadata, true, nil
			}
		}
	}

	return findBundlerMetadata(ctx, root, boundary, cwd, env, dependencyRoots)
}

func findBundlerMetadata(
	ctx context.Context,
	root, boundary, cwd string,
	env map[string]string,
	dependencyRoots []string,
) (serviceMetadata, bool, error) {
	if err := ctx.Err(); err != nil {
		return serviceMetadata{}, false, err
	}

	if path := env[bundleGemfile]; path != "" && !pathInDependencyRoot(cwd, path, dependencyRoots) {
		if resolved, ok := langtools.ResolveProcessPath(root, cwd, path); ok && regularFile(resolved) {
			metadata, found, err := findProjectMetadata(ctx, filepath.Dir(resolved), boundary, "", true)
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
	ctx context.Context,
	start, boundary, directFallback string,
	firstDirectoryIsProject bool,
) (serviceMetadata, bool, error) {
	var metadata serviceMetadata
	found := false
	first := true
	err := langtools.WalkParentDirectories(start, boundary, func(dir string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return true, err
		}

		kind, candidate, err := inspectProjectDirectory(ctx, dir)
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

func inspectProjectDirectory(ctx context.Context, dir string) (projectKind, serviceMetadata, error) {
	if err := ctx.Err(); err != nil {
		return projectNone, serviceMetadata{}, err
	}

	configPath := filepath.Join(dir, "config")
	if configInfo, err := os.Lstat(configPath); err == nil {
		if err := ctx.Err(); err != nil {
			return projectNone, serviceMetadata{}, err
		}

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

	gemspecs, boundary, err := rootGemspecs(ctx, dir)
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
		if err := ctx.Err(); err != nil {
			return projectNone, serviceMetadata{}, err
		}

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

func rootGemspecs(ctx context.Context, dir string) ([]string, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	directory, err := os.Open(dir)
	if err != nil {
		return nil, false, fmt.Errorf("opening Ruby project directory %q: %w", dir, err)
	}

	defer directory.Close()

	entries, err := directory.ReadDir(maxProjectEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("reading Ruby project directory %q: %w", dir, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}

	if len(entries) > maxProjectEntries {
		return nil, true, nil
	}

	var paths []string
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
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
