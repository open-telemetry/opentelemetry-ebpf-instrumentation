// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejstools // import "go.opentelemetry.io/obi/pkg/internal/nodejstools"

import (
	"encoding/json"
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
	maxPackageJSONBytes int64 = 2 * 1024 * 1024
	npmPackageJSON            = "npm_package_json"
	serviceVersion            = attr.Name("service.version")
)

var (
	rootDirForPID = ebpfcommon.RootDirectoryForPID
	cmdlineForPID = ebpfcommon.CMDLineForPID
	cwdForPID     = ebpfcommon.CWDForPID
)

type packageMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func ResolveServiceMetadata(fileInfo *exec.FileInfo) error {
	if fileInfo == nil {
		return errors.New("node.js service metadata requires process file info")
	}

	service := fileInfo.ServiceAttrs()
	resolveName := service.UID.Name == ""
	resolveVersion := service.Metadata[serviceVersion] == ""
	if !resolveName && !resolveVersion {
		return nil
	}

	pid := fileInfo.Pid()
	_, args, cmdlineErr := cmdlineForPID(pid)
	cwd, cwdErr := cwdForPID(pid)
	if err := errors.Join(cmdlineErr, cwdErr); err != nil {
		return err
	}

	launch := ParseNodeLaunch(args)
	metadata := findPackageMetadata(rootDirForPID(pid), cwd, launch.EntryPoint, service.EnvVars)
	if resolveName {
		name, namespace, ok := parsePackageName(metadata.Name)
		if ok {
			fileInfo.SetAutoServiceName(name)
			if namespace != "" && service.UID.Namespace == "" {
				fileInfo.SetAutoServiceNamespace(namespace)
			}
		} else if name := serviceNameFromEntryPoint(cwd, launch.EntryPoint); name != "" {
			fileInfo.SetAutoServiceName(name)
		}
	}

	if resolveVersion {
		version := strings.TrimSpace(metadata.Version)
		if version != "" {
			if service.Metadata == nil {
				service.Metadata = map[attr.Name]string{}
			}
			service.Metadata[serviceVersion] = version
			fileInfo.SetMetadata(service.Metadata)
		}
	}

	return nil
}

func findPackageMetadata(root, cwd, entryPoint string, env map[string]string) packageMetadata {
	if path := env[npmPackageJSON]; path != "" && !pathHasNodeModules(cwd, path) {
		if resolved, ok := langtools.ResolveProcessPath(root, cwd, path); ok {
			if metadata, found := readPackageJSON(resolved); found {
				return metadata
			}
		}
	}

	start, ok := packageSearchStart(root, cwd, entryPoint)
	if !ok {
		return packageMetadata{}
	}
	boundary, ok := langtools.ResolveProcessPath(root, "/", "/")
	if !ok {
		return packageMetadata{}
	}

	for dir := start; ; dir = filepath.Dir(dir) {
		if metadata, found := readPackageJSON(filepath.Join(dir, "package.json")); found {
			return metadata
		}
		if dir == boundary || filepath.Dir(dir) == dir {
			return packageMetadata{}
		}
	}
}

func packageSearchStart(root, cwd, entryPoint string) (string, bool) {
	if entryPoint == "" || pathHasNodeModules(cwd, entryPoint) {
		return langtools.ResolveProcessPath(root, "/", cwd)
	}

	path, ok := langtools.ResolveProcessPath(root, cwd, entryPoint)
	if ok {
		info, err := os.Stat(path)
		if err != nil {
			return "", false
		}
		if info.IsDir() {
			return path, true
		}
		return filepath.Dir(path), true
	}

	entryPoint = absoluteProcessPath(cwd, entryPoint)
	return langtools.ResolveProcessPath(root, "/", filepath.Dir(entryPoint))
}

func readPackageJSON(path string) (packageMetadata, bool) {
	file, found := openPackageJSON(path)
	if file == nil {
		return packageMetadata{}, found
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxPackageJSONBytes+1))
	if err != nil || int64(len(data)) > maxPackageJSONBytes {
		return packageMetadata{}, true
	}

	var fields struct {
		Name    json.RawMessage `json:"name"`
		Version json.RawMessage `json:"version"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return packageMetadata{}, true
	}

	var metadata packageMetadata
	_ = json.Unmarshal(fields.Name, &metadata.Name)
	_ = json.Unmarshal(fields.Version, &metadata.Version)
	return metadata, true
}

func parsePackageName(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsFunc(value, unicode.IsControl) {
		return "", "", false
	}

	if !strings.HasPrefix(value, "@") {
		if strings.Contains(value, "/") {
			return "", "", false
		}
		return value, "", true
	}

	scope, name, ok := strings.Cut(strings.TrimPrefix(value, "@"), "/")
	if !ok || scope == "" || name == "" || strings.Contains(name, "/") {
		return "", "", false
	}
	return name, scope, true
}

func serviceNameFromEntryPoint(cwd, entryPoint string) string {
	if entryPoint == "" || pathHasNodeModules(cwd, entryPoint) {
		return ""
	}

	name := filepath.Base(entryPoint)
	name = strings.TrimSuffix(name, filepath.Ext(name))
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || name == "-" ||
		name == string(filepath.Separator) || strings.ContainsFunc(name, unicode.IsControl) {
		return ""
	}
	return name
}

func pathHasNodeModules(cwd, path string) bool {
	for _, part := range strings.Split(absoluteProcessPath(cwd, path), string(filepath.Separator)) {
		if part == "node_modules" {
			return true
		}
	}
	return false
}

func absoluteProcessPath(cwd, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(cwd, path))
}
