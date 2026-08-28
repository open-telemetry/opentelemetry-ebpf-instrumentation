// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnettools

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestResolveServiceMetadata(t *testing.T) {
	t.Run("dotnet host resolves entry assembly and version", func(t *testing.T) {
		root := t.TempDir()
		writeDotnetFile(t, filepath.Join(root, "app", "Orders.Api.deps.json"), depsJSON("Orders.Api", "2.3.4-beta.1"))
		fileInfo := mockDotnetProcess(t, root, "/usr/bin/dotnet", []string{"Orders.Api.dll"}, nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "Orders.Api", service.UID.Name)
		assert.Empty(t, service.UID.Namespace)
		assert.Equal(t, "2.3.4-beta.1", service.Metadata[serviceVersion])
		assert.True(t, service.AutoName())
	})

	t.Run("explicit deps file is resolved from cwd", func(t *testing.T) {
		root := t.TempDir()
		writeDotnetFile(t, filepath.Join(root, "app", "metadata", "service.deps.json"), depsJSON("Orders.Api", "3.0.0"))
		fileInfo := mockDotnetProcess(t, root, "/usr/bin/dotnet", []string{
			"exec", "--depsfile", "metadata/service.deps.json", "Orders.Api.dll",
		}, nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "Orders.Api", service.UID.Name)
		assert.Equal(t, "3.0.0", service.Metadata[serviceVersion])
	})

	t.Run("apphost resolves adjacent deps file without command inspection", func(t *testing.T) {
		root := t.TempDir()
		writeDotnetFile(t, filepath.Join(root, "app", "Orders.Api.deps.json"), depsJSON("Orders.Api", "1.0.0"))
		expectedErr := errors.New("must not inspect")
		fileInfo := mockDotnetProcess(t, root, "/app/Orders.Api", nil, expectedErr, expectedErr)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "Orders.Api", service.UID.Name)
		assert.Equal(t, "1.0.0", service.Metadata[serviceVersion])
	})

	t.Run("DLL name is used without a deps file", func(t *testing.T) {
		root := t.TempDir()
		fileInfo := mockDotnetProcess(t, root, "/usr/bin/dotnet", []string{"/app/Orders.Worker.dll"}, nil, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "Orders.Worker", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("name and version resolve independently", func(t *testing.T) {
		root := t.TempDir()
		writeDotnetFile(t, filepath.Join(root, "app", "Orders.Api.deps.json"), depsJSON("Orders.Api", "2.3.4"))
		fileInfo := mockDotnetProcess(t, root, "/usr/bin/dotnet", []string{"Orders.Api.dll"}, nil, nil)
		fileInfo.SetUID(svc.UID{Name: "explicit", Namespace: "production"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "explicit", service.UID.Name)
		assert.Equal(t, "production", service.UID.Namespace)
		assert.Equal(t, "2.3.4", service.Metadata[serviceVersion])
		assert.False(t, service.AutoName())

		fileInfo = mockDotnetProcess(t, root, "/usr/bin/dotnet", []string{"Orders.Api.dll"}, nil, nil)
		fileInfo.SetMetadata(map[attr.Name]string{serviceVersion: "explicit-version"})

		err = ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service = fileInfo.ServiceAttrs()
		assert.Equal(t, "Orders.Api", service.UID.Name)
		assert.Equal(t, "explicit-version", service.Metadata[serviceVersion])
	})

	t.Run("explicit name and version skip process inspection", func(t *testing.T) {
		root := t.TempDir()
		expectedErr := errors.New("must not inspect")
		fileInfo := mockDotnetProcess(t, root, "/usr/bin/dotnet", nil, expectedErr, expectedErr)
		fileInfo.SetUID(svc.UID{Name: "explicit"})
		fileInfo.SetMetadata(map[attr.Name]string{serviceVersion: "2.0.0"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "explicit", service.UID.Name)
		assert.Equal(t, "2.0.0", service.Metadata[serviceVersion])
	})

	t.Run("relative launch keeps name when cwd lookup fails", func(t *testing.T) {
		root := t.TempDir()
		expectedErr := errors.New("process disappeared")
		fileInfo := mockDotnetProcess(t, root, "/usr/bin/dotnet", []string{"Orders.Api.dll"}, nil, expectedErr)

		err := ResolveServiceMetadata(fileInfo)

		require.ErrorIs(t, err, expectedErr)
		assert.Equal(t, "Orders.Api", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("command lookup failure is returned", func(t *testing.T) {
		root := t.TempDir()
		expectedErr := errors.New("process disappeared")
		fileInfo := mockDotnetProcess(t, root, "/usr/bin/dotnet", nil, expectedErr, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.ErrorIs(t, err, expectedErr)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})
}

func TestReadDepsJSON(t *testing.T) {
	t.Run("ambiguous application versions are ignored", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "Orders.Api.deps.json")
		writeDotnetFile(t, path, []byte(`{
  "runtimeTarget":{"name":"net8.0"},
  "targets":{"net8.0":{
    "Orders.Api/1.0.0":{"runtime":{"Orders.Api.dll":{}}},
    "Orders.Api/2.0.0":{"runtime":{"Orders.Api.dll":{}}}
  }},
  "libraries":{
    "Orders.Api/1.0.0":{"type":"project"},
    "Orders.Api/2.0.0":{"type":"project"}
  }
}`))

		assert.Empty(t, readDepsJSON(path, "Orders.Api"))
	})

	t.Run("project references are not selected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "Orders.Api.deps.json")
		writeDotnetFile(t, path, depsJSON("Orders.Library", "4.0.0"))

		assert.Empty(t, readDepsJSON(path, "Orders.Api"))
	})

	t.Run("runtime asset must match", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "Orders.Api.deps.json")
		writeDotnetFile(t, path, []byte(`{
  "runtimeTarget":{"name":"net8.0"},
  "targets":{"net8.0":{"Orders.Api/1.0.0":{"runtime":{"Other.dll":{}}}}},
  "libraries":{"Orders.Api/1.0.0":{"type":"project"}}
}`))

		assert.Empty(t, readDepsJSON(path, "Orders.Api"))
	})

	t.Run("malformed file is ignored", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "Orders.Api.deps.json")
		writeDotnetFile(t, path, []byte(`{"runtimeTarget":`))

		assert.Empty(t, readDepsJSON(path, "Orders.Api"))
	})

	t.Run("oversized file is ignored", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "Orders.Api.deps.json")
		writeDotnetFile(t, path, make([]byte, maxDepsJSONBytes+1))

		assert.Empty(t, readDepsJSON(path, "Orders.Api"))
	})

	t.Run("symlink is ignored", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.deps.json")
		writeDotnetFile(t, target, depsJSON("Orders.Api", "1.0.0"))
		path := filepath.Join(dir, "Orders.Api.deps.json")
		require.NoError(t, os.Symlink(target, path))

		assert.Empty(t, readDepsJSON(path, "Orders.Api"))
	})
}

func TestNormalizeMetadataValue(t *testing.T) {
	value, ok := normalizeMetadataValue("  Acme.Orders API  ")

	assert.True(t, ok)
	assert.Equal(t, "Acme.Orders API", value)
	_, ok = normalizeMetadataValue("Orders\nAPI")
	assert.False(t, ok)
}

func mockDotnetProcess(
	t *testing.T,
	root string,
	executable string,
	args []string,
	cmdlineErr error,
	cwdErr error,
) *exec.FileInfo {
	t.Helper()

	oldRootDirForPID := rootDirForPID
	oldCmdlineForPID := cmdlineForPID
	oldCwdForPID := cwdForPID
	rootDirForPID = func(app.PID) string { return root }
	cmdlineForPID = func(app.PID) (string, []string, error) {
		return executable, args, cmdlineErr
	}
	cwdForPID = func(app.PID) (string, error) { return "/app", cwdErr }
	t.Cleanup(func() {
		rootDirForPID = oldRootDirForPID
		cmdlineForPID = oldCmdlineForPID
		cwdForPID = oldCwdForPID
	})

	return exec.New(exec.Init{
		Pid:        app.PID(1234),
		CmdExePath: executable,
		Service: svc.Attrs{
			Metadata: map[attr.Name]string{},
		},
	})
}

func depsJSON(name, version string) []byte {
	return fmt.Appendf(nil, `{
  "runtimeTarget":{"name":"net8.0"},
  "targets":{"net8.0":{"%[1]s/%[2]s":{"runtime":{"%[1]s.dll":{}}}}},
  "libraries":{"%[1]s/%[2]s":{"type":"project"}}
}`, name, version)
}

func writeDotnetFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, contents, 0o644))
}
