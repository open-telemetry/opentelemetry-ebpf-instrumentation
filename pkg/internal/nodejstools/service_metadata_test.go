// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejstools

import (
	"errors"
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
	t.Run("scoped package supplies automatic identity and version", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "app", "dist", "main.js"), nil)
		writeNodeFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"@acme/orders","version":"1.2.3"}`))
		fileInfo := mockNodeProcess(t, root, []string{"/app/dist/main.js"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "acme", service.UID.Namespace)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
		assert.True(t, service.AutoName())
		assert.True(t, service.AutoNamespace())
	})

	t.Run("nearest package is a boundary even when its name is invalid", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"outer","version":"1.0.0"}`))
		writeNodeFile(t, filepath.Join(root, "app", "packages", "api", "package.json"), []byte(`{"name":"bad/name/again","version":"2.0.0"}`))
		writeNodeFile(t, filepath.Join(root, "app", "packages", "api", "dist", "main.js"), nil)
		fileInfo := mockNodeProcess(t, root, []string{"packages/api/dist/main.js"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "main", service.UID.Name)
		assert.Equal(t, "2.0.0", service.Metadata[serviceVersion])
	})

	t.Run("explicit identity is preserved while package supplies version", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "app", "main.js"), nil)
		writeNodeFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"@acme/orders","version":"1.2.3"}`))
		fileInfo := mockNodeProcess(t, root, []string{"main.js"}, nil)
		fileInfo.SetUID(svc.UID{Name: "explicit", Namespace: "production"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "explicit", service.UID.Name)
		assert.Equal(t, "production", service.UID.Namespace)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
		assert.False(t, service.AutoName())
		assert.False(t, service.AutoNamespace())
	})

	t.Run("package scope is not applied without its package name", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "app", "main.js"), nil)
		writeNodeFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"@acme/orders","version":"1.2.3"}`))
		fileInfo := mockNodeProcess(t, root, []string{"main.js"}, nil)
		fileInfo.SetUID(svc.UID{Name: "explicit"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Namespace)
	})

	t.Run("npm package path takes precedence", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "workspace", "package.json"), []byte(`{"name":"workspace"}`))
		writeNodeFile(t, filepath.Join(root, "app", "main.js"), nil)
		writeNodeFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"application"}`))
		fileInfo := mockNodeProcess(t, root, []string{"main.js"}, map[string]string{
			npmPackageJSON: "/workspace/package.json",
		})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "workspace", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("npm package path inside node_modules is ignored", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "app", "main.js"), nil)
		writeNodeFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"application"}`))
		writeNodeFile(t, filepath.Join(root, "app", "node_modules", "tool", "package.json"), []byte(`{"name":"tool"}`))
		fileInfo := mockNodeProcess(t, root, []string{"main.js"}, map[string]string{
			npmPackageJSON: "/app/node_modules/tool/package.json",
		})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "application", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("node_modules entrypoint restarts lookup from cwd", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"application"}`))
		writeNodeFile(t, filepath.Join(root, "app", "node_modules", "tool", "cli.js"), nil)
		writeNodeFile(t, filepath.Join(root, "app", "node_modules", "tool", "package.json"), []byte(`{"name":"tool"}`))
		fileInfo := mockNodeProcess(t, root, []string{"node_modules/tool/cli.js"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "application", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("eval launch uses the cwd package", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"eval-service"}`))
		fileInfo := mockNodeProcess(t, root, []string{"--eval", "setInterval(() => {}, 1000)"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "eval-service", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("entrypoint basename is the final Node.js fallback", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "app", "client.js"), nil)
		fileInfo := mockNodeProcess(t, root, []string{"client"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "client", service.UID.Name)
		assert.True(t, service.AutoName())
	})

	t.Run("application arguments are not treated as the entrypoint", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "opt", "orders", "server.js"), nil)
		fileInfo := mockNodeProcess(t, root, []string{"/opt/orders/server", "--config", "worker.js"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "server", service.UID.Name)
		assert.True(t, service.AutoName())
	})

	t.Run("file URL entrypoint supplies the fallback name", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "opt", "orders", "main.js"), nil)
		fileInfo := mockNodeProcess(t, root, []string{"--entry-url", "file:///opt/orders/main.js"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "main", service.UID.Name)
		assert.True(t, service.AutoName())
	})

	t.Run("entrypoint inside node_modules is not used as a fallback", func(t *testing.T) {
		root := t.TempDir()
		writeNodeFile(t, filepath.Join(root, "app", "node_modules", "tool", "cli.js"), nil)
		fileInfo := mockNodeProcess(t, root, []string{"node_modules/tool/cli.js"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("package lookup does not walk beyond the process root", func(t *testing.T) {
		outer := t.TempDir()
		root := filepath.Join(outer, "process-root")
		writeNodeFile(t, filepath.Join(outer, "package.json"), []byte(`{"name":"host-package"}`))
		writeNodeFile(t, filepath.Join(root, "app", "main.js"), nil)
		fileInfo := mockNodeProcess(t, root, []string{"main.js"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "main", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("process lookup failure is returned", func(t *testing.T) {
		root := t.TempDir()
		expectedErr := errors.New("process disappeared")
		fileInfo := mockNodeProcessWithErrors(t, root, nil, nil, expectedErr, expectedErr)

		err := ResolveServiceMetadata(fileInfo)

		require.ErrorIs(t, err, expectedErr)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})
}

func TestParsePackageName(t *testing.T) {
	tests := []struct {
		value     string
		name      string
		namespace string
		ok        bool
	}{
		{value: " orders ", name: "orders", ok: true},
		{value: "@acme/orders", name: "orders", namespace: "acme", ok: true},
		{value: ""},
		{value: "@acme"},
		{value: "@/orders"},
		{value: "@acme/"},
		{value: "@acme/orders/worker"},
		{value: "acme/orders"},
		{value: "orders\nworker"},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			name, namespace, ok := parsePackageName(tt.value)

			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.name, name)
			assert.Equal(t, tt.namespace, namespace)
		})
	}
}

func TestReadPackageJSONLimits(t *testing.T) {
	t.Run("fields are decoded independently", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "package.json")
		writeNodeFile(t, path, []byte(`{"name":"orders","version":1}`))

		metadata, found := readPackageJSON(path)

		assert.True(t, found)
		assert.Equal(t, "orders", metadata.Name)
		assert.Empty(t, metadata.Version)
	})

	t.Run("oversized file is a manifest boundary", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "package.json")
		writeNodeFile(t, path, make([]byte, maxPackageJSONBytes+1))

		metadata, found := readPackageJSON(path)

		assert.True(t, found)
		assert.Empty(t, metadata)
	})

	t.Run("symlink is a manifest boundary", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		writeNodeFile(t, target, []byte(`{"name":"outside"}`))
		path := filepath.Join(dir, "package.json")
		require.NoError(t, os.Symlink(target, path))

		metadata, found := readPackageJSON(path)

		assert.True(t, found)
		assert.Empty(t, metadata)
	})
}

func TestServiceNameFromEntryPoint(t *testing.T) {
	for _, entryPoint := range []string{"", ".", "..", "/", "-", "node_modules/tool/cli.js"} {
		t.Run(entryPoint, func(t *testing.T) {
			assert.Empty(t, serviceNameFromEntryPoint("/app", entryPoint))
		})
	}
}

func mockNodeProcess(t *testing.T, root string, args []string, env map[string]string) *exec.FileInfo {
	t.Helper()
	return mockNodeProcessWithErrors(t, root, args, env, nil, nil)
}

func mockNodeProcessWithErrors(
	t *testing.T,
	root string,
	args []string,
	env map[string]string,
	cmdlineErr error,
	cwdErr error,
) *exec.FileInfo {
	t.Helper()

	oldRootDirForPID := rootDirForPID
	oldCmdlineForPID := cmdlineForPID
	oldCwdForPID := cwdForPID
	rootDirForPID = func(app.PID) string { return root }
	cmdlineForPID = func(app.PID) (string, []string, error) {
		return "node", args, cmdlineErr
	}
	cwdForPID = func(app.PID) (string, error) { return "/app", cwdErr }
	t.Cleanup(func() {
		rootDirForPID = oldRootDirForPID
		cmdlineForPID = oldCmdlineForPID
		cwdForPID = oldCwdForPID
	})

	return exec.New(exec.Init{
		Pid: app.PID(1234),
		Service: svc.Attrs{
			EnvVars:  env,
			Metadata: map[attr.Name]string{},
		},
	})
}

func writeNodeFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, contents, 0o644))
}
