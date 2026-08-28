// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package denotools

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
	t.Run("deno jsonc supplies scoped identity and package fills version", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "src", "main.ts"), nil)
		writeDenoFile(t, filepath.Join(root, "app", "deno.jsonc"), []byte(`{
			// JSR identity
			"name": "@acme/orders",
		}`))
		writeDenoFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"ignored","version":"1.2.3"}`))
		fileInfo := mockDenoProcess(t, root, []string{"run", "src/main.ts"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "acme", service.UID.Namespace)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
		assert.True(t, service.AutoName())
		assert.True(t, service.AutoNamespace())
	})

	t.Run("deno json is preferred over deno jsonc and package json", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "main.ts"), nil)
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"deno","version":"2.0.0"}`))
		writeDenoFile(t, filepath.Join(root, "app", "deno.jsonc"), []byte(`{"name":"jsonc"}`))
		writeDenoFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"package","version":"1.0.0"}`))
		fileInfo := mockDenoProcess(t, root, []string{"run", "main.ts"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "deno", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "2.0.0", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("nameless nearer config does not cross-associate its version", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"orders","version":"1.0.0"}`))
		writeDenoFile(t, filepath.Join(root, "app", "src", "deno.json"), []byte(`{"version":"2.0.0"}`))
		writeDenoFile(t, filepath.Join(root, "app", "src", "main.ts"), nil)
		fileInfo := mockDenoProcess(t, root, []string{"run", "src/main.ts"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "1.0.0", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("nearer named config does not borrow an outer version", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"outer","version":"1.0.0"}`))
		writeDenoFile(t, filepath.Join(root, "app", "src", "deno.json"), []byte(`{"name":"worker"}`))
		writeDenoFile(t, filepath.Join(root, "app", "src", "main.ts"), nil)
		fileInfo := mockDenoProcess(t, root, []string{"run", "src/main.ts"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "worker", fileInfo.ServiceAttrs().UID.Name)
		version, ok := fileInfo.ServiceAttrs().Metadata[serviceVersion]
		assert.False(t, ok)
		assert.Empty(t, version)
	})

	t.Run("nearer named config does not borrow an outer version 2", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"outer","version":"1.0.0"}`))
		writeDenoFile(t, filepath.Join(root, "app", "src", "deno.json"), []byte(`{"name":"worker"}`))
		writeDenoFile(t, filepath.Join(root, "app", "src", "main.ts"), nil)
		fileInfo := mockDenoProcess(t, root, []string{"run", "src/main.ts"}, nil)
		fileInfo.SetAutoServiceName("my-service")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "my-service", fileInfo.ServiceAttrs().UID.Name)
		version, ok := fileInfo.ServiceAttrs().Metadata[serviceVersion]
		assert.False(t, ok)
		assert.Empty(t, version)
	})

	t.Run("explicit config takes precedence over entrypoint project", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "config", "service.jsonc"), []byte(`{"name":"configured","version":"3.0.0"}`))
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"entrypoint"}`))
		writeDenoFile(t, filepath.Join(root, "app", "main.ts"), nil)
		fileInfo := mockDenoProcess(t, root, []string{
			"run", "--config", "/config/service.jsonc", "main.ts",
		}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "configured", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "3.0.0", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("explicit config directory cannot escape the process root", func(t *testing.T) {
		outer := t.TempDir()
		root := filepath.Join(outer, "process-root")
		writeDenoFile(t, filepath.Join(outer, "package.json"), []byte(`{"name":"host-project"}`))
		writeDenoFile(t, filepath.Join(root, "app", "main.ts"), nil)
		fileInfo := mockDenoProcess(t, root, []string{"run", "--config", "/", "main.ts"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "main", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("no config still permits package json", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "main.ts"), nil)
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"deno"}`))
		writeDenoFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"package"}`))
		fileInfo := mockDenoProcess(t, root, []string{"run", "--no-config", "main.ts"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "package", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("DENO_NO_PACKAGE_JSON disables package discovery", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "main.ts"), nil)
		writeDenoFile(t, filepath.Join(root, "app", "package.json"), []byte(`{"name":"package"}`))
		fileInfo := mockDenoProcess(t, root, []string{"run", "main.ts"}, map[string]string{
			denoNoPackageJSON: "1",
		})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "main", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("JSR specifier supplies package identity and exact version", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", ".keep"), nil)
		fileInfo := mockDenoProcess(t, root, []string{
			"run", "jsr:@acme/orders@1.2.3/server",
		}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "acme", service.UID.Namespace)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
	})

	t.Run("registry version ranges are not service versions", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", ".keep"), nil)
		fileInfo := mockDenoProcess(t, root, []string{"run", "npm:orders@^1.2.0/worker"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Empty(t, fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	for _, version := range []string{"1", "1.2"} {
		t.Run("partial registry version "+version+" is not exact", func(t *testing.T) {
			root := t.TempDir()
			writeDenoFile(t, filepath.Join(root, "app", ".keep"), nil)
			fileInfo := mockDenoProcess(t, root, []string{"run", "npm:orders@" + version}, nil)

			err := ResolveServiceMetadata(fileInfo)

			require.NoError(t, err)
			assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
			assert.Empty(t, fileInfo.ServiceAttrs().Metadata[serviceVersion])
		})
	}

	t.Run("HTTP entrypoint uses only the URL path basename", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"cwd-project"}`))
		fileInfo := mockDenoProcess(t, root, []string{
			"run", "https://example.test/apps/orders.ts?revision=2#start",
		}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("file URL participates in local project discovery", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "opt", "orders", "main.ts"), nil)
		writeDenoFile(t, filepath.Join(root, "opt", "orders", "deno.json"), []byte(`{"name":"file-project"}`))
		fileInfo := mockDenoProcess(t, root, []string{"run", "file:///opt/orders/main.ts"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "file-project", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("direct shorthand must resolve to a local entrypoint", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"cwd-project"}`))
		fileInfo := mockDenoProcess(t, root, []string{"future-command"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("direct shorthand is validated before explicit config", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"configured"}`))
		fileInfo := mockDenoProcess(t, root, []string{"--config", "deno.json", "future-command"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("direct node modules shorthand must exist", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"application"}`))
		fileInfo := mockDenoProcess(t, root, []string{"node_modules/missing-tool"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("direct shorthand after option terminator must exist", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"application"}`))
		fileInfo := mockDenoProcess(t, root, []string{"--", "future-command"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("extensionless direct shorthand resolves an existing entrypoint", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "server"), nil)
		fileInfo := mockDenoProcess(t, root, []string{"server"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "server", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("node modules entrypoint restarts lookup from cwd", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"application"}`))
		writeDenoFile(t, filepath.Join(root, "app", "node_modules", "tool", "cli.ts"), nil)
		writeDenoFile(t, filepath.Join(root, "app", "node_modules", "tool", "deno.json"), []byte(`{"name":"tool"}`))
		fileInfo := mockDenoProcess(t, root, []string{"run", "node_modules/tool/cli.ts"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "application", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("cwd inside node modules does not use dependency metadata", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"application"}`))
		writeDenoFile(t, filepath.Join(root, "app", "node_modules", "tool", "deno.json"), []byte(`{"name":"tool"}`))
		writeDenoFile(t, filepath.Join(root, "app", "node_modules", "tool", "cli.ts"), nil)
		fileInfo := mockDenoProcess(t, root, []string{"run", "cli.ts"}, nil)
		cwdForPID = func(app.PID) (string, error) { return "/app/node_modules/tool", nil }

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "application", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("explicit identity is preserved while nearest config supplies version", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "main.ts"), nil)
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"version":"4.0.0"}`))
		fileInfo := mockDenoProcess(t, root, []string{"run", "main.ts"}, nil)
		fileInfo.SetUID(svc.UID{Name: "explicit", Namespace: "production"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "explicit", service.UID.Name)
		assert.Equal(t, "production", service.UID.Namespace)
		assert.Equal(t, "4.0.0", service.Metadata[serviceVersion])
		assert.False(t, service.AutoName())
	})

	t.Run("scoped name preserves an explicit namespace", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "main.ts"), nil)
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"@acme/orders"}`))
		fileInfo := mockDenoProcess(t, root, []string{"run", "main.ts"}, nil)
		fileInfo.SetUID(svc.UID{Namespace: "production"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "production", service.UID.Namespace)
		assert.True(t, service.AutoName())
		assert.False(t, service.AutoNamespace())
	})

	t.Run("unsupported URL does not use unrelated cwd metadata", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"cwd-project"}`))
		fileInfo := mockDenoProcess(t, root, []string{"run", "data:text/javascript,console.log(1)"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("project lookup does not walk beyond the process root", func(t *testing.T) {
		outer := t.TempDir()
		root := filepath.Join(outer, "process-root")
		writeDenoFile(t, filepath.Join(outer, "deno.json"), []byte(`{"name":"host-project"}`))
		writeDenoFile(t, filepath.Join(root, "app", "main.ts"), nil)
		fileInfo := mockDenoProcess(t, root, []string{"run", "main.ts"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "main", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("task supervisor is not named", func(t *testing.T) {
		root := t.TempDir()
		writeDenoFile(t, filepath.Join(root, "app", "deno.json"), []byte(`{"name":"task-project"}`))
		fileInfo := mockDenoProcess(t, root, []string{"task", "start"}, nil)

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("process lookup failure is returned", func(t *testing.T) {
		root := t.TempDir()
		expectedErr := errors.New("process disappeared")
		fileInfo := mockDenoProcessWithErrors(t, root, nil, nil, expectedErr, expectedErr)

		err := ResolveServiceMetadata(fileInfo)

		require.ErrorIs(t, err, expectedErr)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})
}

func TestReadMetadataFile(t *testing.T) {
	t.Run("invalid field does not discard valid field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "deno.json")
		writeDenoFile(t, path, []byte(`{"name":"orders","version":1}`))

		metadata, found := readMetadataFile(path, false)

		assert.True(t, found)
		assert.Equal(t, "orders", metadata.Name)
		assert.Empty(t, metadata.Version)
	})

	t.Run("oversized file is ignored safely", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "deno.json")
		writeDenoFile(t, path, make([]byte, maxServiceMetadataBytes+1))

		metadata, found := readMetadataFile(path, false)

		assert.True(t, found)
		assert.Empty(t, metadata)
	})

	t.Run("symlink is not followed", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "outside.json")
		writeDenoFile(t, target, []byte(`{"name":"outside"}`))
		path := filepath.Join(dir, "deno.json")
		require.NoError(t, os.Symlink(target, path))

		metadata, found := readMetadataFile(path, false)

		assert.True(t, found)
		assert.Empty(t, metadata)
	})
}

func mockDenoProcess(t *testing.T, root string, args []string, env map[string]string) *exec.FileInfo {
	t.Helper()
	return mockDenoProcessWithErrors(t, root, args, env, nil, nil)
}

func mockDenoProcessWithErrors(
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
		return "deno", args, cmdlineErr
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

func writeDenoFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, contents, 0o644))
}
