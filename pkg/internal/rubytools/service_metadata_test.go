// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

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
)

func TestResolveServiceMetadata(t *testing.T) {
	t.Run("Rails application supplies its canonical name", func(t *testing.T) {
		root := t.TempDir()
		writeRailsApplication(t, root, "app", `
module OrdersAPI
  class Application < Rails::Application
  end
end
`)
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)
		fileInfo.SetUID(svc.UID{Namespace: "production"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders-api", service.UID.Name)
		assert.Equal(t, "production", service.UID.Namespace)
		assert.True(t, service.AutoName())
		assert.False(t, service.AutoNamespace())
	})

	t.Run("direct Rails application class is normalized", func(t *testing.T) {
		root := t.TempDir()
		writeRailsApplication(t, root, "app", "class BillingService < ::Rails::Application\nend\n")
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Equal(t, "billing-service", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("unusual Rails declaration falls back to project directory", func(t *testing.T) {
		root := t.TempDir()
		writeRailsApplication(t, root, "orders-service", "Application = Class.new(Rails::Application)\n")
		fileInfo := mockRubyProcess(t, root, "/orders-service", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Equal(t, "orders-service", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("multiple Rails applications fall back to project directory", func(t *testing.T) {
		root := t.TempDir()
		writeRailsApplication(t, root, "orders-service", `
module FirstApp
  class Application < Rails::Application
  end
end

module SecondApp
  class Application < Rails::Application
  end
end
`)
		fileInfo := mockRubyProcess(t, root, "/orders-service", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Equal(t, "orders-service", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("symlinked Rails application falls back to project directory", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "outside-application.rb")
		writeRubyFile(t, target, []byte("class OutsideApp < Rails::Application\n"))
		applicationPath := filepath.Join(root, "app", "config", "application.rb")
		require.NoError(t, os.MkdirAll(filepath.Dir(applicationPath), 0o755))
		require.NoError(t, os.Symlink(target, applicationPath))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Equal(t, "app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("symlinked config directory is not treated as Rails", func(t *testing.T) {
		root := t.TempDir()
		sharedConfig := filepath.Join(root, "shared-config")
		require.NoError(t, os.MkdirAll(sharedConfig, 0o755))
		appDir := filepath.Join(root, "app")
		require.NoError(t, os.MkdirAll(appDir, 0o755))
		require.NoError(t, os.Symlink(sharedConfig, filepath.Join(appDir, "config")))
		fileInfo := mockRubyProcess(t, root, "/app", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("entrypoint searches parent directories for a Rails root", func(t *testing.T) {
		root := t.TempDir()
		writeRailsApplication(t, root, "orders", `
module Orders
  class Application < Rails::Application
  end
end
`)
		writeRubyFile(t, filepath.Join(root, "orders", "bin", "server.rb"), nil)
		fileInfo := mockRubyProcess(t, root, "/", "ruby", []string{"/orders/bin/server.rb"}, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Sidekiq require path locates its Rails root", func(t *testing.T) {
		root := t.TempDir()
		writeRailsApplication(t, root, "orders", `
module Orders
  class Application < Rails::Application
  end
end
`)
		writeRubyFile(t, filepath.Join(root, "orders", "config", "environment.rb"), nil)
		fileInfo := mockRubyProcess(t, root, "/", "sidekiq", []string{
			"--require", "/orders/config/environment.rb",
		}, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("BUNDLE_GEMFILE locates a Rails root when cwd is a dependency", func(t *testing.T) {
		root := t.TempDir()
		writeRailsApplication(t, root, "orders", `
module Orders
  class Application < Rails::Application
  end
end
`)
		writeRubyFile(t, filepath.Join(root, "orders", "Gemfile.custom"), nil)
		require.NoError(t, os.MkdirAll(filepath.Join(root, "bundle", "puma"), 0o755))
		fileInfo := mockRubyProcess(t, root, "/bundle/puma", "puma", nil, map[string]string{
			gemHome:       "/bundle",
			bundleGemfile: "/orders/Gemfile.custom",
		})

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("plain Ruby script is ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "worker", "worker.rb"), nil)
		fileInfo := mockRubyProcess(t, root, "/worker", "ruby", []string{"worker.rb"}, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("gemspec is ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "worker", "orders.gemspec"), []byte(`
Gem::Specification.new "orders", "1.2.3"
`))
		fileInfo := mockRubyProcess(t, root, "/worker", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
		assert.Empty(t, fileInfo.ServiceAttrs().Metadata)
	})

	t.Run("Gemfile without Rails application is ignored", func(t *testing.T) {
		root := t.TempDir()
		writeRubyFile(t, filepath.Join(root, "worker", "Gemfile"), nil)
		fileInfo := mockRubyProcess(t, root, "/worker", "puma", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("explicit name is preserved", func(t *testing.T) {
		root := t.TempDir()
		writeRailsApplication(t, root, "orders", `
module Orders
  class Application < Rails::Application
  end
end
`)
		fileInfo := mockRubyProcess(t, root, "/orders", "puma", nil, nil)
		fileInfo.SetUID(svc.UID{Name: "configured", Namespace: "production"})

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "configured", service.UID.Name)
		assert.Equal(t, "production", service.UID.Namespace)
		assert.False(t, service.AutoName())
	})

	t.Run("process lookup errors are returned", func(t *testing.T) {
		root := t.TempDir()
		expectedErr := errors.New("process disappeared")
		fileInfo := mockRubyProcessWithErrors(t, root, "/app", nil, nil, expectedErr, expectedErr)

		err := ResolveServiceMetadata(fileInfo)

		require.ErrorIs(t, err, expectedErr)
	})
}

func writeRailsApplication(t *testing.T, root, project, source string) {
	t.Helper()
	writeRubyFile(t, filepath.Join(root, project, "config", "application.rb"), []byte(source))
}

func mockRubyProcess(
	t *testing.T,
	root, cwd, command string,
	args []string,
	env map[string]string,
) *exec.FileInfo {
	t.Helper()
	return mockRubyProcessWithErrors(t, root, cwd, env, []string{command}, nil, nil, args...)
}

func mockRubyProcessWithErrors(
	t *testing.T,
	root, cwd string,
	env map[string]string,
	command []string,
	cmdlineErr, cwdErr error,
	args ...string,
) *exec.FileInfo {
	t.Helper()

	oldRootDirForPID := rootDirForPID
	oldCmdlineForPID := cmdlineForPID
	oldCwdForPID := cwdForPID
	rootDirForPID = func(app.PID) string { return root }
	cmdlineForPID = func(app.PID) (string, []string, error) {
		var executable string
		if len(command) != 0 {
			executable = command[0]
		}
		return executable, args, cmdlineErr
	}
	cwdForPID = func(app.PID) (string, error) { return cwd, cwdErr }
	t.Cleanup(func() {
		rootDirForPID = oldRootDirForPID
		cmdlineForPID = oldCmdlineForPID
		cwdForPID = oldCwdForPID
	})

	return exec.New(exec.Init{
		Service: svc.Attrs{EnvVars: env},
		Pid:     123,
	})
}

func writeRubyFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, data, 0o644))
}
