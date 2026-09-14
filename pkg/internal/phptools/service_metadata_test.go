// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools

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
	t.Run("nil process", func(t *testing.T) {
		require.EqualError(t, ResolveServiceMetadata(nil), "PHP service metadata requires process file info")
	})

	t.Run("complete metadata avoids process inspection", func(t *testing.T) {
		root := t.TempDir()
		fileInfo := mockPHPProcess(t, root, "/usr/bin/php", "/", nil, nil)
		fileInfo.SetExplicitServiceName("orders")
		fileInfo.SetMetadata(map[attr.Name]string{serviceVersion: "1.2.3"})
		rootDirForPID = func(app.PID) string {
			panic("process root must not be inspected")
		}
		cwdForPID = func(app.PID) (string, error) {
			panic("working directory must not be inspected")
		}
		cmdlineForPID = func(app.PID) (string, []string, error) {
			panic("command line must not be inspected")
		}

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
	})

	t.Run("FPM avoids command line inspection", func(t *testing.T) {
		root := t.TempDir()
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/", nil, map[string]string{
			appNameEnv: "Orders",
		})
		cmdlineForPID = func(app.PID) (string, []string, error) {
			panic("FPM command line must not be inspected")
		}

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "Orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Composer generated metadata matches the PHP SDK detector", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"composer/fallback"}`))
		writePHPFile(t, filepath.Join(root, "app", "vendor", "composer", "installed.php"), installedPHP("acme/orders-api", "2.4.1"))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm8.3", "/app", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "acme/orders-api", service.UID.Name)
		assert.Equal(t, "2.4.1", service.Metadata[serviceVersion])
		assert.True(t, service.AutoName())
	})

	t.Run("generated metadata works without composer.json", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "vendor", "composer", "installed.php"), installedPHP("acme/orders-api", "2.4.1"))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/app", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "acme/orders-api", service.UID.Name)
		assert.Equal(t, "2.4.1", service.Metadata[serviceVersion])
	})

	t.Run("composer.json is used when generated metadata is absent", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"acme/symfony-app","version":"1.3.0"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/app/public", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "acme/symfony-app", service.UID.Name)
		assert.Equal(t, "1.3.0", service.Metadata[serviceVersion])
	})

	t.Run("confirmed Symfony project uses directory name", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "my_app", "composer.json"), []byte(`{
            "name":"symfony/skeleton",
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))
		require.NoError(t, os.MkdirAll(filepath.Join(root, "my_app", "public"), 0o755))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/my_app/public", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "my_app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("unnamed Symfony project uses directory name", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "my_app", "composer.json"), []byte(`{
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/my_app", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "my_app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("process APP_NAME wins over Symfony directory", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "my_app", "composer.json"), []byte(`{
            "name":"symfony/skeleton",
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/my_app", nil, map[string]string{
			appNameEnv: "Orders API",
		})

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "Orders API", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("dotenv APP_NAME wins over Symfony directory", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "my_app", "composer.json"), []byte(`{
            "name":"symfony/skeleton",
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))
		writePHPFile(t, filepath.Join(root, "my_app", ".env"), []byte("APP_NAME=Orders API\n"))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/my_app", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "Orders API", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Symfony components alone do not enable directory naming", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "my_app", "composer.json"), []byte(`{
            "require":{"symfony/console":"^7.4","symfony/http-kernel":"^7.4"}
        }`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/my_app", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("PHP CLI script discovers Symfony without a symfony command", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "my_app", "composer.json"), []byte(`{
            "name":"symfony/skeleton",
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))
		writePHPFile(t, filepath.Join(root, "my_app", "bin", "console"), nil)
		fileInfo := mockPHPProcess(t, root, "/usr/bin/php", "/", []string{"/my_app/bin/console"}, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "my_app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("Composer name wins over APP_NAME", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"acme/orders"}`))
		writePHPFile(t, filepath.Join(root, "app", ".env"), []byte("APP_NAME=file-name\n"))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/app", nil, map[string]string{
			appNameEnv: "process-name",
		})

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "acme/orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("process APP_NAME does not require a Composer project", func(t *testing.T) {
		root := t.TempDir()
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/", nil, map[string]string{
			appNameEnv: "Checkout API",
		})

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "Checkout API", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("project dotenv supplies a literal APP_NAME", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{}`))
		writePHPFile(t, filepath.Join(root, "app", ".env"), []byte("APP_NAME=\"Orders API\" # service name\n"))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/app/public", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "Orders API", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("dotenv interpolation is ignored", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{}`))
		writePHPFile(t, filepath.Join(root, "app", ".env"), []byte("APP_NAME=\"${BASE_NAME} API\"\n"))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/app", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))
		fileInfo.ApplyServiceDefaults(svc.InstrumentablePHP)

		assert.Equal(t, "php-fpm", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("explicit name is preserved while Composer supplies version", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"acme/orders","version":"3.2.1"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/app", nil, nil)
		fileInfo.SetExplicitServiceName("production-orders")

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "production-orders", service.UID.Name)
		assert.Equal(t, "3.2.1", service.Metadata[serviceVersion])
		assert.False(t, service.AutoName())
	})

	t.Run("Composer version initializes missing metadata map", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"version":"3.2.1"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/app", nil, nil)
		fileInfo.SetExplicitServiceName("production-orders")
		fileInfo.SetMetadata(nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "3.2.1", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("explicit version is preserved while Composer supplies name", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"acme/orders","version":"3.2.1"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/app", nil, nil)
		fileInfo.SetMetadata(map[attr.Name]string{serviceVersion: "9.0.0"})

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "acme/orders", service.UID.Name)
		assert.Equal(t, "9.0.0", service.Metadata[serviceVersion])
	})

	t.Run("Composer placeholders are omitted", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{}`))
		writePHPFile(t, filepath.Join(root, "app", "vendor", "composer", "installed.php"), installedPHP(
			composerRootPlaceholder,
			composerVersionPlaceholder,
		))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/app", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		service := fileInfo.ServiceAttrs()
		assert.Empty(t, service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("PHP CLI script takes precedence over CWD", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "cli-app", "composer.json"), []byte(`{"name":"acme/cli"}`))
		writePHPFile(t, filepath.Join(root, "cli-app", "bin", "console"), nil)
		writePHPFile(t, filepath.Join(root, "cwd-app", "composer.json"), []byte(`{"name":"acme/cwd"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/bin/php", "/cwd-app", []string{
			"-d", "display_errors=1", "/cli-app/bin/console",
		}, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "acme/cli", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("malformed composer.json is ignored during parent search", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"acme/outer"}`))
		writePHPFile(t, filepath.Join(root, "app", "broken", "composer.json"), []byte(`{"name":`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/app/broken/public", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "acme/outer", fileInfo.ServiceAttrs().UID.Name)
	})
}

func TestResolveServiceMetadataInspectionErrors(t *testing.T) {
	t.Run("command line error", func(t *testing.T) {
		root := t.TempDir()
		fileInfo := mockPHPProcess(t, root, "/usr/bin/php", "/", nil, map[string]string{
			appNameEnv: "Orders",
		})
		cmdlineForPID = func(app.PID) (string, []string, error) {
			return "", nil, errors.New("command line failed")
		}

		err := ResolveServiceMetadata(fileInfo)

		require.ErrorContains(t, err, "command line failed")
		assert.Equal(t, "Orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("working directory and command line errors are joined", func(t *testing.T) {
		root := t.TempDir()
		fileInfo := mockPHPProcess(t, root, "/usr/bin/php", "/", nil, map[string]string{
			appNameEnv: "Orders",
		})
		cwdForPID = func(app.PID) (string, error) {
			return "", errors.New("working directory failed")
		}
		cmdlineForPID = func(app.PID) (string, []string, error) {
			return "", nil, errors.New("command line failed")
		}

		err := ResolveServiceMetadata(fileInfo)

		require.ErrorContains(t, err, "working directory failed")
		require.ErrorContains(t, err, "command line failed")
		assert.Equal(t, "Orders", fileInfo.ServiceAttrs().UID.Name)
	})
}

func TestInferredName(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		valid bool
	}{
		{name: "plain", value: "orders-api", want: "orders-api", valid: true},
		{name: "spaces are trimmed", value: "  Orders API  ", want: "Orders API", valid: true},
		{name: "empty"},
		{name: "whitespace", value: " \t "},
		{name: "dot", value: "."},
		{name: "dot dot", value: ".."},
		{name: "dash", value: "-"},
		{name: "root", value: "/"},
		{name: "control character", value: "orders\napi"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, valid := inferredName(test.value)
			assert.Equal(t, test.want, value)
			assert.Equal(t, test.valid, valid)
		})
	}
}

func TestPHPFPMProcessRootScan(t *testing.T) {
	t.Run("finds one nested Composer project", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "var", "www", "html", "composer.json"), []byte(`{"name":"acme/web"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "acme/web", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("multiple projects are ambiguous", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app-one", "composer.json"), []byte(`{"name":"acme/one"}`))
		writePHPFile(t, filepath.Join(root, "app-two", "composer.json"), []byte(`{"name":"acme/two"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("invalid Composer files do not make a scan ambiguous", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "broken", "composer.json"), []byte(`not-json`))
		writePHPFile(t, filepath.Join(root, "application", "composer.json"), []byte(`{"name":"acme/application"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "acme/application", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("does not scan past the depth limit", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "one", "two", "three", "four", "five", "composer.json"), []byte(`{"name":"acme/deep"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("names a Symfony project at the depth limit", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "one", "two", "three", "my_app", "composer.json"), []byte(`{
            "name":"symfony/skeleton",
            "require":{"symfony/framework-bundle":"^7.4"}
        }`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/", nil, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Equal(t, "my_app", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("does not recursively scan the host root", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"acme/host-app"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/sbin/php-fpm", "/", nil, nil)
		hostRoot = root

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("does not recursively scan for PHP CLI", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"acme/unrelated"}`))
		fileInfo := mockPHPProcess(t, root, "/usr/bin/php", "/", []string{"-r", "sleep(10);"}, nil)

		require.NoError(t, ResolveServiceMetadata(fileInfo))

		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})
}

func TestResolveServiceMetadataReturnsInspectionErrorsAfterApplyingAvailableMetadata(t *testing.T) {
	root := t.TempDir()
	writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"acme/orders"}`))
	writePHPFile(t, filepath.Join(root, "app", "index.php"), nil)
	fileInfo := mockPHPProcess(t, root, "/usr/bin/php", "/app", []string{"/app/index.php"}, nil)
	cwdForPID = func(app.PID) (string, error) {
		return "/app", errors.New("cwd inspection failed")
	}

	err := ResolveServiceMetadata(fileInfo)

	require.ErrorContains(t, err, "cwd inspection failed")
	assert.Equal(t, "acme/orders", fileInfo.ServiceAttrs().UID.Name)
}

func installedPHP(name, version string) []byte {
	return []byte(fmt.Sprintf(`<?php return array(
    'root' => array(
        'name' => '%s',
        'pretty_version' => '%s',
    ),
    'versions' => array(),
);`, name, version))
}

func mockPHPProcess(
	t *testing.T,
	root, executable, cwd string,
	args []string,
	env map[string]string,
) *exec.FileInfo {
	t.Helper()

	oldRootDirForPID := rootDirForPID
	oldCMDLineForPID := cmdlineForPID
	oldCWDForPID := cwdForPID
	oldHostRoot := hostRoot
	t.Cleanup(func() {
		rootDirForPID = oldRootDirForPID
		cmdlineForPID = oldCMDLineForPID
		cwdForPID = oldCWDForPID
		hostRoot = oldHostRoot
	})

	rootDirForPID = func(app.PID) string { return root }
	cmdlineForPID = func(app.PID) (string, []string, error) {
		return executable, args, nil
	}
	cwdForPID = func(app.PID) (string, error) { return cwd, nil }
	hostRoot = string(filepath.Separator)

	fileInfo := exec.New(exec.Init{
		Service:    svc.Attrs{},
		CmdExePath: executable,
		Pid:        1234,
	})
	fileInfo.ApplyEnvVariables(env)
	return fileInfo
}

func writePHPFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, contents, 0o644))
}
