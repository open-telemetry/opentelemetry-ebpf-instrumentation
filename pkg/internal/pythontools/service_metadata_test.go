// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestResolveServiceMetadata(t *testing.T) {
	t.Run("pyproject supplies declared name and version", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders", "wsgi.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'Orders-Service'\nversion = '1.2.3'\n")
		fileInfo := mockPythonProcess(t, root, "gunicorn", []string{"orders.wsgi:application"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "Orders-Service", service.UID.Name)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
		assert.True(t, service.AutoName())
	})

	t.Run("pep 621 metadata wins over poetry", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), strings.Join([]string{
			"[project]",
			"name = 'pep-orders'",
			"version = '2.0'",
			"[tool.poetry]",
			"name = 'poetry-orders'",
			"version = '1.0'",
		}, "\n"))
		fileInfo := mockPythonProcess(t, root, "python", []string{"orders.py"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "pep-orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "2.0", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("poetry metadata", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[tool.poetry]\nname = 'poetry-orders'\nversion = '3.1'\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{"orders.py"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "poetry-orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "3.1", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("setup cfg metadata", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[build-system]\nrequires = []\n")
		writePythonFile(t, filepath.Join(root, "app", "setup.cfg"), "[metadata]\nname = setup-orders\nversion = 4.0\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{"orders.py"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "setup-orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "4.0", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("dynamic versions are ignored", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'orders'\ndynamic = ['version']\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{"orders.py"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Empty(t, fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("invalid declared name falls back to the target", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = '../outside'\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{"orders.py"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("explicit identity is preserved while project supplies version", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'project-orders'\nversion = '1.2.3'\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{"orders.py"}, nil, "/app")
		fileInfo.SetUID(svc.UID{Name: "explicit-orders", Namespace: "production"})

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "explicit-orders", service.UID.Name)
		assert.Equal(t, "production", service.UID.Namespace)
		assert.Equal(t, "1.2.3", service.Metadata[serviceVersion])
		assert.False(t, service.AutoName())
	})

	t.Run("nearest project is a boundary without a name", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'workspace'\nversion = '1.0'\n")
		writePythonFile(t, filepath.Join(root, "app", "services", "orders", "pyproject.toml"), "[project]\nversion = '2.0'\n")
		writePythonFile(t, filepath.Join(root, "app", "services", "orders", "orders", "api.py"), "")
		fileInfo := mockPythonProcess(t, root, "uvicorn", []string{"orders.api:app"}, nil, "/app/services/orders")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Equal(t, "2.0", service.Metadata[serviceVersion])
	})

	t.Run("malformed nearest project falls back without using parent", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'workspace'\n")
		writePythonFile(t, filepath.Join(root, "app", "services", "orders", "pyproject.toml"), "[project\nname = 'broken'\n")
		writePythonFile(t, filepath.Join(root, "app", "services", "orders", "company", "orders", "api.py"), "")
		fileInfo := mockPythonProcess(t, root, "uvicorn", []string{"company.orders.api:app"}, nil, "/app/services/orders")

		err := ResolveServiceMetadata(fileInfo)

		require.Error(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("unrecognized nearest project is a boundary", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'workspace'\n")
		writePythonFile(t, filepath.Join(root, "app", "services", "orders", "pyproject.toml"), "[build-system]\nrequires = []\n")
		writePythonFile(t, filepath.Join(root, "app", "services", "orders", "orders", "api.py"), "")
		fileInfo := mockPythonProcess(t, root, "uvicorn", []string{"orders.api:app"}, nil, "/app/services/orders")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("project above cwd is ignored when target resolves elsewhere", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "workspace", "pyproject.toml"), "[project]\nname = 'workspace'\n")
		writePythonFile(t, filepath.Join(root, "services", "company", "orders", "api.py"), "")
		fileInfo := mockPythonProcess(t, root, "uvicorn", []string{"company.orders.api:app"}, map[string]string{
			"PYTHONPATH": "/services",
		}, "/workspace")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("fastapi entrypoint associates project", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "backend", "main.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), strings.Join([]string{
			"[project]",
			"name = 'fast-orders'",
			"version = '5.0'",
			"[tool.fastapi]",
			"entrypoint = 'backend.main:app'",
		}, "\n"))
		fileInfo := mockPythonProcess(t, root, "fastapi", []string{"run"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "fast-orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "5.0", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("flask automatic app associates project", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "app.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'flask-orders'\nversion = '1.0'\n")
		fileInfo := mockPythonProcess(t, root, "flask", []string{"run"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "flask-orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "1.0", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("flask automatic generic target remains unnamed", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "wsgi.py"), "")
		fileInfo := mockPythonProcess(t, root, "flask", []string{"run"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("fastapi command entrypoint associates project", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "company", "orders", "api.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'fast-orders'\n")
		fileInfo := mockPythonProcess(t, root, "fastapi", []string{
			"run", "--entrypoint", "company.orders.api:app",
		}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "fast-orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("waitress dotted factory associates project", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "company", "orders", "wsgi.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'waitress-orders'\n")
		fileInfo := mockPythonProcess(t, root, "waitress-serve", []string{
			"--call", "company.orders.wsgi.application.create_app",
		}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "waitress-orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("waitress dotted factory falls back to resolved module name", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "company", "orders", "wsgi.py"), "")
		fileInfo := mockPythonProcess(t, root, "waitress-serve", []string{
			"--call", "company.orders.wsgi.create_app",
		}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("unresolved waitress dotted factory remains unnamed", func(t *testing.T) {
		root := t.TempDir()
		fileInfo := mockPythonProcess(t, root, "waitress-serve", []string{
			"--call", "company.orders.wsgi.create_app",
		}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("gunicorn name is final fallback", func(t *testing.T) {
		root := t.TempDir()
		fileInfo := mockPythonProcess(t, root, "gunicorn", []string{"--name", "orders-worker", "-b", "0.0.0.0:8080"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders-worker", fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("generic script remains unnamed", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "main.py"), "")
		fileInfo := mockPythonProcess(t, root, "python", []string{"main.py"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})

	t.Run("missing exact script does not borrow project metadata", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'wrong-project'\nversion = '9.9'\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{"orders"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Empty(t, fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("symlink escape cannot supply project metadata", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		writePythonFile(t, filepath.Join(outside, "company", "orders", "api.py"), "")
		writePythonFile(t, filepath.Join(outside, "pyproject.toml"), "[project]\nname = 'outside-name'\nversion = '9.9'\n")
		require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "app", "escape")))
		fileInfo := mockPythonProcess(t, root, "uvicorn", []string{"--app-dir", "/app/escape", "company.orders.api:app"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("gunicorn chdir cannot escape through a symlink", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		writePythonFile(t, filepath.Join(outside, "orders", "wsgi.py"), "")
		writePythonFile(t, filepath.Join(outside, "pyproject.toml"), "[project]\nname = 'outside-name'\nversion = '9.9'\n")
		require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "app", "escape")))
		fileInfo := mockPythonProcess(t, root, "gunicorn", []string{"--chdir", "/app/escape", "orders.wsgi:application"}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		service := fileInfo.ServiceAttrs()
		assert.Equal(t, "orders", service.UID.Name)
		assert.Empty(t, service.Metadata[serviceVersion])
	})

	t.Run("process lookup error is returned", func(t *testing.T) {
		root := t.TempDir()
		expectedErr := errors.New("process disappeared")
		fileInfo := mockPythonProcessWithErrors(t, root, "python", nil, nil, "/app", expectedErr, expectedErr)

		err := ResolveServiceMetadata(fileInfo)

		require.ErrorIs(t, err, expectedErr)
		assert.Empty(t, fileInfo.ServiceAttrs().UID.Name)
	})
}

func TestResolveServiceMetadataHonorsInterpreterPathIsolation(t *testing.T) {
	t.Run("ignore environment excludes pythonpath", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "libs", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "libs", "pyproject.toml"), "[project]\nname = 'path-orders'\nversion = '2'\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{"-E", "-m", "orders"}, map[string]string{
			"PYTHONPATH": "/libs",
		}, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Empty(t, fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	tests := []struct {
		name        string
		args        []string
		env         map[string]string
		wantName    string
		wantVersion string
	}{
		{
			name:        "default prefers cwd",
			args:        []string{"-m", "orders"},
			wantName:    "cwd-orders",
			wantVersion: "1",
		},
		{
			name:        "safe path omits automatic cwd",
			args:        []string{"-P", "-m", "orders"},
			wantName:    "path-orders",
			wantVersion: "2",
		},
		{
			name:        "python safe path accepts any nonempty value",
			args:        []string{"-m", "orders"},
			env:         map[string]string{"PYTHONSAFEPATH": "0"},
			wantName:    "path-orders",
			wantVersion: "2",
		},
		{
			name:     "isolated mode omits cwd and ignores pythonpath",
			args:     []string{"-I", "-m", "orders"},
			wantName: "orders",
		},
		{
			name:        "ignore Python environment disables safe path",
			args:        []string{"-E", "-m", "orders"},
			env:         map[string]string{"PYTHONSAFEPATH": "1"},
			wantName:    "cwd-orders",
			wantVersion: "1",
		},
		{
			name:        "pythonpath can explicitly reintroduce cwd",
			args:        []string{"-P", "-m", "orders"},
			env:         map[string]string{"PYTHONPATH": ":/libs"},
			wantName:    "cwd-orders",
			wantVersion: "1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
			writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'cwd-orders'\nversion = '1'\n")
			writePythonFile(t, filepath.Join(root, "libs", "orders.py"), "")
			writePythonFile(t, filepath.Join(root, "libs", "pyproject.toml"), "[project]\nname = 'path-orders'\nversion = '2'\n")
			env := map[string]string{"PYTHONPATH": "/libs"}
			for name, value := range test.env {
				env[name] = value
			}
			fileInfo := mockPythonProcess(t, root, "python", test.args, env, "/app")

			err := ResolveServiceMetadata(fileInfo)

			require.NoError(t, err)
			assert.Equal(t, test.wantName, fileInfo.ServiceAttrs().UID.Name)
			assert.Equal(t, test.wantVersion, fileInfo.ServiceAttrs().Metadata[serviceVersion])
		})
	}

	t.Run("direct script remains exact in isolated mode", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'cwd-orders'\nversion = '1'\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{"-I", "orders.py"}, map[string]string{
			"PYTHONPATH": "/libs",
		}, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "cwd-orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "1", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("fastapi file remains cwd relative", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'cwd-orders'\nversion = '1'\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{
			"-I", "-m", "fastapi", "run", "orders.py",
		}, map[string]string{"PYTHONPATH": "/libs"}, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "cwd-orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "1", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("isolation survives module launcher delegation", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "libs", "orders", "api.py"), "")
		writePythonFile(t, filepath.Join(root, "libs", "pyproject.toml"), "[project]\nname = 'path-orders'\nversion = '2'\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{
			"-E", "-m", "uvicorn", "orders.api:app",
		}, map[string]string{"PYTHONPATH": "/libs"}, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Empty(t, fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("launcher default app directory remains explicit", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders", "api.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'cwd-orders'\nversion = '1'\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{
			"-I", "-m", "uvicorn", "orders.api:app",
		}, map[string]string{"PYTHONPATH": "/libs"}, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "cwd-orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "1", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})

	t.Run("gunicorn pythonpath remains explicit in isolated mode", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders", "wsgi.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "pyproject.toml"), "[project]\nname = 'cwd-orders'\nversion = '1'\n")
		writePythonFile(t, filepath.Join(root, "libs", "orders", "wsgi.py"), "")
		writePythonFile(t, filepath.Join(root, "libs", "pyproject.toml"), "[project]\nname = 'path-orders'\nversion = '2'\n")
		fileInfo := mockPythonProcess(t, root, "python", []string{
			"-I", "-m", "gunicorn", "--pythonpath=/libs", "orders.wsgi:application",
		}, nil, "/app")

		err := ResolveServiceMetadata(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, "path-orders", fileInfo.ServiceAttrs().UID.Name)
		assert.Equal(t, "2", fileInfo.ServiceAttrs().Metadata[serviceVersion])
	})
}

func TestResolveTargetPathMatchesPython(t *testing.T) {
	t.Run("extensionless script path is accepted", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders"), "")
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		launch := parsePythonLaunch("python", []string{"orders"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, nil)

		assert.True(t, found)
		assert.Equal(t, filepath.Join(root, "app", "orders"), path)
		assert.Equal(t, "orders", target)
	})

	t.Run("script path is exact", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		launch := parsePythonLaunch("python", []string{"orders"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, nil)

		assert.False(t, found)
		assert.Empty(t, path)
		assert.Empty(t, target)
	})

	t.Run("script directory requires main", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "orders", "__init__.py"), "")
		launch := parsePythonLaunch("python", []string{"orders"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, nil)

		assert.False(t, found)
		assert.Empty(t, path)
		assert.Empty(t, target)
	})

	t.Run("script path ignores pythonpath", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "libs", "orders"), "")
		launch := parsePythonLaunch("python", []string{"orders"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, map[string]string{"PYTHONPATH": "/libs"})

		assert.False(t, found)
		assert.Empty(t, path)
		assert.Empty(t, target)
	})

	t.Run("script directory executes main", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "orders", "__main__.py"), "")
		launch := parsePythonLaunch("python", []string{"orders"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, nil)

		assert.True(t, found)
		assert.Equal(t, filepath.Join(root, "app", "orders", "__main__.py"), path)
		assert.Equal(t, "orders", target)
	})

	t.Run("runnable package precedes module", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "orders", "__init__.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "orders", "__main__.py"), "")
		launch := parsePythonLaunch("python", []string{"-m", "orders"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, nil)

		assert.True(t, found)
		assert.Equal(t, filepath.Join(root, "app", "orders", "__main__.py"), path)
		assert.Equal(t, "orders", target)
	})

	t.Run("runnable module executes module file", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		launch := parsePythonLaunch("python", []string{"-m", "orders"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, nil)

		assert.True(t, found)
		assert.Equal(t, filepath.Join(root, "app", "orders.py"), path)
		assert.Equal(t, "orders", target)
	})

	t.Run("runnable package without main blocks module", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "orders", "__init__.py"), "")
		launch := parsePythonLaunch("python", []string{"-m", "orders"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, nil)

		assert.False(t, found)
		assert.Empty(t, path)
		assert.Empty(t, target)
	})

	t.Run("runnable namespace package executes main", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders", "__main__.py"), "")
		launch := parsePythonLaunch("python", []string{"-m", "orders"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, nil)

		assert.True(t, found)
		assert.Equal(t, filepath.Join(root, "app", "orders", "__main__.py"), path)
		assert.Equal(t, "orders", target)
	})

	t.Run("framework import prefers package", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "orders", "__init__.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "orders", "api.py"), "")
		writePythonFile(t, filepath.Join(root, "app", "orders", "api", "__init__.py"), "")
		launch := parsePythonLaunch("uvicorn", []string{"orders.api:app"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, nil)

		assert.True(t, found)
		assert.Equal(t, filepath.Join(root, "app", "orders", "api", "__init__.py"), path)
		assert.Equal(t, "orders.api", target)
	})

	t.Run("parent module blocks lower import", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "company.py"), "")
		writePythonFile(t, filepath.Join(root, "libs", "company", "orders.py"), "")
		launch := parsePythonLaunch("uvicorn", []string{"company.orders:app"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, map[string]string{"PYTHONPATH": "/libs"})

		assert.False(t, found)
		assert.Empty(t, path)
		assert.Empty(t, target)
	})

	t.Run("parent package blocks lower import", func(t *testing.T) {
		root := t.TempDir()
		writePythonFile(t, filepath.Join(root, "app", "company", "__init__.py"), "")
		writePythonFile(t, filepath.Join(root, "libs", "company", "orders.py"), "")
		launch := parsePythonLaunch("uvicorn", []string{"company.orders:app"}, nil)

		path, target, found := resolveTargetPath(root, "/app", launch, map[string]string{"PYTHONPATH": "/libs"})

		assert.False(t, found)
		assert.Empty(t, path)
		assert.Empty(t, target)
	})
}

func TestProjectFileLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pyproject.toml")
	require.NoError(t, os.WriteFile(path, make([]byte, maxProjectFileBytes+1), 0o644))

	file, found, _ := readProjectFile(path)

	assert.True(t, found)
	require.Nil(t, file)
}

func mockPythonProcess(
	t *testing.T,
	root string,
	executable string,
	args []string,
	env map[string]string,
	cwd string,
) *exec.FileInfo {
	t.Helper()
	return mockPythonProcessWithErrors(t, root, executable, args, env, cwd, nil, nil)
}

func mockPythonProcessWithErrors(
	t *testing.T,
	root string,
	executable string,
	args []string,
	env map[string]string,
	cwd string,
	cmdlineErr error,
	cwdErr error,
) *exec.FileInfo {
	t.Helper()

	oldRootDirForPID := rootDirForPID
	oldCmdlineForPID := cmdlineForPID
	oldCwdForPID := cwdForPID
	rootDirForPID = func(app.PID) string { return root }
	cmdlineForPID = func(app.PID) (string, []string, error) { return executable, args, cmdlineErr }
	cwdForPID = func(app.PID) (string, error) { return cwd, cwdErr }
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

func writePythonFile(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
}
