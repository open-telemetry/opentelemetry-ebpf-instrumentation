// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/pythontools/frameworks"
)

func TestPythonPathDirs(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"app", "lib", "srv/shared"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "module.py"), nil, 0o644))
	host, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	app := filepath.Join(host, "app")
	lib := filepath.Join(host, "lib")
	shared := filepath.Join(host, "srv", "shared")

	for _, tc := range []struct {
		name       string
		pythonPath string
		cwd        string
		pathConfig frameworks.PythonPathConfig
		want       []string
	}{
		{name: "unset"},
		{name: "absolute entry", pythonPath: "/lib", want: []string{lib}},
		{name: "relative entry", pythonPath: "../lib", want: []string{lib}},
		{name: "entries keep their order", pythonPath: "/srv/shared:/lib", want: []string{shared, lib}},
		{name: "empty entries stand for the working directory", pythonPath: "::/lib:", want: []string{app, lib}},
		{name: "empty entry with the filesystem root as working directory", pythonPath: ":/lib", cwd: "/", want: []string{lib}},
		{name: "duplicates are dropped", pythonPath: "/lib:/lib/", want: []string{lib}},
		{name: "missing directory", pythonPath: "/missing"},
		{name: "file entry", pythonPath: "/module.py"},
		{name: "filesystem root", pythonPath: "/:/lib", want: []string{lib}},
		{name: "relative path up to the filesystem root", pythonPath: "../../.."},
		{
			name:       "ignored with -E or -I",
			pythonPath: "/lib",
			pathConfig: frameworks.PythonPathConfig{IgnorePythonEnvironment: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := tc.cwd
			if cwd == "" {
				cwd = "/app"
			}
			assert.Equal(t, tc.want, pythonPathDirs(root, cwd, tc.pathConfig, tc.pythonPath))
		})
	}
}

func TestAppOnImportPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		env  map[string]string
		want bool
	}{
		{name: "script", args: []string{"app.py"}, want: true},
		{name: "-P script", args: []string{"-P", "app.py"}, want: false},
		{name: "-I script", args: []string{"-I", "app.py"}, want: false},
		{name: "PYTHONSAFEPATH", args: []string{"app.py"}, env: map[string]string{"PYTHONSAFEPATH": "1"}, want: false},
		{name: "-E ignores PYTHONSAFEPATH", args: []string{"-E", "app.py"}, env: map[string]string{"PYTHONSAFEPATH": "1"}, want: true},
		{name: "-P launcher adds its own path", args: []string{"-P", "-m", "uvicorn", "app.main:app"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, appOnImportPath(parsePythonLaunch("python3", tc.args, tc.env), tc.env))
		})
	}
}

func TestPythonPathDirsFollowParsedLaunchFlags(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "lib"), 0o755))
	host, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	lib := filepath.Join(host, "lib")

	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{name: "script", args: []string{"app.py"}, want: []string{lib}},
		{name: "command string", args: []string{"-c", "import app"}, want: []string{lib}},
		{name: "command string with -E", args: []string{"-E", "-c", "import app"}},
		{name: "command string with -I", args: []string{"-I", "-c", "import app"}},
		{name: "combined -Ec", args: []string{"-Ec", "import app"}},
		{name: "stdin with -E", args: []string{"-E", "-"}},
		{name: "interactive with -I", args: []string{"-I"}},
		{name: "script with -E", args: []string{"-E", "app.py"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launch := parsePythonLaunch("python3", tc.args, nil)
			assert.Equal(t, tc.want, pythonPathDirs(root, "/", launch.PathConfig, "/lib"))
		})
	}
}
