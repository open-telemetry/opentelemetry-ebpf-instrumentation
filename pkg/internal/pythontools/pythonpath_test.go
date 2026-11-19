// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythontools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImportRootDirsFromPythonPath(t *testing.T) {
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := tc.cwd
			if cwd == "" {
				cwd = "/app"
			}
			assert.Equal(t, tc.want, importRootDirs(root, cwd, targetSearchRoots(cwd, nil, tc.pythonPath, false)))
		})
	}
}

func TestImportRootDirsFollowTheLaunch(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"app", "lib"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
	}
	host, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	app := filepath.Join(host, "app")
	lib := filepath.Join(host, "lib")
	pythonPath := map[string]string{"PYTHONPATH": "/lib"}
	safePythonPath := map[string]string{"PYTHONPATH": "/lib", "PYTHONSAFEPATH": "1"}

	for _, tc := range []struct {
		name string
		exe  string
		args []string
		env  map[string]string
		want []string
	}{
		{name: "script", args: []string{"server.py"}, env: pythonPath, want: []string{app, lib}},
		{name: "-P script", args: []string{"-P", "server.py"}, env: pythonPath, want: []string{lib}},
		{name: "-I script", args: []string{"-I", "server.py"}, env: pythonPath},
		{name: "-E script", args: []string{"-E", "server.py"}, env: pythonPath, want: []string{app}},
		{name: "PYTHONSAFEPATH", args: []string{"server.py"}, env: safePythonPath, want: []string{lib}},
		{name: "-E ignores PYTHONSAFEPATH", args: []string{"-E", "server.py"}, env: safePythonPath, want: []string{app}},
		{name: "command string", args: []string{"-c", "import server"}, env: pythonPath, want: []string{app, lib}},
		{name: "command string with -E", args: []string{"-E", "-c", "import server"}, env: pythonPath, want: []string{app}},
		{name: "command string with -I", args: []string{"-Ic", "import server"}, env: pythonPath},
		{name: "stdin with -E", args: []string{"-E", "-"}, env: pythonPath, want: []string{app}},
		{name: "-P launcher adding the application directory", args: []string{"-P", "-m", "uvicorn", "server:app"}, env: pythonPath, want: []string{app, lib}},
		{name: "-P launcher adding another directory", args: []string{"-P", "/app/manage.py", "runserver", "--pythonpath=/lib"}, env: pythonPath, want: []string{lib}},
		{name: "gunicorn search path before the application", exe: "gunicorn", args: []string{"--pythonpath=/lib", "project.wsgi:application"}, env: pythonPath, want: []string{lib, app}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exe := tc.exe
			if exe == "" {
				exe = "python3"
			}
			launch := parsePythonLaunch(exe, tc.args, tc.env)
			assert.Equal(t, tc.want, importRootDirs(root, "/app", importSearchPaths("/app", launch, tc.env)))
		})
	}
}
