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

func TestAppDir(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	for _, dir := range []string{"work", "src/api", "srv"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
	}

	tests := []struct {
		name   string
		launch frameworks.PythonLaunch
		want   string
	}{
		{name: "cwd", want: "work"},
		{name: "app dir", launch: frameworks.PythonLaunch{AppDir: "/srv"}, want: "srv"},
		{name: "file", launch: frameworks.PythonLaunch{Target: "../src/api/main.py", TargetKind: frameworks.TargetFile}, want: "src/api"},
		{name: "script dir", launch: frameworks.PythonLaunch{Target: "api:app", TargetKind: frameworks.TargetModule, ScriptDir: "/src/api"}, want: "src/api"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := appDir(root, "/work", tt.launch)
			require.NoError(t, err)
			assert.Equal(t, filepath.Join(root, tt.want), got)
		})
	}
}

func TestAppDirDoesNotUseSearchPaths(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "work"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "libs"), 0o755))

	got, err := appDir(root, "/work", frameworks.PythonLaunch{SearchPaths: []string{"/libs"}})

	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "work"), got)
}

func TestAppDirForPIDGunicornChdir(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "srv", "app"), 0o755))

	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "relative", args: []string{"--chdir", "app", "orders:app"}},
		{name: "relative attached", args: []string{"--chdir=app", "orders:app"}},
		{name: "environment", args: []string{"orders:app"}, env: map[string]string{"GUNICORN_CMD_ARGS": "--chdir app"}},
		{name: "absolute", args: []string{"--chdir", "/srv/app", "orders:app"}},
		{name: "default", args: []string{"orders:app"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileInfo := mockPythonProcess(t, root, "python", append([]string{"/venv/bin/gunicorn"}, tt.args...), tt.env, "/srv/app")

			got, err := AppDirForPID(fileInfo.Pid(), tt.env)

			require.NoError(t, err)
			assert.Equal(t, filepath.Join(root, "srv", "app"), got)
		})
	}
}
