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
