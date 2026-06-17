// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java

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
)

func TestParseJavaLaunch(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		expected javaLaunch
	}{
		{
			name:     "jar wins over classpath",
			args:     []string{"-cp", "/classes", "-jar", "/app.jar"},
			env:      map[string]string{envClasspath: "/env-classes"},
			expected: javaLaunch{jar: "/app.jar"},
		},
		{
			name:     "short classpath flag",
			args:     []string{"-cp", "/classes", "com.example.Main"},
			expected: javaLaunch{classpath: "/classes"},
		},
		{
			name:     "long classpath flag",
			args:     []string{"--class-path", "/classes", "com.example.Main"},
			expected: javaLaunch{classpath: "/classes"},
		},
		{
			name:     "long classpath flag with equals",
			args:     []string{"--class-path=/classes", "com.example.Main"},
			expected: javaLaunch{classpath: "/classes"},
		},
		{
			name:     "legacy classpath flag",
			args:     []string{"-classpath", "/classes", "com.example.Main"},
			expected: javaLaunch{classpath: "/classes"},
		},
		{
			name:     "last explicit classpath wins",
			args:     []string{"-cp", "/old", "--class-path=/new", "com.example.Main"},
			expected: javaLaunch{classpath: "/new"},
		},
		{
			name:     "env classpath fallback",
			args:     []string{"com.example.Main"},
			env:      map[string]string{envClasspath: "/env-classes"},
			expected: javaLaunch{classpath: "/env-classes"},
		},
		{
			name:     "explicit classpath wins over env",
			args:     []string{"-cp", "/classes", "com.example.Main"},
			env:      map[string]string{envClasspath: "/env-classes"},
			expected: javaLaunch{classpath: "/classes"},
		},
		{
			name:     "missing jar value",
			args:     []string{"-jar"},
			expected: javaLaunch{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseJavaLaunch(tt.args, tt.env))
		})
	}
}

func TestScanRootsFromClasspath(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "classes"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "lib"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "lib"), 0o755))
	writeFile(t, filepath.Join(root, "app", "app.jar"))
	writeFile(t, filepath.Join(root, "app", "lib", "dep.jar"))
	writeFile(t, filepath.Join(root, "app", "lib", "plugin.war"))
	writeFile(t, filepath.Join(root, "app", "lib", "notes.txt"))
	writeFile(t, filepath.Join(root, "lib", "dep.jar"))
	writeFile(t, filepath.Join(root, "app", "notes.txt"))

	t.Run("returns directories and archives in classpath order", func(t *testing.T) {
		classpath := strings.Join([]string{"classes", "app.jar", "lib/*"}, string(filepath.ListSeparator))

		roots := scanRootsFromClasspath(root, "/app", classpath)

		assert.Equal(t, []scanRoot{
			{path: filepath.Join(root, "app", "classes"), dir: true},
			{path: filepath.Join(root, "app", "app.jar")},
			{path: filepath.Join(root, "app", "lib", "dep.jar")},
			{path: filepath.Join(root, "app", "lib", "plugin.war")},
		}, roots)
	})

	t.Run("returns a single archive", func(t *testing.T) {
		roots := scanRootsFromClasspath(root, "/app", "app.jar")

		require.Len(t, roots, 1)
		assert.False(t, roots[0].dir)
		assert.Equal(t, filepath.Join(root, "app", "app.jar"), roots[0].path)
	})

	t.Run("returns multiple archives", func(t *testing.T) {
		classpath := strings.Join([]string{"app.jar", "/lib/dep.jar"}, string(filepath.ListSeparator))

		roots := scanRootsFromClasspath(root, "/app", classpath)

		assert.Equal(t, []scanRoot{
			{path: filepath.Join(root, "app", "app.jar")},
			{path: filepath.Join(root, "lib", "dep.jar")},
		}, roots)
	})

	t.Run("expands wildcard archive entries", func(t *testing.T) {
		classpath := strings.Join([]string{"app.jar", "lib/*"}, string(filepath.ListSeparator))

		roots := scanRootsFromClasspath(root, "/app", classpath)

		assert.Equal(t, []scanRoot{
			{path: filepath.Join(root, "app", "app.jar")},
			{path: filepath.Join(root, "app", "lib", "dep.jar")},
			{path: filepath.Join(root, "app", "lib", "plugin.war")},
		}, roots)
	})

	t.Run("skips wildcard archives escaping root", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "outside.jar")
		writeFile(t, outside)
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "app", "lib", "escape.jar")))

		roots := scanRootsFromClasspath(root, "/app", "lib/*")

		assert.Equal(t, []scanRoot{
			{path: filepath.Join(root, "app", "lib", "dep.jar")},
			{path: filepath.Join(root, "app", "lib", "plugin.war")},
		}, roots)
	})

	t.Run("skips unsupported wildcards missing paths and non archives", func(t *testing.T) {
		classpath := strings.Join([]string{"/app/l*b", "/missing", "notes.txt"}, string(filepath.ListSeparator))

		assert.Empty(t, scanRootsFromClasspath(root, "/app", classpath))
	})

	// no shell semantics expansion, mimics what Java class path expansion supports
	t.Run("does not expand directory prefix wildcard", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "application"), 0o755))

		assert.Empty(t, scanRootsFromClasspath(root, "/app", "/app*"))
	})
}

func TestResolveProcessPath(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	writeFile(t, filepath.Join(root, "app", "app.jar"))

	t.Run("resolves relative paths from process cwd", func(t *testing.T) {
		path, ok := resolveProcessPath(root, "/app", "app.jar")

		assert.True(t, ok)
		assert.Equal(t, filepath.Join(root, "app", "app.jar"), path)
	})

	t.Run("resolves absolute container paths under root", func(t *testing.T) {
		path, ok := resolveProcessPath(root, "/ignored", "/app/app.jar")

		assert.True(t, ok)
		assert.Equal(t, filepath.Join(root, "app", "app.jar"), path)
	})

	t.Run("rejects missing resolved paths", func(t *testing.T) {
		path, ok := resolveProcessPath(root, "/", "../app.jar")

		assert.False(t, ok)
		assert.Empty(t, path)
	})

	t.Run("rejects symlink escape", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "outside.jar")
		writeFile(t, outside)
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "app", "escape.jar")))

		path, ok := resolveProcessPath(root, "/app", "escape.jar")

		assert.False(t, ok)
		assert.Empty(t, path)
	})
}

func TestIsProcRoot(t *testing.T) {
	tests := []struct {
		root string
		want bool
	}{
		{root: "/proc/1/root", want: true},
		{root: "/proc/1234/root/", want: true},
		{root: "/proc/self/root", want: false},
		{root: "/proc/1/cwd", want: false},
		{root: "/tmp/proc/1/root", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.root, func(t *testing.T) {
			assert.Equal(t, tt.want, isProcRoot(tt.root))
		})
	}
}

func TestFindScanRoots(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "classes"), 0o755))
	writeFile(t, filepath.Join(root, "app", "app.jar"))

	t.Run("finds jar root", func(t *testing.T) {
		fileInfo := javaClasspathFileInfo(t, root, []string{"-jar", "app.jar"}, nil, nil, nil)

		roots, err := NewExtractor().findScanRoots(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, []scanRoot{{path: filepath.Join(root, "app", "app.jar")}}, roots)
	})

	t.Run("finds explicit classpath root before env", func(t *testing.T) {
		fileInfo := javaClasspathFileInfo(t, root, []string{"-cp", "classes", "com.example.Main"},
			map[string]string{envClasspath: "missing"}, nil, nil)

		roots, err := NewExtractor().findScanRoots(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, []scanRoot{{path: filepath.Join(root, "app", "classes"), dir: true}}, roots)
	})

	t.Run("finds env classpath root", func(t *testing.T) {
		fileInfo := javaClasspathFileInfo(t, root, []string{"com.example.Main"},
			map[string]string{envClasspath: "classes"}, nil, nil)

		roots, err := NewExtractor().findScanRoots(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, []scanRoot{{path: filepath.Join(root, "app", "classes"), dir: true}}, roots)
	})

	t.Run("finds wildcard classpath archives", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "lib"), 0o755))
		writeFile(t, filepath.Join(root, "app", "lib", "dep.jar"))
		writeFile(t, filepath.Join(root, "app", "lib", "plugin.war"))
		classpath := strings.Join([]string{"app.jar", "lib/*"}, string(filepath.ListSeparator))
		fileInfo := javaClasspathFileInfo(t, root, []string{"-cp", classpath, "com.example.Main"}, nil, nil, nil)

		roots, err := NewExtractor().findScanRoots(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, []scanRoot{
			{path: filepath.Join(root, "app", "app.jar")},
			{path: filepath.Join(root, "app", "lib", "dep.jar")},
			{path: filepath.Join(root, "app", "lib", "plugin.war")},
		}, roots)
	})

	t.Run("uses cwd when classpath is empty", func(t *testing.T) {
		fileInfo := javaClasspathFileInfo(t, root, []string{"com.example.Main"}, nil, nil, nil)

		roots, err := NewExtractor().findScanRoots(fileInfo)

		require.NoError(t, err)
		assert.Equal(t, []scanRoot{{path: filepath.Join(root, "app"), dir: true}}, roots)
	})

	t.Run("errors when cmdline lookup fails", func(t *testing.T) {
		expectedErr := errors.New("boom")
		fileInfo := javaClasspathFileInfo(t, root, nil, nil, expectedErr, nil)

		roots, err := NewExtractor().findScanRoots(fileInfo)

		require.ErrorContains(t, err, "error finding Java cmd line")
		require.ErrorIs(t, err, expectedErr)
		assert.Empty(t, roots)
	})

	t.Run("errors when cwd lookup fails", func(t *testing.T) {
		expectedErr := errors.New("boom")
		fileInfo := javaClasspathFileInfo(t, root, []string{"-jar", "app.jar"}, nil, nil, expectedErr)

		roots, err := NewExtractor().findScanRoots(fileInfo)

		require.ErrorContains(t, err, "error finding Java cwd")
		require.ErrorIs(t, err, expectedErr)
		assert.Empty(t, roots)
	})
}

func writeFile(t *testing.T, path string) {
	t.Helper()

	require.NoError(t, os.WriteFile(path, []byte("test"), 0o644))
}

func javaClasspathFileInfo(
	t *testing.T,
	root string,
	args []string,
	env map[string]string,
	cmdlineErr error,
	cwdErr error,
) *exec.FileInfo {
	t.Helper()

	cwd := "/app"

	pid := app.PID(4321)
	oldRootDirForPID := rootDirForPID
	oldCmdlineForPID := cmdlineForPID
	oldCwdForPID := cwdForPID
	rootDirForPID = func(app.PID) string {
		return root
	}
	cmdlineForPID = func(app.PID) (string, []string, error) {
		if cmdlineErr != nil {
			return "", nil, cmdlineErr
		}
		return "java", args, nil
	}
	cwdForPID = func(app.PID) (string, error) {
		if cwdErr != nil {
			return "", cwdErr
		}
		return cwd, nil
	}
	t.Cleanup(func() {
		rootDirForPID = oldRootDirForPID
		cmdlineForPID = oldCmdlineForPID
		cwdForPID = oldCwdForPID
	})

	return exec.New(exec.Init{
		Pid: pid,
		Service: svc.Attrs{
			EnvVars: env,
		},
	})
}
