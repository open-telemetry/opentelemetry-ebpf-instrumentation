// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvmtools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJavaLaunch(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		expected JavaLaunch
	}{
		{
			name:     "jar wins over classpath",
			args:     []string{"-cp", "/classes", "-jar", "/app.jar"},
			env:      map[string]string{envClasspath: "/env-classes"},
			expected: JavaLaunch{Jar: "/app.jar"},
		},
		{
			name:     "short classpath flag",
			args:     []string{"-cp", "/classes", "com.example.Main"},
			expected: JavaLaunch{Classpath: "/classes"},
		},
		{
			name:     "legacy classpath flag",
			args:     []string{"-classpath", "/classes", "com.example.Main"},
			expected: JavaLaunch{Classpath: "/classes"},
		},
		{
			name:     "long classpath flag",
			args:     []string{"--class-path", "/classes", "com.example.Main"},
			expected: JavaLaunch{Classpath: "/classes"},
		},
		{
			name:     "long classpath flag with equals",
			args:     []string{"--class-path=/classes", "com.example.Main"},
			expected: JavaLaunch{Classpath: "/classes"},
		},
		{
			name:     "last classpath wins",
			args:     []string{"-cp", "/old", "--class-path=/new", "com.example.Main"},
			expected: JavaLaunch{Classpath: "/new"},
		},
		{
			name:     "environment fallback",
			args:     []string{"com.example.Main"},
			env:      map[string]string{envClasspath: "/env-classes"},
			expected: JavaLaunch{Classpath: "/env-classes"},
		},
		{
			name:     "explicit classpath wins over environment",
			args:     []string{"-cp", "/classes", "com.example.Main"},
			env:      map[string]string{envClasspath: "/env-classes"},
			expected: JavaLaunch{Classpath: "/classes"},
		},
		{
			name: "missing jar value",
			args: []string{"-jar"},
		},
		{
			name: "no launch option",
			args: []string{"com.example.Main"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseJavaLaunch(tt.args, tt.env))
		})
	}
}

func TestScanRoots(t *testing.T) {
	root, actualRoot := classpathTestRoot(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "classes"), 0o755))
	writeClasspathTestFile(t, filepath.Join(root, "app", "app.jar"))

	t.Run("resolves jar relative to working directory", func(t *testing.T) {
		roots, err := ScanRoots(root, "/app", []string{"-jar", "app.jar"}, nil)

		require.NoError(t, err)
		assert.Equal(t, []ScanRoot{{Path: filepath.Join(actualRoot, "app", "app.jar")}}, roots)
	})

	t.Run("resolves explicit classpath", func(t *testing.T) {
		roots, err := ScanRoots(root, "/app", []string{"-cp", "classes", "com.example.Main"}, nil)

		require.NoError(t, err)
		assert.Equal(t, []ScanRoot{{Path: filepath.Join(actualRoot, "app", "classes"), Directory: true}}, roots)
	})

	t.Run("uses environment classpath", func(t *testing.T) {
		roots, err := ScanRoots(root, "/app", []string{"com.example.Main"}, map[string]string{
			envClasspath: "classes",
		})

		require.NoError(t, err)
		assert.Equal(t, []ScanRoot{{Path: filepath.Join(actualRoot, "app", "classes"), Directory: true}}, roots)
	})

	t.Run("uses working directory by default", func(t *testing.T) {
		roots, err := ScanRoots(root, "/app", []string{"com.example.Main"}, nil)

		require.NoError(t, err)
		assert.Equal(t, []ScanRoot{{Path: filepath.Join(actualRoot, "app"), Directory: true}}, roots)
	})

	t.Run("rejects missing jar", func(t *testing.T) {
		roots, err := ScanRoots(root, "/app", []string{"-jar", "missing.jar"}, nil)

		require.EqualError(t, err, `invalid Java jar path "missing.jar"`)
		assert.Nil(t, roots)
	})

	t.Run("rejects jar path that is not a regular file", func(t *testing.T) {
		roots, err := ScanRoots(root, "/app", []string{"-jar", "classes"}, nil)

		require.EqualError(t, err, `java jar path "classes" is not a regular file`)
		assert.Nil(t, roots)
	})
}

func TestClasspathRoots(t *testing.T) {
	root, actualRoot := classpathTestRoot(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "classes"), 0o755))
	writeClasspathTestFile(t, filepath.Join(root, "app", "app.jar"))

	tests := []struct {
		name     string
		launch   JavaLaunch
		expected []ScanRoot
	}{
		{
			name:     "jar",
			launch:   JavaLaunch{Jar: "app.jar"},
			expected: []ScanRoot{{Path: filepath.Join(actualRoot, "app", "app.jar")}},
		},
		{
			name:   "invalid jar",
			launch: JavaLaunch{Jar: "missing.jar"},
		},
		{
			name:     "classpath",
			launch:   JavaLaunch{Classpath: "classes"},
			expected: []ScanRoot{{Path: filepath.Join(actualRoot, "app", "classes"), Directory: true}},
		},
		{
			name:     "working directory fallback",
			expected: []ScanRoot{{Path: filepath.Join(actualRoot, "app"), Directory: true}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, classpathRoots(root, "/app", tt.launch))
		})
	}
}

func TestScanRootsFromClasspath(t *testing.T) {
	root, actualRoot := classpathTestRoot(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "classes"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "lib", "nested.jar"), 0o755))
	writeClasspathTestFile(t, filepath.Join(root, "app", "app.jar"))
	writeClasspathTestFile(t, filepath.Join(root, "app", "lib", "a.jar"))
	writeClasspathTestFile(t, filepath.Join(root, "app", "lib", "b.WAR"))
	writeClasspathTestFile(t, filepath.Join(root, "app", "lib", "notes.txt"))
	writeClasspathTestFile(t, filepath.Join(root, "app", "notes.txt"))

	t.Run("preserves classpath order and expands archive wildcards", func(t *testing.T) {
		classpath := strings.Join([]string{"classes", "app.jar", "lib/*"}, string(filepath.ListSeparator))

		roots := ScanRootsFromClasspath(root, "/app", classpath)

		assert.Equal(t, []ScanRoot{
			{Path: filepath.Join(actualRoot, "app", "classes"), Directory: true},
			{Path: filepath.Join(actualRoot, "app", "app.jar")},
			{Path: filepath.Join(actualRoot, "app", "lib", "a.jar")},
			{Path: filepath.Join(actualRoot, "app", "lib", "b.WAR")},
		}, roots)
	})

	t.Run("skips empty missing non archive and unsupported wildcard entries", func(t *testing.T) {
		classpath := strings.Join([]string{
			"", "missing.jar", "notes.txt", "missing/*", "app.jar/*", "l*b/*", "lib/a*",
		}, string(filepath.ListSeparator))

		assert.Empty(t, ScanRootsFromClasspath(root, "/app", classpath))
	})

	t.Run("skips wildcard archive symlinks that escape root", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "outside.jar")
		writeClasspathTestFile(t, outside)
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "app", "lib", "escape.jar")))

		roots := ScanRootsFromClasspath(root, "/app", "lib/*")

		assert.Equal(t, []ScanRoot{
			{Path: filepath.Join(actualRoot, "app", "lib", "a.jar")},
			{Path: filepath.Join(actualRoot, "app", "lib", "b.WAR")},
		}, roots)
	})
}

func TestScanRootFromClasspathEntry(t *testing.T) {
	root, actualRoot := classpathTestRoot(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "classes"), 0o755))
	writeClasspathTestFile(t, filepath.Join(root, "app", "app.JAR"))
	writeClasspathTestFile(t, filepath.Join(root, "app", "notes.txt"))

	tests := []struct {
		name     string
		entry    string
		expected ScanRoot
		ok       bool
	}{
		{
			name:     "directory",
			entry:    "classes",
			expected: ScanRoot{Path: filepath.Join(actualRoot, "app", "classes"), Directory: true},
			ok:       true,
		},
		{
			name:     "archive",
			entry:    "app.JAR",
			expected: ScanRoot{Path: filepath.Join(actualRoot, "app", "app.JAR")},
			ok:       true,
		},
		{name: "non archive", entry: "notes.txt"},
		{name: "missing path", entry: "missing.jar"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, ok := ScanRootFromClasspathEntry(root, "/app", tt.entry)

			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestClasspathWildcardDir(t *testing.T) {
	tests := []struct {
		entry    string
		expected string
		ok       bool
	}{
		{entry: "lib/*", expected: "lib", ok: true},
		{entry: "*", expected: ".", ok: true},
		{entry: "lib/a*"},
		{entry: "l*b/*"},
		{entry: "lib/app.jar"},
	}

	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			actual, ok := classpathWildcardDir(tt.entry)

			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestJavaArchive(t *testing.T) {
	assert.True(t, isJavaArchive("app.jar"))
	assert.True(t, isJavaArchive("app.WAR"))
	assert.False(t, isJavaArchive("app.zip"))
	assert.False(t, isJavaArchive("jar"))
}

func classpathTestRoot(t *testing.T) (string, string) {
	t.Helper()

	root := t.TempDir()
	actualRoot, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	return root, actualRoot
}

func writeClasspathTestFile(t *testing.T, path string) {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("test"), 0o644))
}
