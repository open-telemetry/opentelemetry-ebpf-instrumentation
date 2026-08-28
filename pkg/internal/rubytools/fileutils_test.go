// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rubytools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectDirectoryForFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "environment.rb directly under config", path: "/app/config/environment.rb", expected: "/app"},
		{name: "other file directly under config", path: "/app/config/routes.rb", expected: "/app/config"},
		{name: "environment.rb outside a config directory", path: "/app/environment.rb", expected: "/app"},
		{name: "environment.rb nested under a non-config directory", path: "/a/config/sub/environment.rb", expected: "/a/config/sub"},
		{name: "ordinary executable path", path: "/app/bin/rails", expected: "/app/bin"},
		{name: "relative environment.rb under config", path: "config/environment.rb", expected: "."},
		{name: "bare environment.rb with no directory", path: "environment.rb", expected: "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, projectDirectoryForFile(tt.path))
		})
	}
}

func TestProjectPathLooksLikeFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{name: "bare config.ru", path: "config.ru", expected: true},
		{name: "config.ru under a directory", path: "/app/config.ru", expected: true},
		{name: "ruby script with extension", path: "/app/app.rb", expected: true},
		{name: "executable with no extension", path: "/app/bin/rails", expected: false},
		{name: "bare directory name", path: "/app", expected: false},
		{name: "trailing slash resolves to the directory name", path: "/app/", expected: false},
		{name: "dotfile is treated as having an extension", path: "/app/.env", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, projectPathLooksLikeFile(tt.path))
		})
	}
}

func TestGemDependencyRoots(t *testing.T) {
	tests := []struct {
		name     string
		cwd      string
		env      map[string]string
		expected []string
	}{
		{name: "nil env yields no roots", cwd: "/app", env: nil, expected: nil},
		{name: "empty env yields no roots", cwd: "/app", env: map[string]string{}, expected: nil},
		{
			name:     "GEM_HOME only",
			cwd:      "/app",
			env:      map[string]string{gemHome: "/gems/home"},
			expected: []string{"/gems/home"},
		},
		{
			name:     "GEM_PATH with multiple entries",
			cwd:      "/app",
			env:      map[string]string{gemPath: "/gems/a:/gems/b"},
			expected: []string{"/gems/a", "/gems/b"},
		},
		{
			name:     "GEM_HOME and GEM_PATH combined, home first",
			cwd:      "/app",
			env:      map[string]string{gemHome: "/gems/home", gemPath: "/gems/a:/gems/b"},
			expected: []string{"/gems/home", "/gems/a", "/gems/b"},
		},
		{
			name:     "empty GEM_PATH entries are dropped",
			cwd:      "/app",
			env:      map[string]string{gemPath: "/gems/a::/gems/b"},
			expected: []string{"/gems/a", "/gems/b"},
		},
		{
			name:     "relative GEM_HOME is resolved against cwd",
			cwd:      "/app",
			env:      map[string]string{gemHome: "vendor/bundle"},
			expected: []string{"/app/vendor/bundle"},
		},
		{
			name:     "relative GEM_HOME with relative cwd yields no root",
			cwd:      "relative",
			env:      map[string]string{gemHome: "vendor/bundle"},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, gemDependencyRoots(tt.cwd, tt.env))
		})
	}
}

func TestPathInDependencyRoot(t *testing.T) {
	tests := []struct {
		name     string
		cwd      string
		path     string
		roots    []string
		expected bool
	}{
		{name: "no roots is never within a dependency root", cwd: "/app", path: "/gems/a/lib.rb", roots: nil, expected: false},
		{name: "path inside the only root", cwd: "/app", path: "/gems/a/lib/foo.rb", roots: []string{"/gems/a"}, expected: true},
		{name: "path outside every root", cwd: "/app", path: "/other/foo.rb", roots: []string{"/gems/a", "/gems/b"}, expected: false},
		{name: "path inside the second root", cwd: "/app", path: "/gems/b/foo.rb", roots: []string{"/gems/a", "/gems/b"}, expected: true},
		{name: "path equal to a root", cwd: "/app", path: "/gems/a", roots: []string{"/gems/a"}, expected: true},
		{name: "sibling directory sharing a prefix is not within the root", cwd: "/app", path: "/gems/aa/foo.rb", roots: []string{"/gems/a"}, expected: false},
		{name: "relative path resolved against cwd before checking", cwd: "/gems/a", path: "foo.rb", roots: []string{"/gems/a"}, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, pathInDependencyRoot(tt.cwd, tt.path, tt.roots))
		})
	}
}

func TestCleanDependencyRoot(t *testing.T) {
	tests := []struct {
		name     string
		cwd      string
		path     string
		expected string
	}{
		{name: "empty path yields empty root", cwd: "/app", path: "", expected: ""},
		{name: "absolute path is cleaned", cwd: "/app", path: "/gems/home/", expected: "/gems/home"},
		{name: "relative path resolved against an absolute cwd", cwd: "/app", path: "vendor/bundle", expected: "/app/vendor/bundle"},
		{name: "relative path with a relative cwd yields empty root", cwd: "relative", path: "vendor/bundle", expected: ""},
		{name: "relative path with empty cwd yields empty root", cwd: "", path: "vendor/bundle", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, cleanDependencyRoot(tt.cwd, tt.path))
		})
	}
}

func TestRegularFile(t *testing.T) {
	t.Run("regular file returns true", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file.rb")
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))

		assert.True(t, regularFile(path))
	})

	t.Run("directory returns false", func(t *testing.T) {
		path := t.TempDir()

		assert.False(t, regularFile(path))
	})

	t.Run("missing path returns false", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.rb")

		assert.False(t, regularFile(path))
	})

	t.Run("symlink to a regular file returns false", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.rb")
		require.NoError(t, os.WriteFile(target, []byte("x"), 0o644))
		link := filepath.Join(dir, "link.rb")
		require.NoError(t, os.Symlink(target, link))

		assert.False(t, regularFile(link))
	})
}

func TestPathEntryExists(t *testing.T) {
	t.Run("existing path returns true with no error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "Gemfile")
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))

		exists, err := pathEntryExists(path)

		assert.True(t, exists)
		assert.NoError(t, err)
	})

	t.Run("missing path returns false with no error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "Gemfile")

		exists, err := pathEntryExists(path)

		assert.False(t, exists)
		assert.NoError(t, err)
	})

	t.Run("symlink target returns true with no error", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "Gemfile")
		require.NoError(t, os.WriteFile(target, []byte("x"), 0o644))
		link := filepath.Join(dir, "link")
		require.NoError(t, os.Symlink(target, link))

		exists, err := pathEntryExists(link)

		assert.True(t, exists)
		assert.NoError(t, err)
	})

	t.Run("unexpected stat failure returns an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), strings.Repeat("a", 300))

		exists, err := pathEntryExists(path)

		assert.False(t, exists)
		assert.Error(t, err)
	})
}

func TestServiceNameFromEntryPoint(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "ordinary ruby script", path: "/app/worker.rb", expected: "worker"},
		{name: "path without an extension", path: "/app/worker", expected: "worker"},
		{name: "recognized launcher tool is rejected", path: "/usr/bin/rails", expected: ""},
		{name: "another recognized launcher tool is rejected", path: "/usr/bin/puma", expected: ""},
		{name: "config.ru is rejected", path: "/app/config.ru", expected: ""},
		{name: "empty path is rejected", path: "", expected: ""},
		{name: "path separator base is rejected", path: "/", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, serviceNameFromEntryPoint(tt.path))
		})
	}
}

func TestServiceNameFromProjectDirectory(t *testing.T) {
	tests := []struct {
		name     string
		dir      string
		boundary string
		expected string
	}{
		{name: "directory below the boundary", dir: "/app/orders", boundary: "/app", expected: "orders"},
		{name: "directory equal to the boundary is rejected", dir: "/app", boundary: "/app", expected: ""},
		{name: "root directory is an invalid service name", dir: "/", boundary: "/srv", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, serviceNameFromProjectDirectory(tt.dir, tt.boundary))
		})
	}
}

func TestFirstValidName(t *testing.T) {
	tests := []struct {
		name     string
		values   []string
		expected string
	}{
		{name: "no values yields empty result", values: nil, expected: ""},
		{name: "first value is valid", values: []string{"orders", "billing"}, expected: "orders"},
		{name: "first value is invalid, second is used", values: []string{"", "billing"}, expected: "billing"},
		{name: "all values invalid yields empty result", values: []string{"", ".", ".."}, expected: ""},
		{name: "invalid separator value is skipped", values: []string{"/", "billing"}, expected: "billing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, firstValidName(tt.values...))
		})
	}
}
