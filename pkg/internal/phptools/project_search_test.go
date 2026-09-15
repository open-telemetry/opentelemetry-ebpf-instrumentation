// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindProject(t *testing.T) {
	t.Run("invalid process root", func(t *testing.T) {
		assert.Equal(t, projectMetadata{}, findProject(filepath.Join(t.TempDir(), "missing"), "/", nil, true))
	})

	t.Run("CLI script takes precedence over working directory", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "script", "composer.json"), []byte(`{"name":"acme/script"}`))
		writePHPFile(t, filepath.Join(root, "script", "bin", "console"), nil)
		writePHPFile(t, filepath.Join(root, "working", "composer.json"), []byte(`{"name":"acme/working"}`))

		project := findProject(root, "/working", []string{"/script/bin/console"}, false)

		assert.Equal(t, projectMetadata{root: filepath.Join(root, "script"), name: "acme/script"}, project)
	})

	t.Run("relative CLI script is resolved from working directory", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"acme/app"}`))
		writePHPFile(t, filepath.Join(root, "app", "bin", "console"), nil)

		project := findProject(root, "/app", []string{"bin/console"}, false)

		assert.Equal(t, projectMetadata{root: filepath.Join(root, "app"), name: "acme/app"}, project)
	})

	t.Run("non-regular script falls back to working directory", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "not-a-script"), 0o755))
		writePHPFile(t, filepath.Join(root, "working", "composer.json"), []byte(`{"name":"acme/working"}`))

		project := findProject(root, "/working", []string{"/not-a-script"}, false)

		assert.Equal(t, projectMetadata{root: filepath.Join(root, "working"), name: "acme/working"}, project)
	})

	t.Run("working directory is searched through parents", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "app", "composer.json"), []byte(`{"name":"acme/app"}`))
		require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "public"), 0o755))

		project := findProject(root, "/app/public", nil, true)

		assert.Equal(t, projectMetadata{root: filepath.Join(root, "app"), name: "acme/app"}, project)
	})

	t.Run("FPM scans a distinct process root", func(t *testing.T) {
		root := t.TempDir()
		setPHPHostRoot(t, string(filepath.Separator))
		writePHPFile(t, filepath.Join(root, "srv", "app", "composer.json"), []byte(`{"name":"acme/app"}`))

		project := findProject(root, "/", nil, true)

		assert.Equal(t, projectMetadata{root: filepath.Join(root, "srv", "app"), name: "acme/app"}, project)
	})

	t.Run("FPM does not scan the host root", func(t *testing.T) {
		root := t.TempDir()
		setPHPHostRoot(t, root)
		writePHPFile(t, filepath.Join(root, "srv", "app", "composer.json"), []byte(`{"name":"acme/app"}`))

		assert.Equal(t, projectMetadata{}, findProject(root, "/", nil, true))
	})

	t.Run("CLI does not recursively scan", func(t *testing.T) {
		root := t.TempDir()
		setPHPHostRoot(t, string(filepath.Separator))
		writePHPFile(t, filepath.Join(root, "srv", "app", "composer.json"), []byte(`{"name":"acme/app"}`))

		assert.Equal(t, projectMetadata{}, findProject(root, "/", []string{"-r", "sleep(10);"}, false))
	})
}

func TestFindParentProject(t *testing.T) {
	t.Run("nearest project wins", func(t *testing.T) {
		root := t.TempDir()
		child := filepath.Join(root, "outer", "child")
		start := filepath.Join(child, "public")
		writePHPFile(t, filepath.Join(root, "outer", "composer.json"), []byte(`{"name":"acme/outer"}`))
		writePHPFile(t, filepath.Join(child, "composer.json"), []byte(`{"name":"acme/child"}`))
		require.NoError(t, os.MkdirAll(start, 0o755))

		project, found := findParentProject(start, root)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: child, name: "acme/child"}, project)
	})

	t.Run("malformed project is skipped", func(t *testing.T) {
		root := t.TempDir()
		start := filepath.Join(root, "outer", "broken")
		writePHPFile(t, filepath.Join(root, "outer", "composer.json"), []byte(`{"name":"acme/outer"}`))
		writePHPFile(t, filepath.Join(start, "composer.json"), []byte(`{"name":`))

		project, found := findParentProject(start, root)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: filepath.Join(root, "outer"), name: "acme/outer"}, project)
	})

	t.Run("no project", func(t *testing.T) {
		root := t.TempDir()
		start := filepath.Join(root, "app")
		require.NoError(t, os.MkdirAll(start, 0o755))

		project, found := findParentProject(start, root)

		assert.False(t, found)
		assert.Equal(t, projectMetadata{}, project)
	})

	t.Run("start outside boundary", func(t *testing.T) {
		boundary := t.TempDir()
		start := t.TempDir()
		writePHPFile(t, filepath.Join(start, "composer.json"), []byte(`{"name":"acme/outside"}`))

		project, found := findParentProject(start, boundary)

		assert.False(t, found)
		assert.Equal(t, projectMetadata{}, project)
	})
}

func TestScanProcessRoot(t *testing.T) {
	t.Run("root project", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "composer.json"), []byte(`{"name":"acme/root"}`))

		project, found := scanProcessRoot(root, root)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: root, name: "acme/root"}, project)
	})

	t.Run("project at depth limit", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "one", "two", "three", "four")
		writePHPFile(t, filepath.Join(dir, "composer.json"), []byte(`{"name":"acme/deep"}`))

		project, found := scanProcessRoot(root, root)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: dir, name: "acme/deep"}, project)
	})

	t.Run("project beyond depth limit", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "one", "two", "three", "four", "five", "composer.json"), []byte(`{"name":"acme/too-deep"}`))

		project, found := scanProcessRoot(root, root)

		assert.False(t, found)
		assert.Equal(t, projectMetadata{}, project)
	})

	t.Run("multiple projects are ambiguous", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "one", "composer.json"), []byte(`{"name":"acme/one"}`))
		writePHPFile(t, filepath.Join(root, "two", "composer.json"), []byte(`{"name":"acme/two"}`))

		project, found := scanProcessRoot(root, root)

		assert.False(t, found)
		assert.Equal(t, projectMetadata{}, project)
	})

	t.Run("malformed metadata is ignored", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "broken", "composer.json"), []byte(`{"name":`))
		writePHPFile(t, filepath.Join(root, "valid", "composer.json"), []byte(`{"name":"acme/valid"}`))

		project, found := scanProcessRoot(root, root)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: filepath.Join(root, "valid"), name: "acme/valid"}, project)
	})

	t.Run("skipped trees are not traversed", func(t *testing.T) {
		root := t.TempDir()
		writePHPFile(t, filepath.Join(root, "vendor", "hidden", "composer.json"), []byte(`{"name":"acme/vendor"}`))
		writePHPFile(t, filepath.Join(root, "var", "lib", "hidden", "composer.json"), []byte(`{"name":"acme/system"}`))
		writePHPFile(t, filepath.Join(root, "srv", "app", "composer.json"), []byte(`{"name":"acme/app"}`))

		project, found := scanProcessRoot(root, root)

		assert.True(t, found)
		assert.Equal(t, projectMetadata{root: filepath.Join(root, "srv", "app"), name: "acme/app"}, project)
	})

	t.Run("symbolic link directories are not traversed", func(t *testing.T) {
		root := t.TempDir()
		external := t.TempDir()
		writePHPFile(t, filepath.Join(external, "composer.json"), []byte(`{"name":"acme/external"}`))
		require.NoError(t, os.Symlink(external, filepath.Join(root, "linked-app")))

		project, found := scanProcessRoot(root, root)

		assert.False(t, found)
		assert.Equal(t, projectMetadata{}, project)
	})

	t.Run("directory limit discards partial result", func(t *testing.T) {
		root := t.TempDir()
		for i := range maxProjectSearchDirectories {
			require.NoError(t, os.Mkdir(filepath.Join(root, fmt.Sprintf("dir-%03d", i)), 0o755))
		}
		writePHPFile(t, filepath.Join(root, "dir-000", "composer.json"), []byte(`{"name":"acme/partial"}`))

		project, found := scanProcessRoot(root, root)

		assert.False(t, found)
		assert.Equal(t, projectMetadata{}, project)
	})

	t.Run("unresolvable boundary", func(t *testing.T) {
		root := t.TempDir()
		project, found := scanProcessRoot(root, filepath.Join(root, "missing"))

		assert.False(t, found)
		assert.Equal(t, projectMetadata{}, project)
	})

	t.Run("unresolvable process root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "missing")
		project, found := scanProcessRoot(root, root)

		assert.False(t, found)
		assert.Equal(t, projectMetadata{}, project)
	})

	t.Run("unreadable directory", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.Chmod(root, 0))
		t.Cleanup(func() {
			_ = os.Chmod(root, 0o755)
		})

		project, found := scanProcessRoot(root, root)

		assert.False(t, found)
		assert.Equal(t, projectMetadata{}, project)
	})
}

func TestResolveSearchDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "srv", "app")
	file := filepath.Join(root, "srv", "index.php")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	writePHPFile(t, file, nil)

	resolved, ok := resolveSearchDirectory(root, root, root)
	assert.True(t, ok)
	assert.Equal(t, root, resolved)

	resolved, ok = resolveSearchDirectory(root, root, dir)
	assert.True(t, ok)
	assert.Equal(t, dir, resolved)

	resolved, ok = resolveSearchDirectory(root, root, file)
	assert.False(t, ok)
	assert.Equal(t, file, resolved)

	resolved, ok = resolveSearchDirectory(root, root, filepath.Join(root, "missing"))
	assert.False(t, ok)
	assert.Empty(t, resolved)

	resolved, ok = resolveSearchDirectory(root, "relative", root)
	assert.False(t, ok)
	assert.Empty(t, resolved)
}

func TestSkipSearchDirectory(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		"vendor", "app/vendor", "node_modules", "app/node_modules", ".git", "app/.git",
		"bin", "boot", "dev", "etc", "lib", "lib64", "proc", "run", "sbin", "sys", "tmp",
		"usr/bin", "usr/include", "usr/lib", "usr/lib64", "usr/sbin", "usr/share",
		"usr/local/bin", "usr/local/lib", "usr/local/lib64", "usr/local/sbin", "usr/local/share",
		"var/cache", "var/lib", "var/log", "var/run", "var/tmp",
	} {
		t.Run("skip "+path, func(t *testing.T) {
			assert.True(t, skipSearchDirectory(root, filepath.Join(root, filepath.FromSlash(path))))
		})
	}

	for _, path := range []string{"app", "srv/app", "usr/local/src", "var/www", "vendorized", ".github"} {
		t.Run("visit "+path, func(t *testing.T) {
			assert.False(t, skipSearchDirectory(root, filepath.Join(root, filepath.FromSlash(path))))
		})
	}

	assert.True(t, skipSearchDirectory("relative", root))
}

func TestProcessRootDiffersFromHost(t *testing.T) {
	t.Run("same directory", func(t *testing.T) {
		root := t.TempDir()
		setPHPHostRoot(t, root)

		assert.False(t, processRootDiffersFromHost(root))
	})

	t.Run("different directories", func(t *testing.T) {
		root := t.TempDir()
		setPHPHostRoot(t, t.TempDir())

		assert.True(t, processRootDiffersFromHost(root))
	})

	t.Run("missing process root", func(t *testing.T) {
		setPHPHostRoot(t, t.TempDir())

		assert.False(t, processRootDiffersFromHost(filepath.Join(t.TempDir(), "missing")))
	})

	t.Run("missing host root", func(t *testing.T) {
		root := t.TempDir()
		setPHPHostRoot(t, filepath.Join(t.TempDir(), "missing"))

		assert.False(t, processRootDiffersFromHost(root))
	})
}

func setPHPHostRoot(t *testing.T, root string) {
	t.Helper()
	oldHostRoot := hostRoot
	hostRoot = root
	t.Cleanup(func() {
		hostRoot = oldHostRoot
	})
}
