// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package phptools

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectScanCache(t *testing.T) {
	t.Run("caches a negative scan", func(t *testing.T) {
		cache := newProjectScanCache(1)
		root := t.TempDir()
		scans := 0
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{}, false
		}

		first, firstFound := cache.scan(root, root, scanner)
		second, secondFound := cache.scan(root, root, scanner)

		assert.False(t, firstFound)
		assert.False(t, secondFound)
		assert.Equal(t, ProjectMetadata{}, first)
		assert.Equal(t, ProjectMetadata{}, second)
		assert.Equal(t, 1, scans)
	})

	t.Run("expires a negative scan after the TTL", func(t *testing.T) {
		setScanTTL(t, time.Millisecond)
		cache := newProjectScanCache(1)
		root := t.TempDir()
		scans := 0
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{}, false
		}

		_, firstFound := cache.scan(root, root, scanner)
		time.Sleep(2 * time.Millisecond)
		_, secondFound := cache.scan(root, root, scanner)

		assert.False(t, firstFound)
		assert.False(t, secondFound)
		assert.Equal(t, 2, scans)
	})

	t.Run("expires a positive scan after the TTL", func(t *testing.T) {
		// Simulates an in-place redeploy (e.g. a symlink-swap release) on a long-lived
		// container: the process root's identity is unchanged, but the project itself
		// has moved on to a new version.
		setScanTTL(t, time.Millisecond)
		cache := newProjectScanCache(1)
		root := t.TempDir()
		scans := 0
		scanner := func(scanRoot, _ string) (ProjectMetadata, bool) {
			scans++
			version := "1.0.0"
			if scans > 1 {
				version = "2.0.0"
			}
			return ProjectMetadata{Root: filepath.Join(scanRoot, "srv", "app"), Name: "acme/app", Version: version}, true
		}

		first, firstFound := cache.scan(root, root, scanner)
		time.Sleep(2 * time.Millisecond)
		second, secondFound := cache.scan(root, root, scanner)

		assert.True(t, firstFound)
		assert.True(t, secondFound)
		assert.Equal(t, "1.0.0", first.Version)
		assert.Equal(t, "2.0.0", second.Version)
		assert.Equal(t, 2, scans)
	})

	t.Run("shares a scan across paths for the same process root", func(t *testing.T) {
		cache := newProjectScanCache(1)
		root := t.TempDir()
		procRoot := t.TempDir()
		firstRoot := fakeProcessRoot(t, procRoot, "101", root, "mnt:[42]")
		secondRoot := fakeProcessRoot(t, procRoot, "102", root, "mnt:[42]")
		scans := 0
		scanner := func(scanRoot, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{
				Root:         filepath.Join(scanRoot, "srv", "app"),
				Name:         "acme/app",
				Version:      "1.2.3",
				FallbackName: "app",
			}, true
		}

		first, firstFound := cache.scan(firstRoot, firstRoot, scanner)
		second, secondFound := cache.scan(secondRoot, secondRoot, scanner)

		assert.True(t, firstFound)
		assert.True(t, secondFound)
		assert.Equal(t, filepath.Join(firstRoot, "srv", "app"), first.Root)
		assert.Equal(t, filepath.Join(secondRoot, "srv", "app"), second.Root)
		assert.Equal(t, first.Name, second.Name)
		assert.Equal(t, first.Version, second.Version)
		assert.Equal(t, first.FallbackName, second.FallbackName)
		assert.Equal(t, 1, scans)
	})

	t.Run("reuses a negative scan after the source PID exits", func(t *testing.T) {
		cache := newProjectScanCache(1)
		root := t.TempDir()
		procRoot := t.TempDir()
		firstRoot := fakeProcessRoot(t, procRoot, "101", root, "mnt:[42]")
		scans := 0
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{}, false
		}

		_, firstFound := cache.scan(firstRoot, firstRoot, scanner)
		require.NoError(t, os.RemoveAll(filepath.Dir(firstRoot)))
		secondRoot := fakeProcessRoot(t, procRoot, "102", root, "mnt:[42]")
		_, secondFound := cache.scan(secondRoot, secondRoot, scanner)

		assert.False(t, firstFound)
		assert.False(t, secondFound)
		assert.Equal(t, 1, scans)
	})

	t.Run("does not share scans across process roots", func(t *testing.T) {
		cache := newProjectScanCache(2)
		scans := 0
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{}, false
		}

		_, _ = cache.scan(t.TempDir(), "/", scanner)
		_, _ = cache.scan(t.TempDir(), "/", scanner)

		assert.Equal(t, 2, scans)
	})

	t.Run("does not share scans across mount namespaces", func(t *testing.T) {
		cache := newProjectScanCache(2)
		root := t.TempDir()
		procRoot := t.TempDir()
		firstRoot := fakeProcessRoot(t, procRoot, "101", root, "mnt:[42]")
		secondRoot := fakeProcessRoot(t, procRoot, "102", root, "mnt:[43]")
		scans := 0
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{}, false
		}

		_, _ = cache.scan(firstRoot, firstRoot, scanner)
		_, _ = cache.scan(secondRoot, secondRoot, scanner)

		assert.Equal(t, 2, scans)
	})

	t.Run("does not share scans across chroots", func(t *testing.T) {
		cache := newProjectScanCache(2)
		procRoot := t.TempDir()
		firstRoot := fakeProcessRoot(t, procRoot, "101", t.TempDir(), "mnt:[42]")
		secondRoot := fakeProcessRoot(t, procRoot, "102", t.TempDir(), "mnt:[42]")
		scans := 0
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{}, false
		}

		_, _ = cache.scan(firstRoot, firstRoot, scanner)
		_, _ = cache.scan(secondRoot, secondRoot, scanner)

		assert.Equal(t, 2, scans)
	})

	t.Run("does not cache an inaccessible process root", func(t *testing.T) {
		cache := newProjectScanCache(1)
		root := filepath.Join(t.TempDir(), "root")
		scans := 0
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{}, false
		}

		_, _ = cache.scan(root, root, scanner)
		require.NoError(t, os.Mkdir(root, 0o755))
		_, _ = cache.scan(root, root, scanner)
		_, _ = cache.scan(root, root, scanner)

		assert.Equal(t, 2, scans)
	})

	t.Run("does not cache when the process root disappears during scanning", func(t *testing.T) {
		cache := newProjectScanCache(1)
		root := filepath.Join(t.TempDir(), "root")
		require.NoError(t, os.Mkdir(root, 0o755))
		scans := 0
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			require.NoError(t, os.Remove(root))
			return ProjectMetadata{}, false
		}

		_, _ = cache.scan(root, root, scanner)
		require.NoError(t, os.Mkdir(root, 0o755))
		_, _ = cache.scan(root, root, scanner)

		assert.Equal(t, 2, scans)
	})

	t.Run("concurrent workers scan once", func(t *testing.T) {
		cache := newProjectScanCache(1)
		root := t.TempDir()
		scans := 0
		//nolint:unparam // must match the projectScanner signature; this test only cares about the scan count
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{}, false
		}

		var workers sync.WaitGroup
		for range 100 {
			workers.Go(func() {
				_, _ = cache.scan(root, root, scanner)
			})
		}
		workers.Wait()

		assert.Equal(t, 1, scans)
	})

	t.Run("evicts the least recently used process root", func(t *testing.T) {
		cache := newProjectScanCache(1)
		firstRoot := t.TempDir()
		secondRoot := t.TempDir()
		scans := 0
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{}, false
		}

		_, _ = cache.scan(firstRoot, firstRoot, scanner)
		_, _ = cache.scan(secondRoot, secondRoot, scanner)
		_, _ = cache.scan(firstRoot, firstRoot, scanner)

		assert.Equal(t, 3, scans)
	})

	t.Run("does not cache a result outside the process root", func(t *testing.T) {
		cache := newProjectScanCache(1)
		root := t.TempDir()
		scans := 0
		scanner := func(_, _ string) (ProjectMetadata, bool) {
			scans++
			return ProjectMetadata{Root: filepath.Dir(root), Name: "acme/app"}, true
		}

		_, _ = cache.scan(root, root, scanner)
		_, _ = cache.scan(root, root, scanner)

		assert.Equal(t, 2, scans)
	})
}

func setScanTTL(t *testing.T, ttl time.Duration) {
	t.Helper()
	oldTTL := scanTTL
	scanTTL = ttl
	t.Cleanup(func() {
		scanTTL = oldTTL
	})
}

func fakeProcessRoot(t *testing.T, procRoot, pid, root, mountNamespace string) string {
	t.Helper()
	processDir := filepath.Join(procRoot, pid)
	require.NoError(t, os.MkdirAll(filepath.Join(processDir, "ns"), 0o755))
	require.NoError(t, os.Symlink(mountNamespace, filepath.Join(processDir, "ns", "mnt")))
	require.NoError(t, os.Symlink(root, filepath.Join(processDir, "root")))
	return filepath.Join(processDir, "root")
}
