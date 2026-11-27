// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"
)

type countedLink struct{ closes int }

func (l *countedLink) Close() error {
	l.closes++
	return nil
}

func useTestMonitor(t *testing.T) *probeMonitor {
	t.Helper()
	root := t.TempDir()
	patchDir := filepath.Join(root, "livepatch")
	require.NoError(t, os.Mkdir(patchDir, 0o755))
	previous := kernelProbes
	kernelProbes = &probeMonitor{patchDir: patchDir, kallsyms: filepath.Join(root, "kallsyms"), interval: time.Hour}
	t.Cleanup(func() { kernelProbes = previous })
	return kernelProbes
}

func writePatchAttribute(t *testing.T, dir, name, value string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(value+"\n"), 0o600))
}

func addTestLivepatch(t *testing.T, root, module, symbol string) string {
	t.Helper()
	dir := filepath.Join(root, module)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "vmlinux", symbol+",1"), 0o755))
	writePatchAttribute(t, dir, "enabled", "1")
	writePatchAttribute(t, dir, "transition", "0")
	return dir
}

func TestActiveLivepatch(t *testing.T) {
	root := t.TempDir()
	// A patch to a different kernel object can name the same function.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "unrelated", "other_object", "listener,1"), 0o755))
	first := addTestLivepatch(t, root, "z_first", "listener")
	module, err := activeLivepatch(root, "listener")
	require.NoError(t, err)
	require.Equal(t, "z_first", module)

	second := addTestLivepatch(t, root, "a_second", "listener")
	_, err = activeLivepatch(root, "listener")
	require.ErrorContains(t, err, "cannot order livepatches")
	writePatchAttribute(t, first, "stack_order", "9")
	writePatchAttribute(t, second, "stack_order", "10")
	module, err = activeLivepatch(root, "listener")
	require.NoError(t, err)
	require.Equal(t, "a_second", module)

	writePatchAttribute(t, second, "enabled", "0")
	writePatchAttribute(t, second, "transition", "1")
	_, err = activeLivepatch(root, "listener")
	require.ErrorContains(t, err, "in transition")
	writePatchAttribute(t, second, "transition", "0")
	module, err = activeLivepatch(root, "listener")
	require.NoError(t, err)
	require.Equal(t, "z_first", module)
}

func TestReplacementHandoff(t *testing.T) {
	restoreAttachments(t)
	m := useTestMonitor(t)
	patch := addTestLivepatch(t, m.patchDir, "patch", "listener")
	const hidden = "0 T listener\n0 t listener [patch]\n0 t listener [unrelated]\n"
	require.NoError(t, os.WriteFile(m.kallsyms, []byte(hidden), 0o600))
	attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) { return nil, unix.EADDRNOTAVAIL }
	links := map[string]*countedLink{}
	fail := false
	attachTraceFSEvent = func(_ *ebpf.Program, opts tracefs.Options) (io.Closer, error) {
		require.True(t, opts.Return)
		require.Len(t, opts.Targets, 1)
		if fail {
			return nil, unix.EBUSY
		}
		token := opts.Targets[0]
		require.NotContains(t, links, token)
		links[token] = &countedLink{}
		return links[token], nil
	}

	l, err := Attach("listener", nil, true)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, l.Close()) })
	require.Len(t, links, 1)
	previous := links["patch:listener"]
	require.NotNil(t, previous)

	// Keep the working replacement if the next attachment fails.
	next := addTestLivepatch(t, m.patchDir, "next", "listener")
	writePatchAttribute(t, patch, "stack_order", "1")
	writePatchAttribute(t, next, "stack_order", "2")
	require.NoError(t, os.WriteFile(m.kallsyms, []byte(hidden+"0 t listener [next]\n"), 0o600))
	fail = true
	require.NoError(t, m.scan())
	require.Zero(t, previous.closes)
	fail = false
	require.NoError(t, m.scan())
	require.Equal(t, 1, previous.closes)
	current := links["next:listener"]
	require.NotNil(t, current)
	require.NoError(t, m.scan())
	require.Zero(t, current.closes)

	// Rollback can leave the disabled modules in kallsyms until they are unloaded.
	writePatchAttribute(t, patch, "enabled", "0")
	writePatchAttribute(t, next, "enabled", "0")
	require.NoError(t, m.scan())
	require.Equal(t, 1, current.closes)
	require.NoError(t, os.WriteFile(m.kallsyms, []byte("0 T listener\n"), 0o600))
	require.NoError(t, m.scan())
	require.Empty(t, m.probes)
	require.Contains(t, links, "listener")
	require.NoError(t, l.Close())
	require.NoError(t, l.Close())
	for _, link := range links {
		assert.Equal(t, 1, link.closes)
	}
}

func TestScanContinuesRetriesAfterSysfsError(t *testing.T) {
	for _, missing := range []string{"", "patch/enabled"} {
		t.Run(filepath.Join("livepatch", missing), func(t *testing.T) {
			restoreAttachments(t)
			m := useTestMonitor(t)
			patch := addTestLivepatch(t, m.patchDir, "patch", "listener")
			otherPatch := addTestLivepatch(t, m.patchDir, "other_patch", "other")
			const remaining = "0 T listener\n0 t listener [patch]\n0 T other\n"
			require.NoError(t, os.WriteFile(m.kallsyms, []byte(remaining+"0 t other [other_patch]\n"), 0o600))

			attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) { return nil, unix.EADDRNOTAVAIL }
			links := map[string]*countedLink{}
			attachTraceFSEvent = func(_ *ebpf.Program, opts tracefs.Options) (io.Closer, error) {
				target := opts.Targets[0]
				require.NotContains(t, links, target)
				links[target] = &countedLink{}
				return links[target], nil
			}
			for _, symbol := range []string{"listener", "other"} {
				probe, err := Attach(symbol, nil, false)
				require.NoError(t, err)
				t.Cleanup(func() { assert.NoError(t, probe.Close()) })
			}

			require.Contains(t, links, "patch:listener")
			require.Contains(t, links, "other_patch:other")

			// Rollback leaves the other probe waiting until its module unloads.
			require.NoError(t, os.RemoveAll(otherPatch))
			require.NoError(t, m.scan())
			require.NotContains(t, links, "other")
			require.Equal(t, 1, links["other_patch:other"].closes)

			require.NoError(t, os.WriteFile(m.kallsyms, []byte(remaining), 0o600))
			path := filepath.Join(m.patchDir, missing)
			require.NoError(t, os.Rename(path, path+".away"))
			err := m.scan()
			require.Contains(t, links, "other")
			require.Zero(t, links["patch:listener"].closes)
			require.ErrorIs(t, err, os.ErrNotExist)
			require.ErrorContains(t, err, path)

			require.NoError(t, os.Rename(path+".away", path))
			writePatchAttribute(t, patch, "enabled", "0")
			require.NoError(t, m.scan())
			require.Equal(t, 1, links["patch:listener"].closes)
		})
	}
}

func TestHiddenAddressesRequireIdentifiableReplacement(t *testing.T) {
	restoreAttachments(t)
	m := useTestMonitor(t)
	attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) { return nil, unix.EADDRNOTAVAIL }
	attachTraceFSEvent = func(*ebpf.Program, tracefs.Options) (io.Closer, error) {
		t.Fatal("unexpected attachment")
		return nil, nil
	}
	require.NoError(t, os.WriteFile(m.kallsyms, []byte("0 T listener\n0 t listener [other]\n"), 0o600))
	_, err := Attach("listener", nil, false)
	require.ErrorContains(t, err, "no active livepatch")
	addTestLivepatch(t, m.patchDir, "patch", "listener")
	_, err = Attach("listener", nil, false)
	require.ErrorContains(t, err, "cannot identify function")
}
