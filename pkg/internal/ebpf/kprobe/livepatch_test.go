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

func TestDuplicateAddresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kallsyms")
	require.NoError(t, os.WriteFile(path, []byte(
		"0001 T listener\n0001 T listener\n0002 t listener\n"+
			"0003 t listener\t[module]\n0004\t t  listener  [module]\n"+
			"0000 t listener\t[hidden]\n0006 D listener\n0007 T listener_extra\n"+
			"0008 t listener\t[mixed]\n0009 d listener\t[mixed]\n"), 0o600))
	syms, err := readSymbols(path, map[string]bool{"listener": true})
	require.NoError(t, err)
	got, err := syms.targets("listener", nil)
	require.NoError(t, err)
	assert.Equal(t, map[probeTarget]bool{
		{"", "0x1"}: true, {"", "0x2"}: true, {"module", "0x3"}: true,
		{"module", "0x4"}: true, {"hidden", "hidden:listener"}: true, {"mixed", "0x8"}: true,
	}, got)

	require.NoError(t, os.WriteFile(path, []byte(
		"0 T listener\n0 t listener\t[hidden]\n0 t listener\t[ambiguous]\n0 t listener\t[ambiguous]\n"), 0o600))
	syms, err = readSymbols(path, map[string]bool{"listener": true})
	require.NoError(t, err)
	got, err = syms.targets("listener", nil)
	require.ErrorContains(t, err, "hidden")
	assert.Equal(t, map[probeTarget]bool{{"hidden", "hidden:listener"}: true}, got)
	got, err = syms.targets("listener", map[string]bool{"hidden": true, "renamed": true})
	require.ErrorContains(t, err, "renamed")
	assert.Equal(t, map[probeTarget]bool{{"hidden", "hidden:listener"}: true}, got)
}

func TestDuplicateAttachRetriesPartialFailure(t *testing.T) {
	restoreAttachments(t)
	m := useTestMonitor(t)
	// Ambiguous symbols can also belong to ordinary modules on a kernel without livepatch.
	require.NoError(t, os.Remove(m.patchDir))
	sym := syscallPrefix() + "sys_listen"
	require.NoError(t, os.WriteFile(m.kallsyms, []byte("0010 T "+sym+"\n0020 t "+sym+"\t[patch]\n"), 0o600))
	attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) { return nil, unix.EADDRNOTAVAIL }
	links := map[string]*countedLink{}
	fail := true
	attachTraceFSEvent = func(_ *ebpf.Program, opts tracefs.Options) (io.Closer, error) {
		require.True(t, opts.Return)
		require.Len(t, opts.Targets, 1)
		token := opts.Targets[0]
		if token == "0x10" && fail {
			return nil, unix.EBUSY
		}
		require.NotContains(t, links, token)
		links[token] = &countedLink{}
		return links[token], nil
	}
	l, err := Attach("sys_listen", nil, true)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, l.Close()) })
	require.Contains(t, links, "patch:"+sym)
	fail = false
	require.NoError(t, m.scan())
	require.NoError(t, m.scan())
	require.Contains(t, links, "0x10")
	require.NoError(t, os.WriteFile(m.kallsyms, []byte("0010 T "+sym+"\n"), 0o600))
	require.NoError(t, m.scan())
	assert.Equal(t, 1, links["patch:"+sym].closes)
	assert.Zero(t, links["0x10"].closes)
	require.NoError(t, l.Close())
	require.NoError(t, l.Close())
	for _, link := range links {
		assert.Equal(t, 1, link.closes)
	}
	require.Empty(t, m.probes)

	attachTraceFSEvent = func(*ebpf.Program, tracefs.Options) (io.Closer, error) { return nil, unix.EROFS }
	failed, err := Attach("sys_listen", nil, true)
	require.Nil(t, failed)
	require.ErrorIs(t, err, unix.EADDRNOTAVAIL)
	require.ErrorIs(t, err, unix.EROFS)
	require.Empty(t, m.probes)
}

func TestScanSkipsMissingLivepatchDir(t *testing.T) {
	m := useTestMonitor(t)
	primary := &watchedProbe{symbol: "listener", primary: nopCloser{}}
	duplicate := &watchedProbe{symbol: "other"}
	m.probes = map[*watchedProbe]bool{primary: true, duplicate: true}

	// The duplicate needs kallsyms, which is also missing.
	require.NoError(t, os.Remove(m.patchDir))
	require.NoError(t, m.scan())
	require.NoError(t, os.Mkdir(m.patchDir, 0o755))
	require.ErrorIs(t, m.scan(), os.ErrNotExist)
}

func TestScanLivepatchTransitions(t *testing.T) {
	restoreAttachments(t)
	m := useTestMonitor(t)
	base := &countedLink{}
	attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) { return base, nil }
	var added []*countedLink
	attachTraceFSEvent = func(_ *ebpf.Program, opts tracefs.Options) (io.Closer, error) {
		require.Equal(t, []string{"patch:listener"}, opts.Targets)
		link := &countedLink{}
		added = append(added, link)
		return link, nil
	}
	l, err := Attach("listener", nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, l.Close()) })
	// With no livepatch a scan must work without opening kallsyms.
	require.NoError(t, m.scan())
	root := filepath.Join(m.patchDir, "patch")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "vmlinux", "listener,1"), 0o755))
	writeState := func(attr, value string) {
		require.NoError(t, os.WriteFile(filepath.Join(root, attr), []byte(value+"\n"), 0o600))
	}
	writeState("enabled", "1")
	writeState("transition", "0")
	require.NoError(t, os.WriteFile(m.kallsyms, []byte("0001 T listener\n0002 t listener\t[patch]\n0003 t listener\t[unrelated]\n"), 0o600))
	writeState("vmlinux/patched", "0")
	require.NoError(t, m.scan())
	require.Empty(t, added)
	writeState("vmlinux/patched", "1")
	require.NoError(t, m.scan())
	require.NoError(t, m.scan())
	require.Len(t, added, 1)
	require.NoError(t, os.Rename(m.kallsyms, m.kallsyms+".away"))
	require.ErrorIs(t, m.scan(), os.ErrNotExist)
	assert.Zero(t, added[0].closes)
	require.NoError(t, os.Rename(m.kallsyms+".away", m.kallsyms))
	enabled := filepath.Join(root, "enabled")
	require.NoError(t, os.Remove(enabled))
	require.NoError(t, os.Mkdir(enabled, 0o755))
	require.NoError(t, m.scan())
	assert.Zero(t, added[0].closes)
	require.NoError(t, os.Remove(enabled))
	writeState("enabled", "0")
	writeState("transition", "1")
	require.NoError(t, m.scan())
	assert.Zero(t, added[0].closes)
	writeState("transition", "0")
	require.NoError(t, m.scan())
	assert.Equal(t, 1, added[0].closes)
	writeState("enabled", "1")
	require.NoError(t, m.scan())
	require.Len(t, added, 2)
	require.NoError(t, l.Close())
	require.NoError(t, m.scan())
	assert.Equal(t, 1, added[1].closes)
	assert.Equal(t, 1, base.closes)
}
