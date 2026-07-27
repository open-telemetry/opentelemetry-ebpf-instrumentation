// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// some tests here rely on concrete values for os.GetPageSize() that might differ in non-Linux environments
//go:build linux

package procs

import (
	"debug/elf"
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModulePathMatching(t *testing.T) {
	maps := makeProcFSMaps([]string{"/something/something/libssl.so.3", "anon_inode:[io_uring]"})

	assert.Nil(t, LibPath("node", maps))
	assert.Equal(t, procPSFromPath("/something/something/libssl.so.3"), LibPath("libssl.so", maps))

	maps = makeProcFSMaps([]string{"libssl.so", "/node"})

	assert.Equal(t, procPSFromPath("/node"), LibPath("node", maps))
	assert.Nil(t, LibPath("libssl.so", maps))
}

func makeProcFSMaps(paths []string) []*procfs.ProcMap {
	res := []*procfs.ProcMap{}

	for _, path := range paths {
		p := procfs.ProcMap{Pathname: path, Perms: &procfs.ProcMapPermissions{Execute: true}}
		res = append(res, &p)
	}

	return res
}

func procPSFromPath(path string) *procfs.ProcMap {
	return &procfs.ProcMap{Pathname: path, Perms: &procfs.ProcMapPermissions{Execute: true}}
}

func TestExeLoadBias(t *testing.T) {
	maps := []*procfs.ProcMap{{
		StartAddr: 0x7f0000400000,
		Offset:    0,
		Pathname:  "/proc/123/exe",
	}}
	progs := []*elf.Prog{{
		ProgHeader: elf.ProgHeader{
			Type:  elf.PT_LOAD,
			Off:   0,
			Vaddr: 0x400000,
		},
	}}

	bias, err := exeLoadBias("/proc/123/exe", maps, progs)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x7f0000000000), bias)
}

func TestExeLoadBiasETExec(t *testing.T) {
	maps := []*procfs.ProcMap{{
		StartAddr: 0x400000,
		Offset:    0,
		Pathname:  "/proc/123/exe",
	}}
	progs := []*elf.Prog{{
		ProgHeader: elf.ProgHeader{
			Type:  elf.PT_LOAD,
			Off:   0,
			Vaddr: 0x400000,
		},
	}}

	bias, err := exeLoadBias("/proc/123/exe", maps, progs)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), bias)
}

func TestExeLoadBiasMatchesMappingOffset(t *testing.T) {
	maps := []*procfs.ProcMap{{
		StartAddr: 0x7f0000401000,
		Offset:    0x1000,
		Pathname:  "/proc/123/exe",
	}}
	progs := []*elf.Prog{{
		ProgHeader: elf.ProgHeader{
			Type:  elf.PT_LOAD,
			Off:   0x1000,
			Vaddr: 0x401000,
		},
	}}

	bias, err := exeLoadBias("/proc/123/exe", maps, progs)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x7f0000000000), bias)
}
