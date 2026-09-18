// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"bytes"
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadVirtualMemoryWithFlags(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flags   elf.ProgFlag
		address uint64
		size    uint64
		filesz  uint64
		data    []byte
		want    []byte
	}{
		{"executable", elf.PF_R | elf.PF_X, 0x1001, 2, 3, []byte{1, 2, 3}, []byte{2, 3}},
		{"not executable", elf.PF_R, 0x1000, 1, 3, []byte{1, 2, 3}, nil},
		{"before segment", elf.PF_X, 0xfff, 1, 3, []byte{1, 2, 3}, nil},
		{"crosses file end", elf.PF_X, 0x1002, 2, 3, []byte{1, 2, 3}, nil},
		{"BSS has no file bytes", elf.PF_X, 0x1003, 1, 3, []byte{1, 2, 3}, nil},
		{"truncated file", elf.PF_X, 0x1000, 3, 3, []byte{1}, nil},
		{"offset exceeds int64", elf.PF_X, 0x1000 + 1<<63, 1, 1<<63 + 1, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &elf.File{Progs: []*elf.Prog{{
				ProgHeader: elf.ProgHeader{
					Type: elf.PT_LOAD, Flags: tc.flags, Vaddr: 0x1000,
					Filesz: tc.filesz, Memsz: 16,
				},
				ReaderAt: bytes.NewReader(tc.data),
			}}}
			data, err := readVirtualMemoryWithFlags(f, tc.address, tc.size, elf.PF_X)
			if tc.want == nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, data)
		})
	}
}

func TestReadVirtualMemoryWithoutRequiredPermissions(t *testing.T) {
	f := &elf.File{Progs: []*elf.Prog{{
		ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Vaddr: 0x1000, Filesz: 1},
		ReaderAt:   bytes.NewReader([]byte{42}),
	}}}
	data, err := readVirtualMemory(f, 0x1000, 1)
	require.NoError(t, err)
	require.Equal(t, []byte{42}, data)
}
