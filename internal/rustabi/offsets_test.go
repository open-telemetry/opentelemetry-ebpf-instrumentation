// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rustabi

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddPathCrateVersions(t *testing.T) {
	tests := []struct {
		name string
		data string
		want map[string][]string
	}{
		{
			name: "cargo registry and vendor paths",
			data: "/root/.cargo/registry/src/index.crates.io/tokio-1.48.0/src/lib.rs " +
				`C:\vendor\hyper-1.7.0\src\lib.rs`,
			want: map[string][]string{"tokio": {"1.48.0"}, "hyper": {"1.7.0"}},
		},
		{
			name: "bazel repository and space separated path",
			data: "external/rules_rust__crate_universe__bytes-1.10.1/src/lib.rs reqwest-0.12.24/src/lib.rs",
			want: map[string][]string{"bytes": {"1.10.1"}, "reqwest": {"0.12.24"}},
		},
		{
			name: "multiple versions and duplicates",
			data: "/tokio-1.48.0/src /tokio-1.48.0/src /tokio-1.47.1/src",
			want: map[string][]string{"tokio": {"1.48.0", "1.47.1"}},
		},
		{
			name: "stable and prerelease versions",
			data: "/vendor/hyper-1.7.0/src/lib.rs /vendor/hyper-1.8.0-rc.1/src/lib.rs /vendor/hyper-1.8.0-rc.1/src/client.rs",
			want: map[string][]string{"hyper": {"1.7.0", "1.8.0-rc.1"}},
		},
		{
			name: "prerelease and build metadata in Windows and Bazel paths",
			data: `C:\vendor\hyper-1.8.0-rc.1+build.7\src\lib.rs external/rules_rust__crate_universe__tokio-1.48.0+build.2/src/lib.rs`,
			want: map[string][]string{"hyper": {"1.8.0-rc.1+build.7"}, "tokio": {"1.48.0+build.2"}},
		},
		{
			name: "invalid versions",
			data: "/hyper-1.8.0-rc.01/src /hyper-1.8.0-rc..1/src /hyper-1.8.0_bad/src /hyper-1.8.0rc1/src /hyper-1.8.0+/src /hyper-01.8.0/src",
			want: map[string][]string{},
		},
		{
			name: "untracked and incomplete paths",
			data: "/serde-1.0.228/src /tokio-1.48/src /tokio-1.48.0",
			want: map[string][]string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			crates := map[string][]string{}
			addPathCrateVersions(crates, []byte(test.data))
			require.Equal(t, test.want, crates)
		})
	}
}

func TestAddAuditableCrateVersions(t *testing.T) {
	tests := []struct {
		name     string
		packages []rustAuditablePackage
		initial  map[string][]string
		want     map[string][]string
	}{
		{
			name: "registry runtime packages",
			packages: []rustAuditablePackage{
				{Name: "tokio", Version: "1.48.0", Source: jsonString("crates.io"), Kind: "runtime"},
				{Name: "hyper", Version: "1.7.0", Source: jsonString("registry"), Kind: "runtime"},
				{Name: "bytes", Version: "1.10.1", Source: jsonString("crates.io")},
			},
			want: map[string][]string{"tokio": {"1.48.0"}, "hyper": {"1.7.0"}, "bytes": {"1.10.1"}},
		},
		{
			name: "non registry and build packages",
			packages: []rustAuditablePackage{
				{Name: "tokio", Version: "1.48.0", Source: jsonString("git"), Kind: "runtime"},
				{Name: "hyper", Version: "1.7.0", Source: jsonString("local"), Kind: "runtime"},
				{Name: "bytes", Version: "1.10.1", Source: json.RawMessage(`{"Other":"unknown"}`), Kind: "runtime"},
				{Name: "reqwest", Version: "0.12.24", Source: jsonString("crates.io"), Kind: "build"},
				{Name: "serde", Version: "1.0.228", Source: jsonString("crates.io"), Kind: "runtime"},
			},
			want: map[string][]string{},
		},
		{
			name: "deduplicates packages and existing path versions",
			packages: []rustAuditablePackage{
				{Name: "tokio", Version: "1.48.0", Source: jsonString("crates.io"), Kind: "runtime"},
				{Name: "tokio", Version: "1.48.0", Source: jsonString("registry"), Kind: "runtime"},
				{Name: "tokio", Version: "1.47.1", Source: jsonString("crates.io"), Kind: "runtime"},
			},
			initial: map[string][]string{"tokio": {"1.48.0"}},
			want:    map[string][]string{"tokio": {"1.48.0", "1.47.1"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(struct {
				Packages []rustAuditablePackage `json:"packages"`
			}{Packages: test.packages})
			require.NoError(t, err)

			crates := test.initial
			if crates == nil {
				crates = map[string][]string{}
			}
			require.NoError(t, addAuditableCrateVersions(crates, zlibData(t, data)))
			require.Equal(t, test.want, crates)
		})
	}
}

func TestReadCompilerWithMalformedCrates(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	f := testELF(t, []testELFSection{
		{Name: rustAuditableSection, Data: []byte("invalid zlib")},
		{Name: ".comment", Data: []byte("rustc version 1.99.0 (012345678)")},
		{Name: ".rodata", Data: []byte("/rustc/" + commit + "/library/core/src/lib.rs")},
	})
	build, err := ReadCompiler(f)
	require.NoError(t, err)
	require.Equal(t, Build{Arch: "amd64", Rustc: "1.99.0", CompilerCommit: commit}, build)

	// A readable compiler comment is sufficient even when source paths are unreadable.
	f.Section(".rodata").Type = elf.SHT_NOBITS
	build, err = ReadCompiler(f)
	require.NoError(t, err)
	require.Equal(t, Build{Arch: "amd64", Rustc: "1.99.0"}, build)
}

func TestReadCratesPrefersAuditableMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source json.RawMessage
		kind   string
		want   map[string][]string
	}{
		{"local", jsonString("local"), "runtime", map[string][]string{}},
		{"git", jsonString("git"), "runtime", map[string][]string{}},
		{"unknown source", jsonString("other"), "runtime", map[string][]string{}},
		{"object source", json.RawMessage(`{"Other":"unknown"}`), "runtime", map[string][]string{}},
		{"build dependency", jsonString("registry"), "build", map[string][]string{}},
		{"unknown dependency kind", jsonString("registry"), "unknown", map[string][]string{}},
		{"runtime dependency", jsonString("registry"), "runtime", map[string][]string{"hyper": {"1.12.0"}}},
		{"default runtime dependency", jsonString("crates.io"), "", map[string][]string{"hyper": {"1.12.0"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := testELFSection{Name: ".rodata", Data: []byte("/vendor/hyper-1.12.0/src/lib.rs")}
			metadata := testELFSection{Name: rustAuditableSection, Data: zlibData(t, auditableData(t,
				rustAuditablePackage{Name: "hyper", Version: "1.12.0", Source: tc.source, Kind: tc.kind},
			))}
			for _, sections := range [][]testELFSection{{paths, metadata}, {metadata, paths}} {
				t.Run(sections[0].Name+" first", func(t *testing.T) {
					crates, err := ReadCrates(testELF(t, sections))
					require.NoError(t, err)
					require.Equal(t, tc.want, crates)
				})
			}
		})
	}
}

func TestReadCrates(t *testing.T) {
	tests := []struct {
		name     string
		sections []testELFSection
		want     map[string][]string
		wantErr  string
	}{
		{
			name: "without optional auditable section",
			sections: []testELFSection{
				{Name: ".comment", Data: []byte("rustc version 1.91.1 (ed61e7d7e 2025-11-07)")},
				{Name: ".rodata", Data: []byte("/cargo/registry/src/tokio-1.48.0/src/runtime.rs")},
			},
			want: map[string][]string{"tokio": {"1.48.0"}},
		},
		{
			name: "source paths retain a second prerelease dependency",
			sections: []testELFSection{
				{Name: ".rodata", Data: []byte("/vendor/hyper-1.7.0/src/lib.rs /vendor/hyper-1.8.0-rc.1/src/lib.rs")},
			},
			want: map[string][]string{"hyper": {"1.7.0", "1.8.0-rc.1"}},
		},
		{
			name: "auditable list overrides stale and unrecorded source paths",
			sections: []testELFSection{
				{Name: ".rodata", Data: []byte("/cargo/registry/src/tokio-1.48.0/src/runtime.rs /vendor/hyper-1.12.0/src/lib.rs /vendor/bytes-1.12.1/src/lib.rs")},
				{Name: rustAuditableSection, Data: zlibData(t, auditableData(t,
					rustAuditablePackage{Name: "tokio", Version: "1.48.0", Source: jsonString("crates.io"), Kind: "runtime"},
					rustAuditablePackage{Name: "hyper", Version: "1.7.0", Source: jsonString("registry"), Kind: "runtime"},
				))},
			},
			want: map[string][]string{"tokio": {"1.48.0"}, "hyper": {"1.7.0"}},
		},
		{
			name: "malformed zlib discards partial crate versions",
			sections: []testELFSection{
				{Name: ".rodata", Data: []byte("/cargo/tokio-1.48.0/src/runtime.rs")},
				{Name: rustAuditableSection, Data: []byte("not zlib")},
			},
			wantErr: "reading .dep-v0",
		},
		{
			name:     "malformed JSON data",
			sections: []testELFSection{{Name: rustAuditableSection, Data: zlibData(t, []byte("not JSON"))}},
			wantErr:  "reading .dep-v0",
		},
		{
			name: "oversized decompressed data",
			sections: []testELFSection{{
				Name: rustAuditableSection,
				Data: zlibData(t, bytes.Repeat([]byte{' '}, rustAuditableMaxBytes+1)),
			}},
			wantErr: "dependency list exceeds the size limit",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := testELF(t, test.sections)
			crates, err := ReadCrates(f)
			require.Equal(t, test.want, crates)
			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr)
			}
		})
	}
}

type testELFSection struct {
	Name string
	Data []byte
}

func testELFImage(t *testing.T, sections []testELFSection) []byte {
	t.Helper()

	var names []byte
	names = append(names, 0)
	headers := make([]elf.Section64, len(sections)+2)
	for i, section := range sections {
		headers[i+1].Name = uint32(len(names))
		names = append(names, section.Name...)
		names = append(names, 0)
	}
	shstrIndex := len(headers) - 1
	headers[shstrIndex].Name = uint32(len(names))
	names = append(names, ".shstrtab\x00"...)
	headers[shstrIndex].Type = uint32(elf.SHT_STRTAB)

	var data bytes.Buffer
	header := elf.Header64{
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Ehsize:    uint16(binary.Size(elf.Header64{})),
		Shentsize: uint16(binary.Size(elf.Section64{})),
		Shnum:     uint16(len(headers)),
		Shstrndx:  uint16(shstrIndex),
	}
	header.Ident[0] = 0x7f
	copy(header.Ident[1:], "ELF")
	header.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	header.Shoff = uint64(binary.Size(header)) + uint64(len(names))
	for _, section := range sections {
		header.Shoff += uint64(len(section.Data))
	}
	require.NoError(t, binary.Write(&data, binary.LittleEndian, header))

	for i, section := range sections {
		headers[i+1].Type = uint32(elf.SHT_PROGBITS)
		headers[i+1].Off = uint64(data.Len())
		headers[i+1].Size = uint64(len(section.Data))
		data.Write(section.Data)
	}
	headers[shstrIndex].Off = uint64(data.Len())
	headers[shstrIndex].Size = uint64(len(names))
	data.Write(names)
	for _, sectionHeader := range headers {
		require.NoError(t, binary.Write(&data, binary.LittleEndian, sectionHeader))
	}

	return data.Bytes()
}

func testELF(t *testing.T, sections []testELFSection) *elf.File {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(testELFImage(t, sections)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	return f
}

func auditableData(t *testing.T, packages ...rustAuditablePackage) []byte {
	t.Helper()
	data, err := json.Marshal(struct {
		Packages []rustAuditablePackage `json:"packages"`
	}{Packages: packages})
	require.NoError(t, err)
	return data
}

func jsonString(value string) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}

func zlibData(t *testing.T, data []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	_, err := writer.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return compressed.Bytes()
}

func TestCheckCompiler(t *testing.T) {
	// The database records one patch of each compiler minor for this binary's architecture.
	db := Database{Profiles: []Profile{
		{Arch: "amd64", Rustc: "1.98.1", CompilerCommit: "known"},
		{Arch: "amd64", Rustc: "1.99.1"},
		{Arch: "arm64", Rustc: "1.100.0"},
	}}

	for _, build := range []Build{
		{Arch: "amd64", Rustc: "1.98.0"},
		{Arch: "amd64", Rustc: "1.99.0"},
		{Arch: "amd64", Rustc: "1.99.2"},
		{Arch: "arm64", Rustc: "1.100.0"},
		{Arch: "amd64", CompilerCommit: "known"},
	} {
		require.NoError(t, db.CheckCompiler(build), "%+v", build)
	}

	for _, build := range []Build{
		{Arch: "amd64", Rustc: "1.96.9"},
		{Arch: "arm64", Rustc: "1.99.1"},
		{Arch: "amd64", Rustc: "1.101.0", CompilerCommit: "known"},
		{Arch: "amd64", Rustc: "1.99.0-nightly"},
		{Arch: "amd64", CompilerCommit: "unknown"},
		{Arch: "arm64", CompilerCommit: "known"},
	} {
		require.ErrorIs(t, db.CheckCompiler(build), ErrUnsupportedCompiler, "%+v", build)
	}
}
