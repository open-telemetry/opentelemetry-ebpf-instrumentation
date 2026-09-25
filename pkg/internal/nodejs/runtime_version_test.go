// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"
)

// AsyncLocalStorage was added in 13.10.0 and backported to 12.17.0, so the
// 13.x releases below 13.10 are a hole above the 12.17 bound.
func TestSupportsAsyncLocalStorage(t *testing.T) {
	for _, tc := range []struct {
		nodeVersion string
		supported   bool
	}{
		{"8.17.0", false},
		{"9.3.0", false},
		{"12.16.3", false},
		{"12.17.0", true},
		{"12.22.12", true},
		{"13.0.0", false},
		{"13.9.0", false},
		{"13.10.0", true},
		{"13.14.0", true},
		{"14.0.0", true},
		{"20.11.1", true},
		{"24.3.0", true},
	} {
		t.Run(tc.nodeVersion, func(t *testing.T) {
			require.Equal(t, tc.supported,
				supportsAsyncLocalStorage(version.Must(version.NewVersion(tc.nodeVersion))))
		})
	}
}

func TestNodeVersionFrom(t *testing.T) {
	for _, tc := range []struct {
		name  string
		data  string
		want  string
		found bool
	}{
		{"as Node.js embeds it", "...\x00node.js/v20.11.1\x00...", "20.11.1", true},
		{"the runtime that crashed in the field", "\x00node.js/v9.3.0\x00", "9.3.0", true},
		{"undelimited, so not a whole string in the pool", "node.js/v12.17.0", "", false},
		{"suffix of a longer name", "\x00myapp-node.js/v1.2.3\x00", "", false},
		{"no version anywhere", "\x00some other rodata\x00", "", false},
		{"prefix without a version", "node.js/vnext", "", false},
		{"truncated version", "node.js/v20.11", "", false},
		{"empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, found := nodeVersionFrom([]byte(tc.data))
			require.Equal(t, tc.found, found)

			if tc.found {
				require.Equal(t, tc.want, got.String())
			}
		})
	}
}

// .rodata is read in pieces, so a version sitting across a read boundary must
// still be found. The first read fills chunkSize+versionLiteralMax bytes, so
// that offset — not chunkSize — is where the carry has to do its work; each
// case asserts it actually straddles it, since an earlier version of this test
// silently did not.
func TestScanNodeVersionAcrossChunkBoundary(t *testing.T) {
	const (
		literal   = "node.js/v18.19.0"
		chunkSize = 64
	)

	boundary := chunkSize + versionLiteralMax

	for _, at := range []int{
		boundary - len(literal) + 1, // one byte of the literal before the boundary
		boundary - len(literal)/2,   // split down the middle
		boundary - 1,                // all but one byte after it
	} {
		t.Run(fmt.Sprintf("literal-at-%d", at), func(t *testing.T) {
			require.Less(t, at, boundary, "case starts past the boundary")
			require.Greater(t, at+len(literal), boundary, "case ends before the boundary")

			rodata := append(bytes.Repeat([]byte{0}, at), literal...)
			rodata = append(rodata, bytes.Repeat([]byte{0}, chunkSize)...)

			got, found := scanNodeVersion(bytes.NewReader(rodata), chunkSize)
			require.True(t, found)
			require.Equal(t, "18.19.0", got.String())
		})
	}
}

// A match many chunks in has to survive every intervening carry.
func TestScanNodeVersionInALaterChunk(t *testing.T) {
	const chunkSize = 64

	rodata := append(bytes.Repeat([]byte{0}, 20*chunkSize), "node.js/v20.11.1\x00"...)

	got, found := scanNodeVersion(bytes.NewReader(rodata), chunkSize)
	require.True(t, found)
	require.Equal(t, "20.11.1", got.String())
}

// A chunk size that leaves no room to read would let the scan loop without
// advancing, which times out rather than fails.
func TestScanNodeVersionAlwaysTerminates(t *testing.T) {
	for _, chunkSize := range []int{-1, 0, 1} {
		t.Run(fmt.Sprintf("chunk-size-%d", chunkSize), func(t *testing.T) {
			_, found := scanNodeVersion(bytes.NewReader(bytes.Repeat([]byte{0}, 4096)), chunkSize)
			require.False(t, found)
		})
	}
}

func TestScanNodeVersionFindsNothing(t *testing.T) {
	const chunkSize = 64

	_, found := scanNodeVersion(bytes.NewReader(bytes.Repeat([]byte{0}, 10*chunkSize)), chunkSize)
	require.False(t, found)
}

// The reader is what stands between OBI and a runtime it cannot instrument, so
// it is exercised end to end over the range of releases that matter, from the
// one that crashed in the field to current.
func TestNodeVersionFromELF(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rodata    string
		want      string
		found     bool
		supported bool
	}{
		{name: "the runtime that crashed in the field", rodata: "\x00node.js/v9.3.0\x00", want: "9.3.0", found: true},
		{name: "last release before the backport", rodata: "\x00node.js/v12.16.3\x00", want: "12.16.3", found: true},
		{name: "the backport itself", rodata: "\x00node.js/v12.17.0\x00", want: "12.17.0", found: true, supported: true},
		{name: "13.x before the feature landed", rodata: "\x00node.js/v13.9.0\x00", want: "13.9.0", found: true},
		{name: "13.x after it landed", rodata: "\x00node.js/v13.10.0\x00", want: "13.10.0", found: true, supported: true},
		{name: "current release", rodata: "\x00node.js/v20.11.1\x00", want: "20.11.1", found: true, supported: true},
		{name: "a library that merely embeds the name", rodata: "\x00myapp-node.js/v1.2.3\x00"},
		{name: "no version anywhere", rodata: "\x00libc.so.6\x00GLIBC_2.34\x00"},
		{name: "empty section", rodata: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			elfFile := newELFWithRodata(t, []byte(tc.rodata), elf.SHT_PROGBITS)

			nodeVersion, found := nodeVersionFromELF(elfFile)
			require.Equal(t, tc.found, found)

			if !tc.found {
				return
			}

			require.Equal(t, tc.want, nodeVersion.String())
			require.Equal(t, tc.supported, supportsAsyncLocalStorage(nodeVersion))
		})
	}
}

// A .rodata the file does not actually carry, and an executable with none at
// all, both have to read as unknown rather than panic.
func TestNodeVersionFromELFWithoutReadableRodata(t *testing.T) {
	t.Run("nobits", func(t *testing.T) {
		elfFile := newELFWithRodata(t, []byte("\x00node.js/v20.11.1\x00"), elf.SHT_NOBITS)
		_, found := nodeVersionFromELF(elfFile)
		require.False(t, found)
	})

	t.Run("no file", func(t *testing.T) {
		_, found := nodeVersionFromELF(nil)
		require.False(t, found)
	})
}

// newELFWithRodata assembles the smallest ELF debug/elf will parse: a header,
// one .rodata section holding content, and the section-name table. Real Node.js
// binaries are tens of megabytes, so the version reader is exercised against a
// synthesized one rather than a committed fixture.
func newELFWithRodata(t *testing.T, content []byte, rodataType elf.SectionType) *elf.File {
	t.Helper()

	const (
		ehdrSize  = 64
		shdrSize  = 64
		sectionNr = 3
	)

	names := []byte("\x00.rodata\x00.shstrtab\x00")
	rodataOff := uint64(ehdrSize)
	namesOff := rodataOff + uint64(len(content))
	shdrOff := namesOff + uint64(len(names))

	buf := &bytes.Buffer{}

	ehdr := make([]byte, ehdrSize)
	copy(ehdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})    // magic, 64-bit, little endian, v1
	binary.LittleEndian.PutUint16(ehdr[16:], 2)         // ET_EXEC
	binary.LittleEndian.PutUint16(ehdr[18:], 0x3e)      // x86-64
	binary.LittleEndian.PutUint32(ehdr[20:], 1)         // version
	binary.LittleEndian.PutUint64(ehdr[40:], shdrOff)   // e_shoff
	binary.LittleEndian.PutUint16(ehdr[52:], ehdrSize)  // e_ehsize
	binary.LittleEndian.PutUint16(ehdr[58:], shdrSize)  // e_shentsize
	binary.LittleEndian.PutUint16(ehdr[60:], sectionNr) // e_shnum
	binary.LittleEndian.PutUint16(ehdr[62:], 2)         // e_shstrndx
	buf.Write(ehdr)

	buf.Write(content)
	buf.Write(names)

	section := func(nameOff uint32, typ elf.SectionType, off, size uint64) []byte {
		h := make([]byte, shdrSize)
		binary.LittleEndian.PutUint32(h[0:], nameOff)
		binary.LittleEndian.PutUint32(h[4:], uint32(typ))
		binary.LittleEndian.PutUint64(h[24:], off)
		binary.LittleEndian.PutUint64(h[32:], size)
		return h
	}

	buf.Write(section(0, elf.SHT_NULL, 0, 0))
	buf.Write(section(1, rodataType, rodataOff, uint64(len(content))))
	buf.Write(section(9, elf.SHT_STRTAB, namesOff, uint64(len(names))))

	elfFile, err := elf.NewFile(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = elfFile.Close() })

	return elfFile
}

// 13.10 clears the AsyncLocalStorage floor and predates the 14.0 the span
// bridge needs, so it is the version that tells the two gates apart.
func TestRuntimeRefusalManualSpans(t *testing.T) {
	for _, tc := range []struct {
		nodeVersion string
		manualSpans bool
		want        string
	}{
		{"13.10.0", false, ""},
		{"13.10.0", true, fmt.Sprintf(refusalManualSpansTooOld, "14.0.0", "13.10.0")},
		{"14.0.0", true, ""},
	} {
		t.Run(fmt.Sprintf("%s manual_spans=%v", tc.nodeVersion, tc.manualSpans), func(t *testing.T) {
			elfFile := newELFWithRodata(t, []byte("\x00node.js/v"+tc.nodeVersion+"\x00"), elf.SHT_PROGBITS)

			cfg := obi.DefaultConfig
			cfg.NodeJS.ManualSpans = tc.manualSpans
			i := NewNodeInjector(&cfg)

			require.Equal(t, tc.want, i.runtimeRefusal(InjectionTarget{}, elfFile))
		})
	}
}

// The fallback needs a live process with libnode.so mapped, which a unit test
// cannot stand up; its positive path is covered by running OBI against a
// distribution-packaged Node.js. What can be pinned here is that a process it
// cannot look up reads as unknown rather than as anything else.
func TestNodeVersionFromLibNodeWithoutAProcess(t *testing.T) {
	_, found := nodeVersionFromLibNode(InjectionTarget{})
	require.False(t, found)
}

func TestRuntimeRefusal(t *testing.T) {
	// an unreadable executable is refused rather than injected: the version is
	// what tells us the agent can run at all
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	require.Equal(t, refusalVersionUnknown, i.runtimeRefusal(InjectionTarget{}, nil))
}
