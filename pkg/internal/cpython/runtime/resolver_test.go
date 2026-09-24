// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func TestSupportedELF(t *testing.T) {
	tests := []struct {
		file *elf.File
		want bool
	}{
		{file: &elf.File{FileHeader: elf.FileHeader{Class: elf.ELFCLASS64, Data: elf.ELFDATA2LSB, Machine: elf.EM_X86_64}}, want: true},
		{file: &elf.File{FileHeader: elf.FileHeader{Class: elf.ELFCLASS64, Data: elf.ELFDATA2LSB, Machine: elf.EM_AARCH64}}, want: true},
		{file: &elf.File{FileHeader: elf.FileHeader{Class: elf.ELFCLASS32, Data: elf.ELFDATA2LSB, Machine: elf.EM_X86_64}}},
		{},
	}
	for _, test := range tests {
		assert.Equal(t, test.want, supportedELF(test.file))
	}
}

func TestParseLegacyVersion(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint32
		ok   bool
	}{
		{name: "build information suffix", data: []byte("3.10.20 (main, Aug 5 2026)"), want: 0x030a14f0, ok: true},
		{name: "null terminator", data: []byte("prefix\x003.9.25\x00suffix"), want: 0x030919f0, ok: true},
		{name: "same version twice", data: []byte("3.9.25\x003.9.25\x00"), want: 0x030919f0, ok: true},
		{name: "conflicting versions", data: []byte("3.9.25\x003.10.20\x00")},
		{name: "embedded text", data: []byte("Python 3.10.20\x00")},
		{name: "invalid micro version", data: []byte("3.10.999\x00")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, ok := parseLegacyVersion(tt.data)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, version)
		})
	}
}

func TestRuntimeVersionFromELFUsesDebugMetadata(t *testing.T) {
	data := make([]byte, debugOffsets.PrefixSize)
	copy(data, debugOffsets.Cookie)
	putDebugWord(data, debugOffsets.Version, 0x030e07f0)
	putDebugWord(data, debugOffsets.FreeThreaded, 1)
	file := elfFileWithLoadSegment(0x1000, data)

	version, freeThreaded, prefix, err := runtimeVersionFromELF(file, &elfAnalysis{anchor: 0x1000})

	require.NoError(t, err)
	assert.Equal(t, uint32(0x030e07f0), version)
	assert.True(t, freeThreaded)
	assert.Equal(t, data, prefix)
}

func TestRuntimeVersionFromELFFallsBackToPyVersion(t *testing.T) {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 0x030c0ef0)
	file := elfFileWithLoadSegment(0x2000, data)

	version, freeThreaded, prefix, err := runtimeVersionFromELF(file, &elfAnalysis{
		anchor:         0x1000,
		versionAddress: 0x2000,
	})

	require.NoError(t, err)
	assert.Equal(t, uint32(0x030c0ef0), version)
	assert.False(t, freeThreaded)
	assert.Nil(t, prefix)
}

func TestRuntimeVersionFromELFFallsBackToLegacyVersion(t *testing.T) {
	file := elfFileWithROData(t, []byte("3.10.20\x00"))

	version, freeThreaded, prefix, err := runtimeVersionFromELF(file, &elfAnalysis{})

	require.NoError(t, err)
	assert.Equal(t, uint32(0x030a14f0), version)
	assert.False(t, freeThreaded)
	assert.Nil(t, prefix)
}

func TestRuntimeVersionFromELFRejectsInvalidDebugMetadata(t *testing.T) {
	data := make([]byte, debugOffsets.PrefixSize)
	copy(data, debugOffsets.Cookie)
	putDebugWord(data, debugOffsets.Version, uint64(math.MaxUint32)+1)
	file := elfFileWithLoadSegment(0x1000, data)

	_, _, _, err := runtimeVersionFromELF(file, &elfAnalysis{anchor: 0x1000})

	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestReadVirtualBytes(t *testing.T) {
	file := elfFileWithLoadSegment(0x1000, []byte("01234567"))

	data, err := readVirtualBytes(file, 0x1002, 4)
	require.NoError(t, err)
	assert.Equal(t, []byte("2345"), data)

	_, err = readVirtualBytes(file, 0x1007, 2)
	require.ErrorIs(t, err, errUnsupportedLayout)

	_, err = readVirtualBytes(file, 0x1000, 0)
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestReadVirtualBytesRejectsOverlappingSegments(t *testing.T) {
	file := elfFileWithLoadSegment(0x1000, []byte("01234567"))
	file.Progs = append(file.Progs, elfFileWithLoadSegment(0x1000, []byte("abcdefgh")).Progs[0])

	_, err := readVirtualBytes(file, 0x1002, 4)

	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestReadVirtualBytesReportsShortRead(t *testing.T) {
	file := elfFileWithLoadSegment(0x1000, []byte("01"))
	file.Progs[0].Filesz = 4

	_, err := readVirtualBytes(file, 0x1000, 4)

	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestRuntimeAnchor(t *testing.T) {
	file := &elf.File{Sections: []*elf.Section{{SectionHeader: elf.SectionHeader{Name: ".PyRuntime", Addr: 0x1000}}}}

	address, ok := runtimeAnchor(file, map[string]procs.Sym{"_PyRuntime": {Value: 0x2000}})
	require.True(t, ok)
	assert.Equal(t, uint64(0x1000), address)

	address, ok = runtimeAnchor(&elf.File{}, map[string]procs.Sym{"_PyRuntime": {Value: 0x2000}})
	require.True(t, ok)
	assert.Equal(t, uint64(0x2000), address)

	_, ok = runtimeAnchor(&elf.File{}, nil)
	assert.False(t, ok)
}

func TestLegacyVersionFromELF(t *testing.T) {
	file := elfFileWithROData(t, []byte("3.10.20\x00"))

	version, ok := legacyVersionFromELF(file)

	require.True(t, ok)
	assert.Equal(t, uint32(0x030a14f0), version)
}

func TestCheckedAddress(t *testing.T) {
	address, err := checkedAddress(100, 20)
	require.NoError(t, err)
	assert.Equal(t, uint64(120), address)

	_, err = checkedAddress(math.MaxUint64, 1)
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestResolveRuntimeObjectCandidatesRejectsAmbiguousRuntime(t *testing.T) {
	objects := []*procfs.ProcMap{{Pathname: "/usr/bin/python"}, {Pathname: "/usr/lib/libpython3.12.so"}}
	_, err := resolveRuntimeObjectCandidates(123, objects, func(*procfs.ProcMap) (*MetricTarget, error) {
		return &MetricTarget{}, nil
	})
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestResolveRuntimeObjectCandidatesKeepsOperationalErrorVisible(t *testing.T) {
	objects := []*procfs.ProcMap{{Pathname: "/usr/bin/python"}, {Pathname: "/usr/lib/libpython3.12.so"}}
	calls := 0
	_, err := resolveRuntimeObjectCandidates(123, objects, func(*procfs.ProcMap) (*MetricTarget, error) {
		calls++
		if calls == 1 {
			return &MetricTarget{}, nil
		}
		return nil, os.ErrPermission
	})
	require.ErrorIs(t, err, os.ErrPermission)
}

func TestResolveRuntimeObjectCandidatesClassifiesMissingLibPythonAnchor(t *testing.T) {
	objects := []*procfs.ProcMap{{Pathname: "/usr/lib/libpython3.12.so"}}

	_, err := resolveRuntimeObjectCandidates(123, objects, func(*procfs.ProcMap) (*MetricTarget, error) {
		return nil, errRuntimeNotFound
	})

	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestResolveRuntimeObjectCandidatesReturnsOnlyPlan(t *testing.T) {
	want := &MetricTarget{PID: 123}
	objects := []*procfs.ProcMap{{Pathname: "/usr/bin/python"}, {Pathname: "/usr/lib/libother.so"}}

	target, err := resolveRuntimeObjectCandidates(123, objects, func(object *procfs.ProcMap) (*MetricTarget, error) {
		if object.Pathname == "/usr/bin/python" {
			return want, nil
		}
		return nil, errRuntimeNotFound
	})

	require.NoError(t, err)
	assert.Same(t, want, target)
}

func TestMetricTargetAttachmentLifecycle(t *testing.T) {
	assert.Empty(t, (*MetricTarget)(nil).AttachmentPath())
	require.NoError(t, (*MetricTarget)(nil).Close())

	attachment, err := os.CreateTemp(t.TempDir(), "python-runtime")
	require.NoError(t, err)
	target := &MetricTarget{attachment: attachment}

	_, err = os.Stat(target.AttachmentPath())
	require.NoError(t, err)
	require.NoError(t, target.Close())
	assert.Empty(t, target.AttachmentPath())
	require.NoError(t, target.Close())
}

func TestResolveReturnsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := NewResolver().Resolve(ctx, app.PID(os.Getpid()), 0)

	require.ErrorIs(t, err, context.Canceled)
}

func TestResolveLiveCPythonBPFPlan(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	command := exec.CommandContext(t.Context(), python, "-c", "import time; time.sleep(30)")
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	pid := app.PID(command.Process.Pid)
	startTime, err := ProcessStartTime(pid)
	require.NoError(t, err)
	var target *MetricTarget
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		target, err = NewResolver().Resolve(t.Context(), pid, startTime)
		if !errors.Is(err, errRuntimeNotFound) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if errors.Is(err, errUnsupportedLayout) {
		t.Skipf("local Python build has no supported GC completion probe: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = target.Close() })
	assert.NotZero(t, target.RuntimeAddress)
	assert.NotZero(t, target.PrimaryProbe.FileOffset)
	assert.Equal(t, startTime, target.StartTime)
	_, err = os.Stat(target.AttachmentPath())
	require.NoError(t, err)
}

func elfFileWithLoadSegment(address uint64, data []byte) *elf.File {
	return &elf.File{Progs: []*elf.Prog{{
		ProgHeader: elf.ProgHeader{
			Type:   elf.PT_LOAD,
			Vaddr:  address,
			Filesz: uint64(len(data)),
		},
		ReaderAt: bytes.NewReader(data),
	}}}
}

func elfFileWithROData(t *testing.T, contents []byte) *elf.File {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)
	data, err := os.ReadFile(executable)
	require.NoError(t, err)
	file, err := elf.NewFile(bytes.NewReader(data))
	require.NoError(t, err)
	rodata := file.Section(".rodata")
	require.NotNil(t, rodata)
	require.LessOrEqual(t, uint64(len(contents)), rodata.Size)
	clear(data[rodata.Offset : rodata.Offset+rodata.Size])
	copy(data[rodata.Offset:], contents)
	file, err = elf.NewFile(bytes.NewReader(data))
	require.NoError(t, err)
	return file
}
