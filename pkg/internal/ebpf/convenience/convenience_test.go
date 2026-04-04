// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfconvenience

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

func TestRoundToNearestMultiple(t *testing.T) {
	tests := []struct {
		x, n, expected uint32
	}{
		{0, 5, 5},   // x < n, should return n
		{3, 5, 5},   // x < n, should return n
		{5, 5, 5},   // x == n, should return n (no rounding needed)
		{6, 5, 5},   // x > n, should round down
		{7, 5, 5},   // x > n, should round down
		{12, 5, 10}, // x > n, should round down
		{13, 5, 15}, // x > n, should round up
		{9, 7, 7},   // x < n, should return n
		{10, 7, 7},  // x == n, should return n
		{11, 7, 14}, // x > n, should round to the nearest multiple
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("x=%d, n=%d", tt.x, tt.n), func(t *testing.T) {
			got := roundToNearestMultiple(tt.x, tt.n)
			if got != tt.expected {
				t.Errorf("roundToNearestMultiple(%d, %d) = %d; want %d", tt.x, tt.n, got, tt.expected)
			}
		})
	}
}

func makeSpec(maps map[string]*ebpf.MapSpec) *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{Maps: maps}
}

func TestSetupMapSizes_ScaleUp(t *testing.T) {
	spec := makeSpec(map[string]*ebpf.MapSpec{
		"my_hash": {Type: ebpf.Hash, MaxEntries: 1024},
	})

	SetupMapSizes(spec, 2, "")

	got := spec.Maps["my_hash"].MaxEntries
	want := uint32(1024 << 2)
	if got != want {
		t.Errorf("scale up: got %d, want %d", got, want)
	}
}

func TestSetupMapSizes_ScaleDown(t *testing.T) {
	spec := makeSpec(map[string]*ebpf.MapSpec{
		"my_hash": {Type: ebpf.Hash, MaxEntries: 1024},
	})

	SetupMapSizes(spec, -2, "")

	got := spec.Maps["my_hash"].MaxEntries
	want := uint32(1024 >> 2)
	if got != want {
		t.Errorf("scale down: got %d, want %d", got, want)
	}
}

func TestSetupMapSizes_ZeroFactorNoOp(t *testing.T) {
	spec := makeSpec(map[string]*ebpf.MapSpec{
		"my_hash": {Type: ebpf.Hash, MaxEntries: 512},
	})

	SetupMapSizes(spec, 0, "")

	got := spec.Maps["my_hash"].MaxEntries
	if got != 512 {
		t.Errorf("zero factor should be no-op: got %d, want 512", got)
	}
}

func TestSetupMapSizes_ClampToMax(t *testing.T) {
	spec := makeSpec(map[string]*ebpf.MapSpec{
		"big": {Type: ebpf.Hash, MaxEntries: MaxMapEntries},
	})

	SetupMapSizes(spec, 1, "")

	got := spec.Maps["big"].MaxEntries
	if got != MaxMapEntries {
		t.Errorf("should clamp to MaxMapEntries: got %d, want %d", got, MaxMapEntries)
	}
}

func TestSetupMapSizes_ClampToMin(t *testing.T) {
	spec := makeSpec(map[string]*ebpf.MapSpec{
		"small": {Type: ebpf.Hash, MaxEntries: 128},
	})

	// Shift right by 2 → 128 >> 2 = 32, which is below MinMapEntries (64)
	SetupMapSizes(spec, -2, "")

	got := spec.Maps["small"].MaxEntries
	if got != MinMapEntries {
		t.Errorf("should clamp to MinMapEntries: got %d, want %d", got, MinMapEntries)
	}
}

func TestSetupMapSizes_SkipsNonResizableTypes(t *testing.T) {
	spec := makeSpec(map[string]*ebpf.MapSpec{
		"prog_array": {Type: ebpf.ProgramArray, MaxEntries: 256},
		"perf":       {Type: ebpf.PerfEventArray, MaxEntries: 256},
		"normal":     {Type: ebpf.Hash, MaxEntries: 256},
	})

	SetupMapSizes(spec, 2, "")

	if spec.Maps["prog_array"].MaxEntries != 256 {
		t.Errorf("ProgramArray should not be resized: got %d", spec.Maps["prog_array"].MaxEntries)
	}
	if spec.Maps["perf"].MaxEntries != 256 {
		t.Errorf("PerfEventArray should not be resized: got %d", spec.Maps["perf"].MaxEntries)
	}
	if spec.Maps["normal"].MaxEntries == 256 {
		t.Error("Hash map should have been resized")
	}
}

func TestSetupMapSizes_SkipsBelowMinResizableMapSize(t *testing.T) {
	spec := makeSpec(map[string]*ebpf.MapSpec{
		"tiny": {Type: ebpf.Hash, MaxEntries: 32},
	})

	SetupMapSizes(spec, 3, "")

	if spec.Maps["tiny"].MaxEntries != 32 {
		t.Errorf("maps below MinResizableMapSize should not be resized: got %d", spec.Maps["tiny"].MaxEntries)
	}
}

func TestSetupMapSizes_SkipsPinnedMaps(t *testing.T) {
	pinDir := t.TempDir()
	// Create files to simulate pinned maps on bpffs
	for _, name := range []string{"pinned_map", "not_pinned_map"} {
		if err := os.WriteFile(filepath.Join(pinDir, name), []byte{}, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	spec := makeSpec(map[string]*ebpf.MapSpec{
		"pinned_map":     {Type: ebpf.Hash, MaxEntries: 1024, Pinning: ebpf.PinByName},
		"not_pinned_map": {Type: ebpf.Hash, MaxEntries: 1024, Pinning: ebpf.PinNone},
		"unpinned_map":   {Type: ebpf.Hash, MaxEntries: 1024},
	})

	SetupMapSizes(spec, 2, pinDir)

	if spec.Maps["pinned_map"].MaxEntries != 1024 {
		t.Errorf("PinByName map with file on disk should be skipped: got %d, want 1024", spec.Maps["pinned_map"].MaxEntries)
	}
	if spec.Maps["not_pinned_map"].MaxEntries == 1024 {
		t.Error("PinNone map should be resized even if a file with same name exists on disk")
	}
	if spec.Maps["unpinned_map"].MaxEntries == 1024 {
		t.Error("unpinned map should have been resized")
	}
}

func TestSetupMapSizes_OverflowClampsToMax(t *testing.T) {
	// Shifting a large value should overflow and be clamped to MaxMapEntries
	spec := makeSpec(map[string]*ebpf.MapSpec{
		"huge": {Type: ebpf.Hash, MaxEntries: 1 << 30},
	})

	SetupMapSizes(spec, 4, "")

	got := spec.Maps["huge"].MaxEntries
	if got != MaxMapEntries {
		t.Errorf("overflow should clamp to MaxMapEntries: got %d, want %d", got, MaxMapEntries)
	}
}

func TestIsResizableMapType(t *testing.T) {
	nonResizable := []ebpf.MapType{
		ebpf.ProgramArray, ebpf.PerfEventArray, ebpf.CGroupArray,
		ebpf.ArrayOfMaps, ebpf.HashOfMaps,
		ebpf.DevMap, ebpf.SockMap, ebpf.CPUMap, ebpf.XSKMap, ebpf.SockHash,
		ebpf.DevMapHash, ebpf.ReusePortSockArray,
	}
	for _, mt := range nonResizable {
		if isResizableMapType(mt) {
			t.Errorf("expected %v to be non-resizable", mt)
		}
	}

	resizable := []ebpf.MapType{ebpf.Hash, ebpf.Array, ebpf.LRUHash, ebpf.RingBuf}
	for _, mt := range resizable {
		if !isResizableMapType(mt) {
			t.Errorf("expected %v to be resizable", mt)
		}
	}
}
