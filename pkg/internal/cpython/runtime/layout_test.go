// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectLayoutFailsClosed(t *testing.T) {
	future312 := uint32(0x030c00f0) | uint32(supportedVersions["3.12"]+1)<<8
	future313 := uint32(0x030d00f0) | uint32(supportedVersions["3.13"]+1)<<8
	future314 := uint32(0x030e00f0) | uint32(supportedVersions["3.14"]+1)<<8
	tests := []struct {
		name         string
		version      uint32
		freeThreaded bool
		want         bool
	}{
		{name: "3.9 family", version: 0x030919f0, want: true},
		{name: "3.12 family", version: 0x030c07f0, want: true},
		{name: "3.13 family", version: 0x030d0ff0, want: true},
		{name: "3.14 family", version: 0x030e06f0, want: true},
		{name: "3.15 prerelease", version: 0x030f00b4},
		{name: "3.15 final", version: 0x030f00f0},
		{name: "current 3.14 patch", version: 0x030e07f0, want: true},
		{name: "unvalidated 3.14 patch", version: future314},
		{name: "unvalidated 3.13 patch", version: future313},
		{name: "unvalidated 3.12 patch", version: future312},
		{name: "older 3.9 patch", version: 0x030918f0, want: true},
		{name: "unknown minor", version: 0x031000f0},
		{name: "unvalidated old prerelease", version: 0x030c00c1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := selectLayout(tt.version, tt.freeThreaded)
			assert.Equal(t, tt.want, ok)
		})
	}
}

func TestEmbeddedOffsets(t *testing.T) {
	offset, ok := layoutOffsets.Find("PyInterpreterState", "gc", "3.12.13")
	require.True(t, ok)
	assert.Equal(t, uint64(112), offset)
}

func TestMustReadLayoutDataPanicsOnInvalidData(t *testing.T) {
	assert.Panics(t, func() {
		mustReadLayoutData([]byte("{"))
	})
}

func TestSelectLayoutUsesVersionFamilies(t *testing.T) {
	tests := []struct {
		name    string
		version uint32
		want    bool
	}{
		{name: "3.9 rebuilt", version: 0x030900f0, want: true},
		{name: "3.12 new patch", version: 0x030c0df0, want: true},
		{name: "unknown minor", version: 0x031000f0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := selectLayout(tt.version, false)
			assert.Equal(t, tt.want, ok)
		})
	}
}

func TestVersionFromHex(t *testing.T) {
	assert.Equal(t, "3.15.0rc1", versionFromHex(0x030f00c1).String())
	assert.Equal(t, "3.14.6", versionFromHex(0x030e06f0).String())
}
