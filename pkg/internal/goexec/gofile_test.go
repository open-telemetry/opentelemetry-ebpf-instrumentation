// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func TestSupportedGoVersion(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// Unsupported versions
		{input: "1.15", want: false},
		{input: "1.15.1", want: false},
		{input: "1.15.15", want: false},
		{input: "1.16beta1", want: false},
		{input: "1.16rc1", want: false},
		{input: "1.16", want: false},
		{input: "1.16.1", want: false},
		{input: "1.16.15", want: false},

		// Supported versions
		{input: "1.17", want: true},
		{input: "1.17beta1", want: true},
		{input: "1.17rc1", want: true},
		{input: "1.17rc2", want: true},
		{input: "1.17.1", want: true},
		{input: "1.17.13", want: true},
		{input: "1.18", want: true},
		{input: "1.18.9", want: true},

		// Uncleaned Go version strings
		{input: "go1.16.4", want: false},
		{input: "go1.21.4", want: true},
		{input: "devel go1.22-098f059 Mon Dec 4 23:03:04 2023 +0000", want: true},

		// Invalid versions
		{input: "devel", want: false},
		{input: "go", want: false},
		{input: "098f059", want: false},
		{input: "Mon Dec 4 23:03:04 2023 +0000", want: false},
	}

	for _, tt := range tests {
		got := supportedGoVersion(tt.input)
		assert.Equal(t, tt.want, got, "input: %v", tt.input)
	}
}

func TestGoRuntimeMemoryMetricVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{version: "go1.20.14"},
		{version: "go1.21.13"},
		{version: "go1.22.12"},
		{version: "go1.23", want: true},
		{version: "go1.26.3", want: true},
		{version: "devel go1.27-abcdef", want: true},
		{version: "unknown"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, goVersionAtLeast(tt.version, minGoRuntimeMemoryMetricVersion))
	}
}

func TestRuntimeMetricGoroutineCountModeVersion(t *testing.T) {
	tests := []struct {
		version        string
		includesSystem bool
		known          bool
	}{
		{version: "go1.25.11", known: true},
		{version: "go1.26.0", includesSystem: true, known: true},
		{version: "unknown"},
	}

	for _, tt := range tests {
		includesSystem, known := runtimeMetricGoroutineCountModeVersion(tt.version)
		assert.Equal(t, tt.includesSystem, includesSystem, "version: %s", tt.version)
		assert.Equal(t, tt.known, known, "version: %s", tt.version)
	}
}

func TestRuntimeMetricGoroutineCountModeFailsClosedWithoutELF(t *testing.T) {
	includesSystem, known := RuntimeMetricGoroutineCountMode(nil)
	assert.False(t, includesSystem)
	assert.False(t, known)
}

func TestRuntimeMetricGCGoalArgumentSupportedVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{version: "go1.17.13"},
		{version: "go1.18.10"},
		{version: "go1.19", want: true},
		{version: "go1.26.3", want: true},
		{version: "unknown"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, runtimeMetricGCGoalArgumentSupportedVersion(tt.version))
	}
}

func TestRuntimeMetricGCGoalArgumentFailsClosedWithoutELF(t *testing.T) {
	assert.False(t, RuntimeMetricGCGoalArgumentSupported(nil))
}

func TestRuntimeMetricSymbolAddrFallsBackToInternalSizeClassTable(t *testing.T) {
	symbols := map[string]procs.Sym{
		runtimeMetricInternalSizeClassToSizesSymbol: {Off: 0x20},
	}

	got := runtimeMetricSymbolAddr(symbols, runtimeMetricSizeClassToSizesSymbol, 0x1000)

	assert.Equal(t, uint64(0x1020), got)
}

func TestRuntimeMetricSymbolAddrResolvesOptionalGoroutineSymbols(t *testing.T) {
	symbols := map[string]procs.Sym{
		runtimeMetricSchedSymbol:   {Off: 0x40},
		runtimeMetricAllgLenSymbol: {Off: 0x50},
		runtimeMetricAllpSymbol:    {Off: 0x60},
	}

	assert.Equal(t, uint64(0x1040),
		runtimeMetricSymbolAddr(symbols, runtimeMetricSchedSymbol, 0x1000))
	assert.Equal(t, uint64(0x1050),
		runtimeMetricSymbolAddr(symbols, runtimeMetricAllgLenSymbol, 0x1000))
	assert.Equal(t, uint64(0x1060),
		runtimeMetricSymbolAddr(symbols, runtimeMetricAllpSymbol, 0x1000))
	assert.Zero(t, runtimeMetricSymbolAddr(nil, runtimeMetricSchedSymbol, 0x1000))
	assert.Zero(t, runtimeMetricSymbolAddr(nil, runtimeMetricAllgLenSymbol, 0x1000))
	assert.Zero(t, runtimeMetricSymbolAddr(nil, runtimeMetricAllpSymbol, 0x1000))
}
