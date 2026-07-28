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

func TestParseModulesTracksReplacements(t *testing.T) {
	modules := parseModules(
		"dep\tgo.opentelemetry.io/auto/sdk\tv1.1.0\n" +
			"=>\t../auto-sdk\t\t\n" +
			"dep\tgo.opentelemetry.io/otel\tv1.33.0\n" +
			"=>\texample.com/otel-fork\tv1.33.0\th1:fork\n" +
			"dep\tgo.opentelemetry.io/otel/trace\tv1.44.0\n" +
			"=>\tgo.opentelemetry.io/otel/trace\tv1.43.0\th1:older\n" +
			"dep\texample.com/unmodified\tv1.0.0\th1:unmodified\n",
	)

	assert.Equal(t, map[string]string{
		"go.opentelemetry.io/auto/sdk":   "v1.1.0",
		"go.opentelemetry.io/otel":       "v1.33.0",
		"go.opentelemetry.io/otel/trace": "v1.44.0",
		"example.com/unmodified":         "v1.0.0",
	}, modules.versions)
	assert.Equal(t, map[string]string{
		"go.opentelemetry.io/auto/sdk":   "",
		"go.opentelemetry.io/otel":       "",
		"go.opentelemetry.io/otel/trace": "",
		"example.com/unmodified":         "h1:unmodified",
	}, modules.sums)
	assert.Equal(t, map[string]struct{}{
		"go.opentelemetry.io/auto/sdk":   {},
		"go.opentelemetry.io/otel":       {},
		"go.opentelemetry.io/otel/trace": {},
	}, modules.replacements)
}

func TestParseModulesRejectsOrphanReplacement(t *testing.T) {
	modules := parseModules("=>\t../auto-sdk\t\t\n")

	assert.Empty(t, modules.versions)
	assert.Empty(t, modules.replacements)
}

func TestParseModulesRejectsMisassociatedReplacement(t *testing.T) {
	modules := parseModules(
		"dep\tgo.opentelemetry.io/auto/sdk\tv1.2.1\n" +
			"dep\texample.com/unrelated\tv1.0.0\th1:unrelated\n" +
			"=>\t../auto-sdk\t\t\n",
	)

	assert.Empty(t, modules.versions)
	assert.Empty(t, modules.sums)
	assert.Empty(t, modules.replacements)
}

func TestRuntimeMetricSymbolAddrFallsBackToInternalSizeClassTable(t *testing.T) {
	symbols := map[string]procs.Sym{
		runtimeMetricInternalSizeClassToSizesSymbol: {Off: 0x20},
	}

	got := runtimeMetricSymbolAddr(symbols, runtimeMetricSizeClassToSizesSymbol, 0x1000)

	assert.Equal(t, uint64(0x1020), got)
}
