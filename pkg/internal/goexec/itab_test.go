// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/tools"
)

func TestIsITabEntry(t *testing.T) {
	cases := []struct {
		name string
		sym  string
		want bool
	}{
		{"new prefix", "go:itab.*net/http.response,net/http.ResponseWriter", true},
		{"old prefix", "go.itab.*net/http.response,net/http.ResponseWriter", true},
		{"not itab", "go:typelink.blah", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isITabEntry(c.sym); got != c.want {
				t.Errorf("isITabEntry(%q) = %v, want %v", c.sym, got, c.want)
			}
		})
	}
}

func TestITabType(t *testing.T) {
	cases := []struct {
		name string
		sym  string
		want string
	}{
		{"valid new", "go:itab.*net/http.response,net/http.ResponseWriter", "*net/http.response"},
		{"valid old", "go.itab.*net/http.response,net/http.ResponseWriter", "*net/http.response"},
		{"short", "go:itab.", ""},
		{"no comma", "go:itab.something", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := iTabType(c.sym); got != c.want {
				t.Errorf("iTabType(%q) = %q, want %q", c.sym, got, c.want)
			}
		})
	}
}

func TestFindInterfaceImplsFromGo127Moduledata(t *testing.T) {
	goVersion, _, err := getGoDetails(smallELF)
	require.NoError(t, err)
	if !goVersionAtLeast(goVersion, "1.27.0") {
		t.Skip("Go 1.27 moduledata is not available")
	}

	elfFile := compileELF(
		tools.ProjectDir()+"/pkg/internal/goexec/testdata/itab/main.go",
		"-ldflags", "-s -w",
	)
	t.Cleanup(func() { require.NoError(t, elfFile.Close()) })

	implementations, err := findInterfaceImpls(elfFile)
	require.NoError(t, err)
	for _, typeName := range []string{
		"*main.workerImpl",
		"main.arrayWorker",
		"main.chanWorker",
		"main.funcWorker",
		"main.mapWorker",
		"main.scalarWorker",
		"main.sliceWorker",
		"main.structWorker",
	} {
		assert.NotZero(t, implementations[typeName], typeName)
	}
	assert.NotZero(t, implementations["go.opentelemetry.io/otel/trace.attributeOption"])
	assert.NotZero(t, implementations["*errors.errorString"])
}

func TestGo127UncommonOffset(t *testing.T) {
	tests := []struct {
		name string
		kind byte
		want uint64
	}{
		{name: "array", kind: go127KindArray, want: 72},
		{name: "chan", kind: go127KindChan, want: 64},
		{name: "func", kind: go127KindFunc, want: 56},
		{name: "interface", kind: go127KindInterface, want: 80},
		{name: "map", kind: go127KindMap, want: 136},
		{name: "pointer", kind: go127KindPointer, want: 56},
		{name: "slice", kind: go127KindSlice, want: 56},
		{name: "struct", kind: go127KindStruct, want: 80},
		{name: "default", kind: 0, want: 48},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, go127UncommonOffset(tt.kind))
		})
	}
}

func TestFindGRPCInterfaceImplsFromGo127Moduledata(t *testing.T) {
	goVersion, _, err := getGoDetails(smallGRPCElf)
	require.NoError(t, err)
	if !goVersionAtLeast(goVersion, "1.27.0") {
		t.Skip("Go 1.27 moduledata is not available")
	}

	implementations, err := findInterfaceImpls(smallGRPCElf)
	require.NoError(t, err)
	assert.NotZero(t, implementations["*google.golang.org/grpc/internal/credentials.syscallConn"])
	assert.NotZero(t, implementations["*crypto/tls.Conn"])
}
