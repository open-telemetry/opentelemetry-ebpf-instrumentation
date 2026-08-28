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
	assert.NotZero(t, implementations["*main.workerImpl"])
	assert.NotZero(t, implementations["go.opentelemetry.io/otel/trace.attributeOption"])
	assert.NotZero(t, implementations["*errors.errorString"])
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
