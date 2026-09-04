// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/goabi"
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

func TestFindInterfaceImplsFromFutureGoDWARF(t *testing.T) {
	goVersion, _, err := getGoDetails(smallELF)
	require.NoError(t, err)
	if !goVersionAtLeast(goVersion, "1.27.0") {
		t.Skip("Go 1.27 moduledata is not available")
	}

	elfFile := compileELF(tools.ProjectDir() + "/pkg/internal/goexec/testdata/itab/main.go")
	t.Cleanup(func() { require.NoError(t, elfFile.Close()) })

	implementations, err := findInterfaceImplsFromModuledata(elfFile, "go999.0.0")
	require.NoError(t, err)
	assert.NotZero(t, implementations["*main.workerImpl"])
	assert.NotZero(t, implementations["go.opentelemetry.io/otel/trace.attributeOption"])
}

func TestLoadGeneratedGoRuntimeABI(t *testing.T) {
	_, err := loadGeneratedGoRuntimeABI("go1.27.999")
	require.NoError(t, err)

	_, err = loadGeneratedGoRuntimeABI("go999.0.0")
	require.ErrorContains(t, err, "runtime ABI is not generated")
}

func TestResolveGoRuntimeABI(t *testing.T) {
	generated, err := loadGeneratedGoRuntimeABI("go1.27.0")
	require.NoError(t, err)

	dynamic := generated
	dynamic.Moduledata.PCHeader = 1
	generated.Moduledata.PCHeader = 2

	actual, err := resolveGoRuntimeABI(
		func() (goabi.ABI, error) { return dynamic, nil },
		func() (goabi.ABI, error) { return generated, nil },
	)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), actual.Moduledata.PCHeader)

	actual, err = resolveGoRuntimeABI(
		func() (goabi.ABI, error) { return dynamic, errors.New("incomplete") },
		func() (goabi.ABI, error) { return generated, nil },
	)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), actual.Moduledata.PCHeader)

	_, err = resolveGoRuntimeABI(
		func() (goabi.ABI, error) { return goabi.ABI{}, errors.New("incomplete") },
		func() (goabi.ABI, error) { return goabi.ABI{}, errors.New("unsupported version") },
	)
	require.ErrorContains(t, err, "DWARF discovery: incomplete")
	require.ErrorContains(t, err, "generated fallback: unsupported version")
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
