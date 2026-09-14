// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"bytes"
	"debug/pe"
	_ "embed"
	"encoding/base64"
	"testing"

	"github.com/microsoft/go-winmd/winmd"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/dotnet/routes.dll.b64
var testBlob string

func testBlobBytes(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(testBlob)
	require.NoError(t, err)
	return b
}

func openTestBlob(t *testing.T) (*pe.File, *winmd.Metadata) {
	t.Helper()
	p := openDotnetPE(t, testBlobBytes(t))
	m, err := winmd.New(p)
	require.NoError(t, err)
	return p, m
}

func openDotnetPE(t *testing.T, b []byte) *pe.File {
	t.Helper()
	p, err := pe.NewFile(bytes.NewReader(b))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	return p
}
