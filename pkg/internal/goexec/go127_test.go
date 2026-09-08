// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/tools"
)

func TestGo127HTTP2BinaryMetadata(t *testing.T) {
	goVersion, _, err := getGoDetails(smallELF)
	require.NoError(t, err)
	if !goVersionAtLeast(goVersion, "1.27.0") {
		t.Skip("Go 1.27 HTTP/2 metadata is not available")
	}
	elfFile := compileELF(
		tools.ProjectDir()+"/pkg/internal/goexec/testdata/http2/main.go",
		"-ldflags", "-s -w",
	)
	t.Cleanup(func() { require.NoError(t, elfFile.Close()) })

	symbols := []string{
		"net/http/internal/http2.(*clientStream).encodeAndWriteHeaders",
		"net/http/internal/http2.(*ClientConn).writeHeader",
		"net/http/internal/http2.(*ClientConn).writeHeaders",
		"net/http/internal/http2.(*Framer).WriteHeaders",
		"net/http/internal/http2.(*responseWriter).handlerDone",
		"net/http/internal/http2.(*responseWriterState).writeHeader",
		"net/http/internal/http2.(*serverConn).processHeaders",
		"net/http/internal/http2.(*serverConn).runHandler",
	}
	points, err := instrumentationPoints(elfFile, symbols)
	require.NoError(t, err)
	for _, symbol := range symbols {
		assert.Contains(t, points, symbol)
	}

	offsets, err := structMemberOffsets(elfFile)
	require.NoError(t, err)
	for _, field := range []GoOffset{
		CcNextStreamIDVendoredPos,
		CcTconnVendoredPos,
		CcTLSVendoredPos,
		CcFramerVendoredPos,
		FramerWPos,
		MetaHeadersFrameFieldsPtrPos,
		ScConnPos,
	} {
		assert.Contains(t, offsets, field)
	}
}
