// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"bytes"
	"strings"
	"testing"

	"github.com/grafana/go-offsets-tracker/pkg/offsets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/tools"
)

func TestGo127HTTP2BinaryMetadata(t *testing.T) {
	goVersion, _, err := getGoDetails(smallELF)
	require.NoError(t, err)
	if !goVersionAtLeast(goVersion, minGoRuntimeTypeMetadataVersion) {
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
		HTTP2ServerReqMethodPos,
		HTTP2ServerReqURLPos,
		HTTP2ServerReqTLSPos,
		HTTP2ResponseWriterStatePos,
		HTTP2ResponseWriterReqPos,
	} {
		assert.Contains(t, offsets, field)
	}
}

func TestGo127HTTP2ServerRequestOffsets(t *testing.T) {
	goVersion, _, err := getGoDetails(smallELF)
	require.NoError(t, err)
	if !goVersionAtLeast(goVersion, minGoRuntimeTypeMetadataVersion) {
		t.Skip("Go 1.27 HTTP/2 metadata is not available")
	}

	elfFile := compileELF(tools.ProjectDir() + "/pkg/internal/goexec/testdata/http2/main.go")
	t.Cleanup(func() { require.NoError(t, elfFile.Close()) })
	data, err := elfFile.DWARF()
	require.NoError(t, err)
	fromDwarf, _ := structMemberOffsetsFromDwarf(data)
	stripped := compileELF(tools.ProjectDir()+"/pkg/internal/goexec/testdata/http2/main.go", "-ldflags", "-s -w")
	t.Cleanup(func() { require.NoError(t, stripped.Close()) })
	fromStripped, err := structMemberOffsets(stripped)
	require.NoError(t, err)
	prefetched, err := offsets.Read(bytes.NewBufferString(prefetchedOffsets))
	require.NoError(t, err)

	for _, tt := range []struct {
		typeName string
		field    string
		offset   GoOffset
	}{
		{"net/http/internal/http2.ServerRequest", "Method", HTTP2ServerReqMethodPos},
		{"net/http/internal/http2.ServerRequest", "URL", HTTP2ServerReqURLPos},
		{"net/http/internal/http2.ServerRequest", "TLS", HTTP2ServerReqTLSPos},
		{"net/http/internal/http2.responseWriter", "rws", HTTP2ResponseWriterStatePos},
		{"net/http/internal/http2.responseWriterState", "req", HTTP2ResponseWriterReqPos},
	} {
		structType := dwarfStruct(t, data, tt.typeName)
		want := uint64(dwarfStructField(t, structType, tt.field).ByteOffset)
		assert.Equal(t, want, fromDwarf[tt.offset], tt.field)
		assert.Equal(t, want, fromStripped[tt.offset], tt.field)
		stored, found := prefetched.Find(tt.typeName, tt.field, strings.TrimPrefix(goVersion, "go"))
		require.True(t, found, tt.field)
		assert.Equal(t, want, stored, tt.field)
		_, found = prefetched.Find(tt.typeName, tt.field, "1.26.10")
		assert.False(t, found, tt.field)
	}
}
