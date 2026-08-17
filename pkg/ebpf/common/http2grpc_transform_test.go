// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/bhpack"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestHTTP2InfoToSpanSetsFullPath(t *testing.T) {
	var info BPFHTTP2Info
	info.Type = uint8(request.EventTypeHTTP)
	span := http2InfoToSpan(&info, "GET", "/users", "/users?x=1", "peer", "host", 200, HTTP2)
	assert.Equal(t, "/users", span.Path)
	assert.Equal(t, "/users?x=1", span.FullPath)
}

var isHTTP2TestCases = []struct {
	name          string
	input         []byte
	inputLen      int
	expected      bool
	expectedQuick bool
}{
	{
		name:          "Test no :path, but has :scheme",
		input:         []byte{0, 0, 77, 1, 4, 0, 0, 7, 35, 195, 194, 131, 134, 193, 192, 191, 190, 0, 11, 116, 114, 97, 99, 101, 112, 97, 114, 101, 110, 116, 55, 48, 48, 45, 52, 53, 53, 49, 102, 50, 57, 102, 101, 102, 54, 97, 50, 57, 56, 51, 52, 51, 48, 102, 98, 101, 49, 101, 53, 101, 99, 99, 101, 100, 55, 54, 45, 55, 52, 102, 49, 48, 55, 98, 98, 52, 55, 98, 53, 52, 57, 57, 54, 45, 48, 49, 0, 0, 4, 8, 0, 0, 0, 7, 35, 0, 0, 0, 5, 0, 0, 5, 0, 1, 0, 0, 7, 35, 0, 0, 0, 0, 0, 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 20, 12},
		inputLen:      10000,
		expected:      true,
		expectedQuick: true,
	},
	{
		name:          "Test no :path, but has :scheme and traceparent",
		input:         []byte{0, 0, 134, 1, 4, 0, 0, 7, 15, 195, 194, 131, 134, 193, 192, 191, 190, 0, 11, 116, 114, 97, 99, 101, 112, 97, 114, 101, 110, 116, 55, 48, 48, 45, 50, 50, 98, 100, 57, 52, 52, 99, 50, 98, 50, 52, 97, 52, 102, 98, 52, 55, 102, 102, 101, 56, 98, 102, 57, 97, 100, 51, 54, 52, 57, 53, 45, 50, 50, 102, 53, 56, 98, 55, 53, 100, 100, 50, 99, 51, 55, 98, 101, 45, 48, 49, 0, 7, 98, 97, 103, 103, 97, 103, 101, 47, 115, 101, 115, 115, 105, 111, 110, 46, 105, 100, 61, 98, 50, 54, 49, 101, 51, 98, 101, 45, 102, 55, 102, 55, 45, 52, 54, 99, 55, 45, 98, 99, 55, 100, 45, 98, 99, 100, 97, 100, 101, 48, 102, 57, 97, 54, 102, 0, 0, 4, 8, 0, 0, 0, 7, 15, 0, 0, 0, 5, 0, 0, 5, 0, 1, 0, 0, 7, 15, 0, 0, 0, 0, 0, 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 20, 12},
		inputLen:      10000,
		expected:      true,
		expectedQuick: true,
	},
	{
		name:          "Status instead of start",
		input:         []byte{0, 0, 29, 1, 4, 0, 0, 1, 101, 136, 224, 223, 222, 221, 97, 150, 223, 105, 126, 148, 19, 106, 101, 182, 165, 4, 1, 52, 160, 92, 184, 23, 174, 1, 197, 49, 104, 223, 0, 0, 44, 0, 0, 0, 0, 1, 101, 1, 0, 0, 0, 39, 31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 18, 98, 11, 14, 113, 12, 241, 116, 150, 98, 206, 79, 75, 83, 98, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		inputLen:      100,
		expectedQuick: true,
		expected:      false,
	},
	{
		name:          "Empty",
		input:         []byte{},
		inputLen:      100,
		expectedQuick: false,
		expected:      false,
	},
	{
		name:          "Short",
		input:         []byte{0, 0, 70, 1, 4},
		inputLen:      3,
		expectedQuick: false,
		expected:      false,
	},
	{
		name:          "Regular HTTP2/gRPC Frame",
		input:         []byte{0, 0, 70, 1, 4, 0, 0, 0, 19, 204, 131, 4, 147, 96, 233, 45, 18, 22, 147, 175, 12, 155, 139, 103, 115, 16, 172, 98, 42, 97, 145, 31, 134, 126, 167, 0, 22, 16, 7, 36, 140, 179, 27, 50, 202, 25, 101, 105, 182, 93, 33, 66, 211, 97, 41, 64, 0, 182, 66, 44, 219, 242, 186, 217, 2, 203, 196, 3, 143, 182, 209, 86, 0, 127, 203, 202, 201, 200, 199, 0, 0, 5, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		inputLen:      10000,
		expectedQuick: true,
		expected:      true,
	},
	{
		name:          "Reset frame before HTTP2/gRPC Frame",
		input:         []byte{0, 0, 4, 3, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 70, 1, 4, 0, 0, 0, 21, 205, 131, 4, 147, 96, 233, 45, 18, 22, 147, 175, 12, 155, 139, 103, 115, 16, 172, 98, 42, 97, 145, 31, 134, 126, 167, 0, 22, 44, 99, 27, 33, 124, 174, 72, 228, 109, 129, 233, 27, 125, 246, 133, 44, 101, 28, 111, 70, 32, 178, 85, 163, 108, 97, 149, 199, 99, 121, 169, 90, 149, 225, 188, 176, 3, 204, 203, 202, 201, 200, 0, 0, 5, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		inputLen:      10000,
		expectedQuick: true,
		expected:      true,
	},
	{
		name:          "Too short of input len, but enough to parse the reset frame",
		input:         []byte{0, 0, 4, 3, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 70, 1, 4, 0, 0, 0, 21, 205, 131, 4, 147, 96, 233, 45, 18, 22, 147, 175, 12, 155, 139, 103, 115, 16, 172, 98, 42, 97, 145, 31, 134, 126, 167, 0, 22, 44, 99, 27, 33, 124, 174, 72, 228, 109, 129, 233, 27, 125, 246, 133, 44, 101, 28, 111, 70, 32, 178, 85, 163, 108, 97, 149, 199, 99, 121, 169, 90, 149, 225, 188, 176, 3, 204, 203, 202, 201, 200, 0, 0, 5, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		inputLen:      frameHeaderLen + 2,
		expectedQuick: false,
		expected:      false,
	},
	{
		name:          "Kafka frame instead of HTTP2",
		input:         []byte{0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 2, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 39, 16, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 72},
		inputLen:      10000,
		expectedQuick: false,
		expected:      false,
	},
	{
		name:          "No headers frame (manually tweaked the type to fail)",
		input:         []byte{0, 0, 4, 3, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 70, 2, 4, 0, 0, 0, 21, 205, 131, 4, 147, 96, 233, 45, 18, 22, 147, 175, 12, 155, 139, 103, 115, 16, 172, 98, 42, 97, 145, 31, 134, 126, 167, 0, 22, 44, 99, 27, 33, 124, 174, 72, 228, 109, 129, 233, 27, 125, 246, 133, 44, 101, 28, 111, 70, 32, 178, 85, 163, 108, 97, 149, 199, 99, 121, 169, 90, 149, 225, 188, 176, 3, 204, 203, 202, 201, 200, 0, 0, 5, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		inputLen:      10000,
		expectedQuick: false,
		expected:      false,
	},
	{
		name:          "Truncated frame, len should be 70 of the second frame",
		input:         []byte{0, 0, 4, 3, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 70, 2, 4, 0, 0, 0, 21, 205, 131},
		inputLen:      10000,
		expectedQuick: false,
		expected:      false,
	},
	{
		name:          "HTTP2/gRPC Header Frame",
		input:         []byte{0x0, 0x0, 0x7f, 0x1, 0x0, 0x0, 0x0, 0x6, 0x11, 0x83, 0x86, 0x10, 0x5, 0x3a, 0x70, 0x61, 0x74, 0x68, 0x10, 0x2f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x10, 0xa, 0x3a, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x11, 0x34, 0x33, 0x2e, 0x31, 0x33, 0x35, 0x2e, 0x38, 0x34, 0x2e, 0x31, 0x33, 0x3a, 0x39, 0x38, 0x34, 0x38, 0x10, 0xc, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x10, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x10, 0xa, 0x75, 0x73, 0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0xe, 0x67, 0x72, 0x70, 0x63, 0x2d, 0x67, 0x6f, 0x2f, 0x31, 0x2e, 0x36, 0x39, 0x2e, 0x32, 0x10, 0x2, 0x74, 0x65, 0x8, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x65, 0x72, 0x73, 0x0, 0x0, 0x32, 0x9, 0x4, 0x0, 0x0, 0x6, 0x11, 0x10, 0x14, 0x67, 0x72, 0x70, 0x63, 0x2d, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x4, 0x67, 0x7a, 0x69, 0x70, 0x10, 0xc, 0x67, 0x72, 0x70, 0x63, 0x2d, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x8, 0x32, 0x39, 0x39, 0x39, 0x39, 0x31, 0x34, 0x75},
		inputLen:      10000,
		expectedQuick: true,
		expected:      true,
	},
	{
		name:          "gRPC proper frame",
		input:         []byte{0, 0, 113, 1, 4, 0, 0, 0, 33, 218, 131, 4, 154, 96, 233, 45, 18, 22, 147, 175, 122, 114, 147, 169, 237, 78, 226, 217, 220, 196, 43, 26, 232, 25, 11, 170, 201, 11, 103, 134, 126, 167, 0, 22, 33, 75, 27, 66, 40, 218, 125, 217, 6, 251, 236, 198, 240, 192, 32, 145, 240, 189, 35, 77, 137, 233, 86, 109, 231, 70, 243, 79, 21, 240, 62, 217, 89, 3, 139, 0, 63, 127, 1, 161, 65, 80, 131, 30, 165, 205, 36, 17, 137, 192, 149, 152, 202, 180, 174, 202, 234, 205, 56, 71, 86, 140, 142, 200, 180, 100, 144, 114, 20, 18, 190, 55, 37, 217, 216, 215, 214, 213, 0, 0, 170, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 165, 10, 36, 98, 50, 54, 49, 101, 51, 98, 101, 45, 102, 55, 102, 55, 45, 52, 54, 99, 55, 45, 98, 99, 55, 100, 45, 98, 99, 100, 97, 100, 101, 48, 102, 57, 97, 54, 102, 18, 3, 66, 82, 76, 26, 68, 10, 25, 49, 54, 48, 48, 32, 65, 109, 112, 104, 105, 116, 104, 101, 97, 116, 114, 101, 32, 80, 97, 114, 107, 119, 97, 121, 18, 13, 77, 111, 117, 110, 116, 97, 105, 110, 32, 86, 105, 101, 119, 26, 2, 67, 65, 34, 13, 85, 110, 105, 116, 101, 100, 32, 83, 116, 97, 116, 101, 115, 42, 5, 57, 52, 48, 52, 51, 42, 19, 115, 111, 109, 101, 111},
		inputLen:      10000,
		expected:      true,
		expectedQuick: true,
	},
	{
		// Random garbage: byte[3]=0x01 (FrameHeaders), byte[5..8] starts
		// 0x17 so the reserved bit is 0 and StreamID is non-zero. Before
		// the 6.5.2 length bound and 4.1 flag-mask checks, this slipped
		// through isLikelyHTTP2 as a "valid" HEADERS frame even though
		// Length=0xA46E71 (~10MB) and Flags=0x6A sets reserved bits.
		name:          "Random garbage misclassified as HEADERS",
		input:         []byte{164, 110, 113, 1, 106, 23, 253, 162, 163, 72, 189, 1, 167, 129, 223, 103, 240, 248, 141, 115, 130, 57, 6, 202, 156, 118, 117, 222, 165, 192, 26, 203, 107, 74, 155, 217, 126, 137, 30, 182, 52, 167, 108, 198, 76, 221, 214, 85, 94, 8, 160, 220, 164, 214, 124, 156, 147, 43, 247, 227, 81, 115, 196, 184},
		inputLen:      64,
		expected:      false,
		expectedQuick: false,
	},
}

func TestHTTP2QuickDetection(t *testing.T) {
	for _, tt := range isHTTP2TestCases {
		t.Run(tt.name, func(t *testing.T) {
			res := isLikelyHTTP2(tt.input, tt.inputLen)
			assert.Equal(t, tt.expectedQuick, res)
			res1 := isHTTP2(largebuf.NewLargeBufferFrom(tt.input), tt.inputLen)
			assert.Equal(t, tt.expected, res1)
		})
	}
}

func TestHTTP2Parsing(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		inputLen    int
		method      string
		path        string
		contentType string
	}{
		{
			name:        "One",
			input:       []byte{0, 0, 88, 1, 4, 0, 0, 6, 237, 208, 131, 4, 164, 96, 233, 45, 18, 22, 147, 175, 180, 164, 61, 52, 150, 169, 6, 147, 30, 173, 197, 179, 37, 2, 0, 0, 0, 0, 0, 0, 187, 70, 76, 66, 163, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 213, 255, 255, 255, 255, 255, 255, 255, 1, 105, 108, 100, 108, 105, 102, 101, 0, 0, 0, 0, 0, 0, 0, 0, 64, 183, 2, 212, 164, 126, 0, 0, 64, 183, 2, 212, 164, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 60, 103, 110, 32, 119, 105, 108, 108, 32, 119, 105, 116, 104, 115, 116, 97, 110, 100, 32, 96, 32, 0, 196, 164, 126, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 112, 32, 0, 196, 164, 126, 0, 0, 137, 42, 109, 81, 165, 126, 0, 0, 97, 115, 104, 108, 105, 103, 104, 116, 46, 106, 112, 103, 42, 12, 10, 3, 85, 83, 68, 16, 57, 24, 128, 232, 146, 38, 50, 11, 97, 99, 99, 101, 115, 115, 111, 114, 105, 101, 115, 50, 11, 102, 108, 97, 115, 104, 108, 105, 103, 104, 116, 115, 10, 165, 5, 10},
			inputLen:    32,
			method:      "POST",
			path:        "",
			contentType: "",
		},
		{
			name:        "Two",
			input:       []byte{0, 0, 77, 1, 4, 0, 0, 0, 37, 195, 194, 131, 134, 193, 192, 191, 190, 0, 11, 116, 114, 97, 99, 0, 0, 0, 0, 0, 0, 0, 0, 8, 101, 112, 97, 114, 101, 110, 116, 55, 0, 8, 6, 0, 0, 0, 0, 0, 36, 42, 35, 123, 242, 89, 199, 0, 7, 1, 240, 184, 117, 0, 0, 55, 0, 0, 0, 0, 0, 0, 0, 16, 7, 1, 240, 184, 117, 0, 0, 137, 218, 220, 116, 185, 117, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 0, 4, 8, 0, 0, 0, 0, 37, 0, 0, 0, 5, 0, 0, 5, 0, 1, 0, 0, 0, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 20, 12, 0, 240, 184, 117, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 210, 202, 123, 115, 185, 117, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 31, 0, 240, 184, 117, 0, 0, 174, 233, 21, 115, 185, 117, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 96, 65, 0, 240, 184, 117, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 112, 65, 0, 240, 184, 117, 0, 0, 208, 201, 127, 3, 185, 117, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4},
			inputLen:    126,
			method:      "POST",
			path:        "",
			contentType: "",
		},
		{
			name:        "Three",
			input:       []byte{0x0, 0x0, 0x7f, 0x1, 0x0, 0x0, 0x0, 0x6, 0x11, 0x83, 0x86, 0x10, 0x5, 0x3a, 0x70, 0x61, 0x74, 0x68, 0x10, 0x2f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x10, 0xa, 0x3a, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x11, 0x34, 0x33, 0x2e, 0x31, 0x33, 0x35, 0x2e, 0x38, 0x34, 0x2e, 0x31, 0x33, 0x3a, 0x39, 0x38, 0x34, 0x38, 0x10, 0xc, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x10, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x10, 0xa, 0x75, 0x73, 0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0xe, 0x67, 0x72, 0x70, 0x63, 0x2d, 0x67, 0x6f, 0x2f, 0x31, 0x2e, 0x36, 0x39, 0x2e, 0x32, 0x10, 0x2, 0x74, 0x65, 0x8, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x65, 0x72, 0x73, 0x0, 0x0, 0x32, 0x9, 0x4, 0x0, 0x0, 0x6, 0x11, 0x10, 0x14, 0x67, 0x72, 0x70, 0x63, 0x2d, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x4, 0x67, 0x7a, 0x69, 0x70, 0x10, 0xc, 0x67, 0x72, 0x70, 0x63, 0x2d, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x8, 0x32, 0x39, 0x39, 0x39, 0x39, 0x31, 0x34, 0x75},
			inputLen:    195,
			method:      "POST",
			path:        "/Request/request",
			contentType: "application/grpc",
		},
	}

	parseContext := NewEBPFParseContext(nil, nil, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			framer := byteFramer(tt.input[:tt.inputLen])
			for {
				f, err := framer.ReadFrame()
				if err != nil {
					break
				}

				if ff, ok := f.(*http2.HeadersFrame); ok {
					method, path, contentType, _, _ := readMetaFrame(parseContext, 0, framer, ff)
					assert.Equal(t, tt.method, method)
					assert.Equal(t, tt.path, path)
					assert.Equal(t, tt.contentType, contentType)
				}
			}
		})
	}
}

// HEADERS frame with END_HEADERS carrying the given HPACK block
func headersFrame(t *testing.T, payload []byte) *http2.HeadersFrame {
	t.Helper()

	frame := append([]byte{0, 0, byte(len(payload)), 1, 4, 0, 0, 0, 5}, payload...)
	f, err := byteFramer(frame).ReadFrame()
	require.NoError(t, err)
	hf, ok := f.(*http2.HeadersFrame)
	require.True(t, ok)

	return hf
}

// literal with incremental indexing, name referenced from the static table
func indexedNameField(nameIdx byte, value string) []byte {
	return append([]byte{0x40 | nameIdx, byte(len(value))}, value...)
}

func TestHTTP2ResponseDetection(t *testing.T) {
	// :status 200 (indexed, 0x88) + content-type: application/grpc
	payload := append([]byte{0x88, 0x10, 0xc}, []byte("content-type")...)
	payload = append(payload, 0x10)
	payload = append(payload, []byte("application/grpc")...)

	parseContext := NewEBPFParseContext(nil, nil, nil)
	framer := byteFramer(nil)

	_, _, _, _, isResponse := readMetaFrame(parseContext, 1, framer, headersFrame(t, payload))
	assert.True(t, isResponse, "HEADERS opening with :status must be flagged as a response")
}

// A response block decoded with the request decoder inserts into the wrong dynamic table, and
// every index the peer sends afterwards resolves one entry off.
//
// Only 200, 204, 206, 304, 400, 404 and 500 have a static entry of their own. Every other code
// is a literal with the name referenced from the static table, and all of entries 8-14 name
// :status, so the opener check has to accept every one of them.
func TestHTTP2ResponseDoesNotPolluteRequestTable(t *testing.T) {
	// literal with incremental indexing, :status name referenced from nameIdx
	status418 := func(nameIdx byte) []byte {
		return indexedNameField(nameIdx, "418")
	}

	for _, tc := range []struct {
		name   string
		opener []byte
	}{
		{":status 200, fully indexed", []byte{0x88}},
		{":status 418, name ref 8", status418(8)},
		{":status 418, name ref 11", status418(11)},
		{":status 418, name ref 14", status418(14)},
		{":status 418, without indexing", append([]byte{0x0e, 3}, "418"...)},
		{":status 418, never indexed", append([]byte{0x1e, 3}, "418"...)},
		{"size update, then :status 418", append([]byte{0x20}, status418(8)...)},
		{"two size updates, then :status 418", append([]byte{0x20, 0x20}, status418(8)...)},
		{"multi-byte size update, then :status 418", append([]byte{0x3f, 0xe1, 0x1f}, status418(8)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const (
				pathStaticIdx = 4
				mostRecentIdx = 0xbe // dynamic table entry 62
				secondIdx     = 0xbf // dynamic table entry 63
			)

			parseContext := NewEBPFParseContext(nil, nil, nil)
			framer := byteFramer(nil)

			// peer inserts (:path, /p1)
			first := append([]byte{0x82}, indexedNameField(pathStaticIdx, "/p1")...)
			_, path, _, _, isResponse := readMetaFrame(parseContext, 1, framer, headersFrame(t, first))
			require.False(t, isResponse)
			require.Equal(t, "/p1", path)

			// a response lands on the same connection, inserting (:path, /bad) if it is decoded here
			resp := append(append([]byte{}, tc.opener...), indexedNameField(pathStaticIdx, "/bad")...)
			_, _, _, _, isResponse = readMetaFrame(parseContext, 1, framer, headersFrame(t, resp))
			require.True(t, isResponse)

			// peer inserts (:path, /p2), so its own table holds /p2 at 62 and /p1 at 63
			second := append([]byte{0x82}, indexedNameField(pathStaticIdx, "/p2")...)
			_, path, _, _, _ = readMetaFrame(parseContext, 1, framer, headersFrame(t, second))
			require.Equal(t, "/p2", path)

			_, path, _, _, _ = readMetaFrame(parseContext, 1, framer,
				headersFrame(t, []byte{0x82, mostRecentIdx}))
			assert.Equal(t, "/p2", path, "entry 62 must be the peer's most recent insertion")

			_, path, _, _, _ = readMetaFrame(parseContext, 1, framer,
				headersFrame(t, []byte{0x82, secondIdx}))
			assert.Equal(t, "/p1", path, "entry 63 must be the peer's previous insertion, not the response")
		})
	}
}

// encodeHPACK writes fields with a real encoder, so the representation each field gets is not
// this test's guess. tableSizes are applied first, which makes the encoder emit size updates
// ahead of the block.
func encodeHPACK(t *testing.T, tableSizes []uint32, fields ...hpack.HeaderField) []byte {
	t.Helper()

	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, size := range tableSizes {
		enc.SetMaxDynamicTableSize(size)
	}
	for _, f := range fields {
		require.NoError(t, enc.WriteField(f))
	}

	return buf.Bytes()
}

// Every status code a server can send must be recognized, not only the seven with a static
// entry. x/net names :status through entry 14, so a first non-static code opens with 0x4e.
func TestHPACKOpensResponseAgainstEncoder(t *testing.T) {
	for code := 100; code < 600; code++ {
		status := hpack.HeaderField{Name: ":status", Value: strconv.Itoa(code)}

		for _, tc := range []struct {
			name       string
			tableSizes []uint32
			field      hpack.HeaderField
		}{
			{"plain", nil, status},
			{"sensitive", nil, hpack.HeaderField{Name: status.Name, Value: status.Value, Sensitive: true}},
			{"after a size update", []uint32{4096}, status},
			{"after two size updates", []uint32{0, 4096}, status},
		} {
			block := encodeHPACK(t, tc.tableSizes, tc.field)

			// the encoder deciding to emit no update would leave the skip untested
			require.Equal(t, len(tc.tableSizes) > 0, hpackFieldStart(block) > 0,
				"%s must carry a size update, got % x", tc.name, block)

			assert.True(t, hpackOpensResponse(block),
				":status %d %s must open a response, got % x", code, tc.name, block)
		}
	}
}

// The mirror case: a request block must never be taken for a response, or the guard would stop
// decoding the requests OBI reports.
func TestHPACKOpensResponseRejectsRequests(t *testing.T) {
	paths := []string{"/", "/index.html", "/a", "/relay.Relay/Relay"}
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT"}

	for _, method := range methods {
		for _, path := range paths {
			for _, sizes := range [][]uint32{nil, {4096}, {0, 4096}} {
				block := encodeHPACK(t, sizes,
					hpack.HeaderField{Name: ":method", Value: method},
					hpack.HeaderField{Name: ":path", Value: path},
					hpack.HeaderField{Name: ":scheme", Value: "https"},
					hpack.HeaderField{Name: ":authority", Value: "host:8080"},
					hpack.HeaderField{Name: "content-type", Value: "application/grpc"},
				)
				assert.False(t, hpackOpensResponse(block),
					"%s %s must not open a response, got % x", method, path, block)
			}
		}
	}

	// a gRPC trailer block opens with a new name, neither a request nor a response
	trailers := encodeHPACK(t, nil, hpack.HeaderField{Name: "grpc-status", Value: "0"})
	assert.False(t, hpackOpensResponse(trailers), "trailers must not open a response")
}

// hpackReference decodes the first byte of a representation per RFC 7541 6.1-6.3 and reports
// the static index the field names, plus whether the byte is a field at all. Written from the
// RFC rather than from the code under test, so the two can disagree.
func hpackReference(b byte) (idx int, isField bool) {
	switch {
	case b&0x80 == 0x80: // 6.1 indexed header field, 7-bit index
		return int(b & 0x7f), true
	case b&0xc0 == 0x40: // 6.2.1 literal with incremental indexing, 6-bit name index
		return int(b & 0x3f), true
	case b&0xe0 == 0x20: // 6.3 dynamic table size update, carries no field
		return 0, false
	case b&0xf0 == 0x00: // 6.2.2 literal without indexing, 4-bit name index
		return int(b & 0x0f), true
	default: // b&0xf0 == 0x10, 6.2.3 literal never indexed, 4-bit name index
		return int(b & 0x0f), true
	}
}

// Static entries 8-14 all name :status (A. Static Table Definition). A 4-bit prefix cannot hold
// an index of 15 or more, so 0x0f and 0x1f start a varint instead of naming an entry.
func TestHPACKOpensResponseExhaustive(t *testing.T) {
	const (
		statusFirst = 8
		statusLast  = 14
		varintMore  = 15
	)

	for b := 0; b < 256; b++ {
		idx, isField := hpackReference(byte(b))
		fourBit := b&0x80 == 0 && b&0xc0 != 0x40 && b&0xe0 != 0x20

		want := isField && idx >= statusFirst && idx <= statusLast
		if fourBit && idx >= varintMore {
			want = false
		}

		assert.Equal(t, want, hpackOpensResponse([]byte{byte(b)}), "byte 0x%02x", b)
	}
}

// A block cannot open a request and a response at once, so the BPF sniffer's two predicates
// must not overlap. Mirrors h2_hpack_opens_request, which has no Go counterpart to call.
func TestHPACKOpenersAreDisjoint(t *testing.T) {
	opensRequest := func(b byte) bool {
		idx, isField := hpackReference(b)
		if !isField {
			return false
		}
		if b&0x80 != 0 {
			return (idx >= 1 && idx <= 7) || idx >= 62
		}
		return idx >= 1 && idx <= 7
	}

	for b := 0; b < 256; b++ {
		if hpackOpensResponse([]byte{byte(b)}) {
			assert.False(t, opensRequest(byte(b)), "byte 0x%02x opens both", b)
		}
	}
}

// hpackSizeUpdate encodes a dynamic table size update per RFC 7541 5.1 and 6.3.
func hpackSizeUpdate(size uint32) []byte {
	const prefix5 = 0x1f

	if size < prefix5 {
		return []byte{0x20 | byte(size)}
	}

	out := []byte{0x20 | prefix5}
	for size -= prefix5; size >= 0x80; size >>= 7 {
		out = append(out, byte(size&0x7f)|0x80)
	}

	return append(out, byte(size))
}

// The opener sits past any size updates, whatever their encoded width. Callers that misjudge
// the width read a varint octet as the opener and misclassify the block.
func TestHPACKFieldStartSkipsSizeUpdates(t *testing.T) {
	// 5.1 boundaries: prefix-only, prefix exhausted, and each added continuation octet
	sizes := []uint32{0, 30, 31, 32, 158, 159, 4096, 16384, 65536, 1 << 21, 1 << 28, math.MaxUint32}

	for _, size := range sizes {
		for updates := 1; updates <= 3; updates++ {
			t.Run(fmt.Sprintf("size %d, %d updates", size, updates), func(t *testing.T) {
				var frag []byte
				for range updates {
					frag = append(frag, hpackSizeUpdate(size)...)
				}
				want := len(frag)
				frag = append(frag, 0x4e) // :status name ref 14

				assert.Equal(t, want, hpackFieldStart(frag))
				assert.True(t, hpackOpensResponse(frag), "response must survive the updates")
			})
		}
	}

	assert.Len(t, hpackSizeUpdate(math.MaxUint32), 6, "a u32 update is at most six octets")
}

func TestHPACKFieldStartRejectsTruncated(t *testing.T) {
	full := append(hpackSizeUpdate(math.MaxUint32), 0x4e)

	for cut := 1; cut < len(full); cut++ {
		frag := full[:cut]
		assert.Equal(t, -1, hpackFieldStart(frag), "%d octets hold no field", cut)
		assert.False(t, hpackOpensResponse(frag))
	}

	assert.Equal(t, len(full)-1, hpackFieldStart(full))
}

func TestHPACKOpensResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		frag []byte
		want bool
	}{
		{":status 200 indexed", []byte{0x88}, true},
		{":status 504 indexed", []byte{0x8e}, true},
		{"name ref 8, incremental", []byte{0x48}, true},
		{"name ref 14, incremental", []byte{0x4e}, true},
		{"name ref 12, without indexing", []byte{0x0c}, true},
		{"name ref 12, never indexed", []byte{0x1c}, true},
		{"size update then name ref", []byte{0x20, 0x48}, true},
		{":method indexed", []byte{0x83}, false},
		{":path name ref", []byte{0x44}, false},
		{"dyn-table entry", []byte{0xc3}, false},
		{"new name, no index ref", []byte{0x40}, false},
		{"index 15 is a varint continuation", []byte{0x1f}, false},
		// 0x50 is not a literal prefix, so the low bits are not a name index
		{"0x5a is not a literal form", []byte{0x5a}, false},
		{"empty block", nil, false},
		{"only a size update", []byte{0x20}, false},
		{"truncated size update varint", []byte{0x3f, 0xe1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hpackOpensResponse(tc.frag))
		})
	}
}

func TestHTTP2EventsParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		rinput   []byte
		inputLen int
		ignored  bool
	}{
		{
			name:     "Ignored, buffers reversed, nothing in there",
			input:    []byte{0, 0, 6, 1, 4, 0, 0, 0, 11, 136, 196, 195, 194, 193, 190, 150, 223, 105, 126, 148, 19, 106, 101, 182, 165, 4, 1, 52, 160, 94, 184, 39, 46, 52, 242, 152, 180, 111, 255, 18, 98, 11, 14, 113, 12, 241, 116, 150, 98, 206, 79, 75, 83, 98, 0, 4, 0, 0, 255, 255, 211, 196, 47, 145},
			rinput:   []byte{0, 0, 138, 1, 36, 0, 0, 0, 11, 0, 0, 0, 0, 15, 0, 0, 0, 0, 45, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			inputLen: 201,
			ignored:  true,
		},
		{
			name:     "Not reversed",
			rinput:   []byte{0, 0, 6, 1, 4, 0, 0, 0, 11, 136, 196, 195, 194, 193, 190, 150, 223, 105, 126, 148, 19, 106, 101, 182, 165, 4, 1, 52, 160, 94, 184, 39, 46, 52, 242, 152, 180, 111, 255, 18, 98, 11, 14, 113, 12, 241, 116, 150, 98, 206, 79, 75, 83, 98, 0, 4, 0, 0, 255, 255, 211, 196, 47, 145},
			input:    []byte{0, 0, 138, 1, 36, 0, 0, 0, 11, 0, 0, 0, 0, 15, 0, 0, 0, 0, 45, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			inputLen: 201,
			ignored:  false,
		},
		{
			name:     "New with concat",
			input:    []byte{0, 0, 138, 1, 36, 0, 0, 0, 21, 0, 0, 0, 0, 15, 222, 221, 131, 134, 220, 219, 218, 127, 0, 55, 48, 48, 45, 102, 50, 100, 52, 101, 54, 99, 98, 54, 56, 98, 53, 55, 51, 54, 56, 49, 49, 48, 99, 48, 52, 102, 49, 48, 100, 51, 101, 53, 54, 53, 56, 45, 56, 57, 57, 57, 51, 97, 48, 57, 50, 54, 51, 99, 100, 98, 49, 48, 45, 48, 49, 126, 55, 48, 48, 45, 102, 50, 100, 52, 101, 54, 99, 98, 54, 56, 98, 53, 55, 51, 54, 56, 49, 49, 48, 99, 48, 52, 102, 49, 48, 100, 51, 101, 53, 54, 53, 56, 45, 102, 49, 52, 49, 99, 49, 98, 51, 102, 57, 55, 53, 97, 49, 48, 53, 45, 48, 49, 217, 127, 1, 7, 52, 57, 57, 54, 49, 51, 117, 0, 0, 45, 0, 1, 0, 0, 0, 21, 0, 0, 0, 0, 40, 10, 16, 97, 100, 83, 101, 114, 118, 105, 99, 101, 72, 105, 103, 104, 67, 112, 117, 18, 20, 10, 18, 10, 12, 116, 97, 114, 103, 101, 116, 105, 110, 103, 75, 101, 121, 18, 2, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			rinput:   []byte{0, 0, 29, 1, 4, 0, 0, 0, 21, 136, 197, 196, 195, 194, 97, 150, 228, 89, 62, 148, 19, 138, 101, 182, 165, 4, 1, 52, 160, 65, 113, 176, 220, 105, 213, 49, 104, 223, 255, 18, 226, 15, 113, 12, 114, 119, 13, 241, 244, 115, 143, 247, 117, 12, 113, 246, 144, 98, 206, 79, 75, 83, 98, 0},
			inputLen: 201,
			ignored:  false,
		},
	}
	parseContext := NewEBPFParseContext(nil, nil, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := makeBPFHTTP2Info(tt.input, tt.rinput, tt.inputLen)
			_, ignore, _ := http2FromBuffers(parseContext, &info)
			assert.Equal(t, tt.ignored, ignore)
		})
	}
}

func TestHTTP2EventsErrorParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		rinput   []byte
		inputLen int
		status   int
	}{
		{
			name:     "Error response with bad index",
			input:    []byte{0, 0, 8, 1, 4, 0, 0, 0, 7, 195, 194, 131, 134, 193, 192, 191, 190, 0, 0, 4, 8, 0, 0, 0, 0, 7, 0, 0, 0, 5, 0, 0, 5, 0, 1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 84},
			rinput:   []byte{0, 0, 55, 1, 5, 0, 0, 0, 3, 136, 192, 64, 11, 103, 114, 112, 99, 45, 115, 116, 97, 116, 117, 115, 1, 51, 0, 12, 103, 114, 112, 99, 45, 109, 101, 115, 115, 97, 103, 101, 23, 76, 97, 116, 105, 116, 117, 100, 101, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 122, 101, 114, 111},
			inputLen: 201,
			status:   3,
		},
		{
			name:     "Error response with bad index on grpc-status",
			input:    []byte{0, 0, 8, 1, 4, 0, 0, 0, 7, 195, 194, 131, 134, 193, 192, 191, 190, 0, 0, 4, 8, 0, 0, 0, 0, 7, 0, 0, 0, 5, 0, 0, 5, 0, 1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 84},
			rinput:   []byte{0, 0, 41, 1, 5, 0, 0, 0, 7, 136, 193, 190, 0, 12, 103, 114, 112, 99, 45, 109, 101, 115, 115, 97, 103, 101, 23, 76, 97, 116, 105, 116, 117, 100, 101, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 122, 101, 114, 111, 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 5, 97},
			inputLen: 201,
			status:   2,
		},
	}

	parseContext := NewEBPFParseContext(nil, nil, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := makeBPFHTTP2Info(tt.input, tt.rinput, tt.inputLen)
			span, _, _ := http2FromBuffers(parseContext, &info)
			assert.Equal(t, tt.status, span.Status)
		})
	}
}

func TestDynamicTableUpdates(t *testing.T) {
	rinput := []byte{0, 0, 138, 1, 36, 0, 0, 0, 11, 0, 0, 0, 0, 15, 0, 0, 0, 0, 45, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	tests := []struct {
		name     string
		input    []byte
		inputLen int
	}{
		{
			name:     "Full path, lots of headers, but cut off",
			input:    []byte{0, 0, 222, 1, 4, 0, 0, 0, 1, 64, 5, 58, 112, 97, 116, 104, 33, 47, 114, 111, 117, 116, 101, 103, 117, 105, 100, 101, 46, 82, 111, 117, 116, 101, 71, 117, 105, 100, 101, 47, 71, 101, 116, 70, 101, 97, 116, 117, 114, 101, 64, 10, 58, 97, 117, 116, 104, 111, 114, 105, 116, 121, 15, 108, 111, 99, 97, 108, 104, 111, 115, 116, 58, 53, 48, 48, 53, 49, 131, 134, 64, 12, 99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 16, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 103, 114, 112, 99, 64, 2, 116, 101, 8, 116, 114, 97, 105, 108, 101, 114, 115, 64, 20, 103, 114, 112, 99, 45, 97, 99, 99, 101, 112, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103},
			inputLen: 146,
		},
		{
			name:     "Full path, lots of headers",
			input:    []byte{0, 0, 222, 1, 4, 0, 0, 0, 1, 64, 5, 58, 112, 97, 116, 104, 33, 47, 114, 111, 117, 116, 101, 103, 117, 105, 100, 101, 46, 82, 111, 117, 116, 101, 71, 117, 105, 100, 101, 47, 71, 101, 116, 70, 101, 97, 116, 117, 114, 101, 64, 10, 58, 97, 117, 116, 104, 111, 114, 105, 116, 121, 15, 108, 111, 99, 97, 108, 104, 111, 115, 116, 58, 53, 48, 48, 53, 49, 131, 134, 64, 12, 99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 16, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 103, 114, 112, 99, 64, 2, 116, 101, 8, 116, 114, 97, 105, 108, 101, 114, 115, 64, 20, 103, 114, 112, 99, 45, 97, 99, 99, 101, 112, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 23, 105, 100, 101, 110, 116, 105, 116, 121, 44, 32, 100, 101, 102, 108, 97, 116, 101, 44, 32, 103, 122, 105, 112, 64, 10, 117, 115, 101, 114, 45, 97, 103, 101, 110, 116, 48, 103, 114, 112, 99, 45, 112, 121, 116, 104, 111, 110, 47, 49, 46, 54, 57, 46, 48, 32, 103, 114, 112, 99, 45, 99, 47, 52, 52, 46, 50, 46, 48, 32, 40, 108, 105, 110, 117, 120, 59, 32, 99, 104, 116, 116, 112, 50, 41, 0, 0, 4, 8, 0, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 22, 0, 1, 0, 0, 0, 1, 0, 0, 0},
			inputLen: 1024,
		},
		{
			name:     "Full path only",
			input:    []byte{0, 0, 222, 1, 4, 0, 0, 0, 1, 64, 5, 58, 112, 97, 116, 104, 33, 47, 114, 111, 117, 116, 101, 103, 117, 105, 100, 101, 46, 82, 111, 117, 116, 101, 71, 117, 105, 100, 101, 47, 71, 101, 116, 70, 101, 97, 116, 117, 114, 101, 131},
			inputLen: 1024,
		},
		{
			name:     "Index encoded",
			input:    []byte{0, 0, 8, 1, 4, 0, 0, 0, 3, 195, 194, 131, 134, 193, 192, 191, 190, 0, 0, 4, 8, 0, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 5, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 84},
			inputLen: 1024,
		},
	}

	parseContext := NewEBPFParseContext(nil, nil, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := makeBPFHTTP2InfoNewRequest(tt.input, rinput, tt.inputLen)
			s, ignore, _ := http2FromBuffers(parseContext, &info)
			assert.False(t, ignore)
			assert.Equal(t, "POST", s.Method)
			assert.Equal(t, "/routeguide.RouteGuide/GetFeature", s.Path)
		})
	}

	// Now let's break the decoder with pushing unknown indices
	unknownIndexInput := []byte{0, 0, 8, 1, 4, 0, 0, 0, 3, 199, 200, 131, 134, 201, 202, 203, 204, 0, 0, 4, 8, 0, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 5, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 84}

	info := makeBPFHTTP2InfoNewRequest(unknownIndexInput, rinput, 1024)
	s, ignore, _ := http2FromBuffers(parseContext, &info)
	assert.False(t, ignore)
	assert.Equal(t, "POST", s.Method)
	assert.Equal(t, "/routeguide.RouteGuide/GetFeature", s.Path)

	nextIndex := 8 + 61 // 61 is the static table index size, 7 is how many entries we store in the dynamic table with that first request

	// Now let's send new path
	newPathInput := []byte{0, 0, 222, 1, 4, 0, 0, 0, 1, 64, 5, 58, 112, 97, 116, 104, 33, 47, 112, 111, 117, 116, 101, 103, 117, 105, 100, 101, 46, 82, 111, 117, 116, 101, 71, 117, 105, 100, 101, 47, 71, 101, 116, 70, 101, 97, 116, 117, 114, 101, 64, 10, 58, 97, 117, 116, 104, 111, 114, 105, 116, 121, 15, 108, 111, 99, 97, 108, 104, 111, 115, 116, 58, 53, 48, 48, 53, 49, 131, 134, 64, 12, 99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 16, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 103, 114, 112, 99, 64, 2, 116, 101, 8, 116, 114, 97, 105, 108, 101, 114, 115, 64, 20, 103, 114, 112, 99, 45, 97, 99, 99, 101, 112, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 23, 105, 100, 101, 110, 116, 105, 116, 121, 44, 32, 100, 101, 102, 108, 97, 116, 101, 44, 32, 103, 122, 105, 112, 64, 10, 117, 115, 101, 114, 45, 97, 103, 101, 110, 116, 48, 103, 114, 112, 99, 45, 112, 121, 116, 104, 111, 110, 47, 49, 46, 54, 57, 46, 48, 32, 103, 114, 112, 99, 45, 99, 47, 52, 52, 46, 50, 46, 48, 32, 40, 108, 105, 110, 117, 120, 59, 32, 99, 104, 116, 116, 112, 50, 41, 0, 0, 4, 8, 0, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 22, 0, 1, 0, 0, 0, 1, 0, 0, 0}

	// We'll be able to decode this correctly, even with broken decoder, beause the values are sent as text
	info = makeBPFHTTP2InfoNewRequest(newPathInput, rinput, 1024)
	s, ignore, _ = http2FromBuffers(parseContext, &info)
	assert.False(t, ignore)
	assert.Equal(t, "POST", s.Method)
	assert.Equal(t, "/pouteguide.RouteGuide/GetFeature", s.Path) // this value is the same I just changed the first character from r to p

	// indexed version of newPathInput
	// if we cached a new pair nextIndex + 128 is the high bit encoded next index which should be in the dynamic table
	// however we mark the decoder as invalid and it shouldn't resolve to anything for :path
	indexedNewPath := []byte{0, 0, 8, 1, 4, 0, 0, 0, 3, 195, 194, 131, 134, 193, 192, 191, byte(nextIndex + 128), 0, 0, 4, 8, 0, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 5, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 84}

	info = makeBPFHTTP2InfoNewRequest(indexedNewPath, rinput, 1024)
	s, ignore, _ = http2FromBuffers(parseContext, &info)
	assert.False(t, ignore)
	assert.Equal(t, "POST", s.Method)
	assert.Equal(t, "*", s.Path) // this value is the same I just changed the first character from r to p
}

func makeBPFHTTP2Info(buf, rbuf []byte, length int) BPFHTTP2Info {
	var info BPFHTTP2Info
	copy(info.Data[:], buf)
	copy(info.RetData[:], rbuf)
	info.Len = int32(length)

	return info
}

func makeBPFHTTP2InfoNewRequest(buf, rbuf []byte, length int) BPFHTTP2Info {
	info := makeBPFHTTP2Info(buf, rbuf, length)
	info.ConnInfo.D_port = 1
	info.ConnInfo.S_port = 1
	info.NewConnId = 1

	return info
}

func TestHandleHeaderField(t *testing.T) {
	tests := []struct {
		name     string
		hf       *bhpack.HeaderField
		expected bool
	}{
		// Valid :method values
		{
			name:     "Valid method GET",
			hf:       &bhpack.HeaderField{Name: ":method", Value: "GET"},
			expected: true,
		},
		{
			name:     "Valid method POST",
			hf:       &bhpack.HeaderField{Name: ":method", Value: "GET"},
			expected: true,
		},
		{
			name:     "Valid method PATCH",
			hf:       &bhpack.HeaderField{Name: ":method", Value: "PATCH"},
			expected: true,
		},
		{
			name:     "Valid method DELETE",
			hf:       &bhpack.HeaderField{Name: ":method", Value: "DELETE"},
			expected: true,
		},
		{
			name:     "Valid method OPTIONS",
			hf:       &bhpack.HeaderField{Name: ":method", Value: "OPTIONS"},
			expected: true,
		},
		{
			name:     "Valid method HEAD",
			hf:       &bhpack.HeaderField{Name: ":method", Value: "HEAD"},
			expected: true,
		},
		{
			name:     "Invalid method PUT",
			hf:       &bhpack.HeaderField{Name: ":method", Value: "PUT"},
			expected: false,
		},
		{
			name:     "Invalid method TRACE",
			hf:       &bhpack.HeaderField{Name: ":method", Value: "TRACE"},
			expected: false,
		},
		{
			name:     "Invalid method CONNECT",
			hf:       &bhpack.HeaderField{Name: ":method", Value: "CONNECT"},
			expected: false,
		},
		{
			name:     "Invalid method arbitrary",
			hf:       &bhpack.HeaderField{Name: ":method", Value: "CUSTOM"},
			expected: false,
		},

		// Valid :path values
		{
			name:     "Valid path simple",
			hf:       &bhpack.HeaderField{Name: ":path", Value: "/api/users"},
			expected: true,
		},
		{
			name:     "Valid path with numbers",
			hf:       &bhpack.HeaderField{Name: ":path", Value: "/api/users/123"},
			expected: true,
		},
		{
			name:     "Valid path with hyphens",
			hf:       &bhpack.HeaderField{Name: ":path", Value: "/api/user-service"},
			expected: true,
		},
		{
			name:     "Valid path with dots",
			hf:       &bhpack.HeaderField{Name: ":path", Value: "/api/v1.0/users"},
			expected: true,
		},
		{
			name:     "Valid path with dots and params separator",
			hf:       &bhpack.HeaderField{Name: ":path", Value: "/api/v1.0/users?hello=world&test=2"},
			expected: true,
		},
		{
			name:     "Valid path with underscores",
			hf:       &bhpack.HeaderField{Name: ":path", Value: "/api/user_service"},
			expected: true,
		},
		{
			name:     "Valid path with tildes",
			hf:       &bhpack.HeaderField{Name: ":path", Value: "/~username/files"},
			expected: true,
		},
		{
			name:     "Invalid path with query",
			hf:       &bhpack.HeaderField{Name: ":path", Value: "/api/users?id=123"},
			expected: true,
		},
		{
			name:     "Invalid path with special chars",
			hf:       &bhpack.HeaderField{Name: ":path", Value: "/api/users/!@#"},
			expected: false,
		},
		{
			name:     "Invalid path with spaces",
			hf:       &bhpack.HeaderField{Name: ":path", Value: "/api/user service"},
			expected: false,
		},

		// Valid content-type values
		{
			name:     "Valid content-type grpc",
			hf:       &bhpack.HeaderField{Name: "content-type", Value: "application/grpc"},
			expected: true,
		},
		{
			name:     "Valid content-type grpc+proto",
			hf:       &bhpack.HeaderField{Name: "content-type", Value: "application/grpc+proto"},
			expected: true,
		},
		{
			name:     "Valid content-type grpc+json",
			hf:       &bhpack.HeaderField{Name: "content-type", Value: "application/grpc+json"},
			expected: true,
		},
		{
			name:     "Valid content-type json",
			hf:       &bhpack.HeaderField{Name: "content-type", Value: "application/json"},
			expected: true,
		},
		{
			name:     "Valid content-type xml",
			hf:       &bhpack.HeaderField{Name: "content-type", Value: "application/xml"},
			expected: true,
		},
		{
			name:     "Valid content-type with hyphen",
			hf:       &bhpack.HeaderField{Name: "content-type", Value: "application/x-protobuf"},
			expected: true,
		},
		{
			name:     "Invalid content-type with charset",
			hf:       &bhpack.HeaderField{Name: "content-type", Value: "application/json; charset=utf-8"},
			expected: false,
		},
		{
			name:     "Invalid content-type with spaces",
			hf:       &bhpack.HeaderField{Name: "content-type", Value: "application / json"},
			expected: false,
		},
		{
			name:     "Invalid content-type with numbers",
			hf:       &bhpack.HeaderField{Name: "content-type", Value: "application/grpc123"},
			expected: false,
		},

		// Other headers (should return false)
		{
			name:     "Unknown header",
			hf:       &bhpack.HeaderField{Name: "user-agent", Value: "grpc-go/1.69.2"},
			expected: false,
		},
		{
			name:     "Empty header name",
			hf:       &bhpack.HeaderField{Name: "", Value: "value"},
			expected: false,
		},
		{
			name:     "Empty header value",
			hf:       &bhpack.HeaderField{Name: ":method", Value: ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handleHeaderField(tt.hf)
			assert.Equal(t, tt.expected, result, "Expected %v for %s:%s", tt.expected, tt.hf.Name, tt.hf.Value)
		})
	}
}

func BenchmarkIsHTTP2(b *testing.B) {
	for b.Loop() {
		for _, tt := range isHTTP2TestCases {
			_ = isHTTP2(largebuf.NewLargeBufferFrom(tt.input), tt.inputLen)
		}
	}
}

// A desynced HPACK dynamic table can hand :path another field's value; anything
// that is not an absolute path must degrade to "*", never become a metric label
func TestValidPathRequiresAbsolutePath(t *testing.T) {
	valid := []string{
		"/ipservice.IPService/GetIpV4Info",
		"/relay.Relay/Relay",
		"/",
	}
	for _, p := range valid {
		assert.True(t, validPath.MatchString(p), p)
	}

	invalid := []string{
		"00-001f6ca4dd49f899e999ea3a7c0f1dab-9e5179d7828a4f85-02",
		"application/grpc",
		"*",
		"",
		"grpc-timeout",
	}
	for _, p := range invalid {
		assert.False(t, validPath.MatchString(p), p)
	}
}

func makeHeadersFrame(t *testing.T, block []byte) []byte {
	t.Helper()
	require.Less(t, len(block), 1<<24)
	frame := []byte{
		byte(len(block) >> 16), byte(len(block) >> 8), byte(len(block)),
		0x1, // HEADERS
		0x4, // END_HEADERS
		0, 0, 0, 0x1,
	}

	return append(frame, block...)
}

// requestFields mirrors what a Java gRPC client sends: unique traceparent and
// timeout per request keep those literal on the wire, the rest gets indexed.
func requestFields(path, traceparent string) []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: path},
		{Name: ":authority", Value: "ipservice.ipservice.svc.cluster.local:9090"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "user-agent", Value: "grpc-java-netty/1.60.1 (linux/amd64; openjdk 17.0.9)"},
		{Name: "te", Value: "trailers"},
		{Name: "grpc-accept-encoding", Value: "gzip"},
		{Name: "traceparent", Value: traceparent},
		{Name: "grpc-timeout", Value: "98136u"},
	}
}

type h2ConnEncoder struct {
	buf bytes.Buffer
	enc *hpack.Encoder
}

func (c *h2ConnEncoder) frame(t *testing.T, fields []hpack.HeaderField) []byte {
	t.Helper()
	c.buf.Reset()
	for _, f := range fields {
		require.NoError(t, c.enc.WriteField(f))
	}
	return makeHeadersFrame(t, c.buf.Bytes())
}

func h2Event(frame []byte, connID uint64, seq uint32) BPFHTTP2Info {
	info := makeBPFHTTP2InfoNewRequest(frame, nil, len(frame))
	info.NewConnId = connID
	info.Seq = seq
	return info
}

const (
	pathA = "/ipservice.IPService/GetIpV4Info"
	pathB = "/ipservice.IPService/GetIpV6Info"
)

// Contiguous events keep the dynamic table in sync: repeated methods resolve
// even when nothing readable is left on the wire.
func TestSequentialRequestsKeepResolvingMethods(t *testing.T) {
	parseContext := NewEBPFParseContext(nil, nil, nil)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)

	span, ignore, _ := http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathA, "00-001f6ca4dd49f899e999ea3a7c0f1dab-9e5179d7828a4f85-01")), 810, 1)))
	require.False(t, ignore)
	require.Equal(t, pathA, span.Path)

	span, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathB, "00-06f46c3e09e28ec908c07d784c0bd10c-de2edfcb452449bf-01")), 810, 2)))
	require.False(t, ignore)
	require.Equal(t, pathB, span.Path)

	// repeat of pathB: :path now rides as a pure dynamic-table index
	span, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathB, "00-07354bea1effc570ca25d2c68ce56409-6f3a3d0efb2b703b-01")), 810, 3)))
	require.False(t, ignore)
	require.Equal(t, pathB, span.Path)
}

// A lost request event carried a header block the decoders never saw: later
// indexed lookups may name the wrong method. The sequence gap must degrade the
// connection to "*", never to another request's method (discussion #2916).
func TestLostHeadersEventPoisonsConnection(t *testing.T) {
	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(8))
	emitted := spans.Subscribe()
	parseContext := NewEBPFParseContext(nil, spans, nil)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)

	span, ignore, _ := http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathA, "00-001f6ca4dd49f899e999ea3a7c0f1dab-9e5179d7828a4f85-01")), 916, 1)))
	require.False(t, ignore)
	require.Equal(t, pathA, span.Path)

	// this event is dropped before user space sees it
	_ = enc.frame(t, requestFields(pathB, "00-06f46c3e09e28ec908c07d784c0bd10c-de2edfcb452449bf-01"))

	// successors of the missing ordinal are held back while the gap could
	// still be an inversion in flight
	for seq := uint32(3); seq <= 3+seqReorderWindow-1; seq++ {
		_, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathB, "00-07354bea1effc570ca25d2c68ce56409-6f3a3d0efb2b703b-01")), 916, seq)))
		require.True(t, ignore, "seq %d must be held while the gap is within the window", seq)
	}

	// the gap outlives the window: everything drains degraded instead of
	// resolving stale indexes
	_, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathB, "00-0a0a4bea1effc570ca25d2c68ce56409-6f3a3d0efb2b703c-01")), 916, 3+seqReorderWindow)))
	require.True(t, ignore)

	select {
	case replayed := <-emitted:
		require.NotEmpty(t, replayed)
		for _, replay := range replayed {
			require.NotEqual(t, pathA, replay.Path, "a desynced lookup must never resolve another request's method")
			require.Equal(t, "*", replay.Path)
		}
	default:
		t.Fatal("the held events were never replayed")
	}
}

// Multiplexed streams can complete in a different order than their header
// blocks were captured: decoding must follow capture order, or the second
// block resolves against a table missing the first block's insertions.
func TestInvertedCompletionKeepsCaptureOrder(t *testing.T) {
	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	emitted := spans.Subscribe()
	parseContext := NewEBPFParseContext(nil, spans, nil)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)

	// a baseline request establishes the connection ordinal
	span, ignore, _ := http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathA, "00-001f6ca4dd49f899e999ea3a7c0f1dab-9e5179d7828a4f85-01")), 919, 1)))
	require.False(t, ignore)
	require.Equal(t, pathA, span.Path)

	// capture order: B then C, each inserting new table entries
	frameB := enc.frame(t, requestFields(pathB, "00-06f46c3e09e28ec908c07d784c0bd10c-de2edfcb452449bf-01"))
	frameC := enc.frame(t, requestFields(pathA, "00-07354bea1effc570ca25d2c68ce56409-6f3a3d0efb2b703b-01"))

	// C completes first: held until B arrives
	_, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(frameC, 919, 3)))
	require.True(t, ignore)

	span, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(frameB, 919, 2)))
	require.False(t, ignore)
	require.Equal(t, pathB, span.Path)

	select {
	case replayed := <-emitted:
		require.Len(t, replayed, 1)
		require.Equal(t, pathA, replayed[0].Path,
			"the held block must decode against the table that includes its predecessor")
	default:
		t.Fatal("the held event was never replayed")
	}
}

// Two requests ending concurrently can take their ordinals in one order and
// their ring buffer slots in the other: a single swapped pair must not poison
// the connection.
func TestReorderedEventsDoNotPoison(t *testing.T) {
	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	emitted := spans.Subscribe()
	parseContext := NewEBPFParseContext(nil, spans, nil)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)

	span, ignore, _ := http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathA, "00-001f6ca4dd49f899e999ea3a7c0f1dab-9e5179d7828a4f85-01")), 917, 1)))
	require.False(t, ignore)
	require.Equal(t, pathA, span.Path)

	// two requests whose events arrive swapped; the second inserts new table
	// entries, so decoding it out of order would corrupt the dynamic table
	second := enc.frame(t, requestFields(pathB, "00-06f46c3e09e28ec908c07d784c0bd10c-de2edfcb452449bf-01"))
	third := enc.frame(t, requestFields(pathB, "00-07354bea1effc570ca25d2c68ce56409-6f3a3d0efb2b703b-01"))

	// the successor is held back until its predecessor arrives
	span, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(third, 917, 3)))
	require.True(t, ignore)

	// the predecessor decodes first, then the held event replays in order
	span, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(second, 917, 2)))
	require.False(t, ignore)
	require.Equal(t, pathB, span.Path)

	select {
	case replayed := <-emitted:
		require.Len(t, replayed, 1)
		require.Equal(t, pathB, replayed[0].Path, "a healed reorder must decode the held event correctly")
	default:
		t.Fatal("the held event was never replayed")
	}

	span, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathA, "00-0a0a4bea1effc570ca25d2c68ce56409-6f3a3d0efb2b703c-01")), 917, 4)))
	require.False(t, ignore)
	require.Equal(t, pathA, span.Path, "a healed reorder must not degrade later requests")
}

// A header block larger than the eBPF capture window arrives truncated with its
// true length restored in the frame header: the decoder resumes the cut field on
// the next event, so the connection keeps resolving methods.
func TestOversizedHeadersBlockStillResolves(t *testing.T) {
	parseContext := NewEBPFParseContext(nil, nil, nil)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)

	fields := requestFields(pathA, "00-001f6ca4dd49f899e999ea3a7c0f1dab-9e5179d7828a4f85-01")
	fields = append(fields, hpack.HeaderField{Name: "x-envoy-peer-metadata", Value: strings.Repeat("m", 1200)})
	oversized := enc.frame(t, fields)
	require.Greater(t, len(oversized), len(BPFHTTP2Info{}.Data))

	span, ignore, _ := http2FromBuffers(parseContext, ptr(h2Event(oversized, 1024, 1)))
	require.False(t, ignore)
	require.Equal(t, pathA, span.Path, ":path precedes the cut and still resolves")
}

func ptr[T any](v T) *T { return &v }

// The BPF side signals exhausted ordinal allocation with a sentinel: the event
// must poison the decoders instead of bypassing gap detection.
func TestUnreliableSeqSentinelPoisonsConnection(t *testing.T) {
	parseContext := NewEBPFParseContext(nil, nil, nil)
	enc := &h2ConnEncoder{}
	enc.enc = hpack.NewEncoder(&enc.buf)

	span, ignore, _ := http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathA, "00-001f6ca4dd49f899e999ea3a7c0f1dab-9e5179d7828a4f85-01")), 918, 1)))
	require.False(t, ignore)
	require.Equal(t, pathA, span.Path)

	_, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathB, "00-06f46c3e09e28ec908c07d784c0bd10c-de2edfcb452449bf-01")), 918, h2SeqUnreliable)))
	require.False(t, ignore)

	// index-only repeat: with the table poisoned it must degrade, not resolve
	span, ignore, _ = http2FromBuffers(parseContext, ptr(h2Event(enc.frame(t, requestFields(pathA, "00-001f6ca4dd49f899e999ea3a7c0f1dab-9e5179d7828a4f85-01")), 918, 2)))
	require.False(t, ignore)
	require.Equal(t, "*", span.Path, "a sentinel event must not leave dynamic-table state trusted")
}
