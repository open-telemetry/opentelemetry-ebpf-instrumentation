// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/bhpack"
)

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
}

func TestHTTP2QuickDetection(t *testing.T) {
	for _, tt := range isHTTP2TestCases {
		t.Run(tt.name, func(t *testing.T) {
			res := isLikelyHTTP2(tt.input, tt.inputLen)
			assert.Equal(t, tt.expectedQuick, res)
			res1 := isHTTP2(tt.input, tt.inputLen)
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
					method, path, contentType, _ := readMetaFrame(parseContext, 0, framer, ff)
					assert.Equal(t, tt.method, method)
					assert.Equal(t, tt.path, path)
					assert.Equal(t, tt.contentType, contentType)
				}
			}
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
	for i := 0; i < b.N; i++ {
		for _, tt := range isHTTP2TestCases {
			_ = isHTTP2(tt.input, tt.inputLen)
		}
	}
}
