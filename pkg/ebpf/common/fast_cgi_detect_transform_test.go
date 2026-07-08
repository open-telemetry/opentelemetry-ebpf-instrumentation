// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestMaybeFastCGI(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		inputLen int
		expected bool
	}{
		{
			name:     "Correct values",
			input:    []byte{1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 1, 217, 7, 0, 12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			inputLen: 100,
			expected: true,
		},
		{
			name:     "Empty",
			input:    []byte{},
			inputLen: 100,
			expected: false,
		},
		{
			name:     "Short",
			input:    []byte{1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 1, 217, 7, 0, 12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			inputLen: 23,
			expected: false,
		},
		{
			name:     "REQUEST METHOD not in the text",
			input:    []byte{1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 1, 217, 7, 0, 12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 81, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			inputLen: 100,
			expected: false,
		},
		// The next group exercises the cheap header prefilter (version byte
		// must be 1, record-type byte must be in 1..11). The buffers all
		// contain the literal "REQUEST_METHOD" so the prefilter is the
		// only thing that can reject them.
		{
			name:     "version byte zero",
			input:    []byte{0, 1, 0, 0, 0, 8, 0, 0, 0, 'R', 'E', 'Q', 'U', 'E', 'S', 'T', '_', 'M', 'E', 'T', 'H', 'O', 'D'},
			inputLen: 100,
			expected: false,
		},
		{
			name:     "version byte 2 (unsupported)",
			input:    []byte{2, 1, 0, 0, 0, 8, 0, 0, 0, 'R', 'E', 'Q', 'U', 'E', 'S', 'T', '_', 'M', 'E', 'T', 'H', 'O', 'D'},
			inputLen: 100,
			expected: false,
		},
		{
			name:     "version byte 255",
			input:    []byte{255, 1, 0, 0, 0, 8, 0, 0, 0, 'R', 'E', 'Q', 'U', 'E', 'S', 'T', '_', 'M', 'E', 'T', 'H', 'O', 'D'},
			inputLen: 100,
			expected: false,
		},
		{
			name:     "type byte zero (below valid range)",
			input:    []byte{1, 0, 0, 0, 0, 8, 0, 0, 0, 'R', 'E', 'Q', 'U', 'E', 'S', 'T', '_', 'M', 'E', 'T', 'H', 'O', 'D'},
			inputLen: 100,
			expected: false,
		},
		{
			name:     "type byte 12 (just above valid range)",
			input:    []byte{1, 12, 0, 0, 0, 8, 0, 0, 0, 'R', 'E', 'Q', 'U', 'E', 'S', 'T', '_', 'M', 'E', 'T', 'H', 'O', 'D'},
			inputLen: 100,
			expected: false,
		},
		{
			name:     "type byte 255 (well above valid range)",
			input:    []byte{1, 255, 0, 0, 0, 8, 0, 0, 0, 'R', 'E', 'Q', 'U', 'E', 'S', 'T', '_', 'M', 'E', 'T', 'H', 'O', 'D'},
			inputLen: 100,
			expected: false,
		},
		{
			name:     "type byte 1 (BEGIN_REQUEST, lower boundary) accepted",
			input:    []byte{1, 1, 0, 0, 0, 8, 0, 0, 0, 'R', 'E', 'Q', 'U', 'E', 'S', 'T', '_', 'M', 'E', 'T', 'H', 'O', 'D'},
			inputLen: 100,
			expected: true,
		},
		{
			name:     "type byte 11 (UNKNOWN_TYPE, upper boundary) accepted",
			input:    []byte{1, 11, 0, 0, 0, 8, 0, 0, 0, 'R', 'E', 'Q', 'U', 'E', 'S', 'T', '_', 'M', 'E', 'T', 'H', 'O', 'D'},
			inputLen: 100,
			expected: true,
		},
		{
			// Without the header prefilter this random-bytes buffer would be a
			// false positive: it happens to contain "REQUEST_METHOD" but is
			// clearly not FastCGI traffic.
			name:     "random bytes containing REQUEST_METHOD literal are rejected",
			input:    []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 'R', 'E', 'Q', 'U', 'E', 'S', 'T', '_', 'M', 'E', 'T', 'H', 'O', 'D'},
			inputLen: 100,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ilen := min(len(tt.input), tt.inputLen)
			res := maybeFastCGI(largebuf.NewLargeBufferFrom(tt.input[0:ilen]))
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestParseCGITable(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		inputLen int
		expected map[string]string
	}{
		{
			name:     "Older PHP",
			input:    []byte("\x01\x01\x00\x01\x00\b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x04\x00\x01\x02\t\a\x00\x0f\x1eSCRIPT_FILENAME/var/www/html/public/index.php\f\x00QUERY_STRING\x0e\x03REQUEST_METHODGET\f\x00CONTENT_TYPE\x0e\x00CONTENT_LENGTH\v\nSCRIPT_NAME/index.php\v\x01REQUEST_URI/\f\nDOCUMENT_URI/index.php\r\x14DOCUMENT_ROOT/var/www/html/public\x0f\bSERVER_PROTOCOLHTTP/1.1\x0e")[24:],
			inputLen: 200,
			expected: map[string]string{"CONTENT_LENGTH": "", "CONTENT_TYPE": "", "QUERY_STRING": "", "REQUEST_METHOD": "GET", "SCRIPT_FILENAME": "/var/www/html/public/index.php", "DOCUMENT_ROOT": "", "DOCUMENT_URI": "/index.php", "REQUEST_URI": "/", "SCRIPT_NAME": "/index.php"},
		},
		{
			name:     "Empty URI",
			input:    []byte("\x01\x01\x00\x01\x00\b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x04\x00\x01\x01\xdb\x05\x00\f\x00QUERY_STRING\x0e\x03REQUEST_METHODGET\f\x00CONTENT_TYPE\x0e\x00CONTENT_LENGTH\v\nSCRIPT_NAME/index.php\v\x01REQUEST_URI/\f\x01DOCUMENT_URI/\r\rDOCUMENT_ROOT/var/www/html\x0f\bSERVER_PROTOCOLHTTP/1.1\x0e\x04REQUEST_SCHEMEhttp\x11\aGATEWAY_INTERFACECGI/1.1\x0f\fSERVER_SOFTWAREn")[24:],
			inputLen: 100,
			expected: map[string]string{"CONTENT_LENGTH": "", "CONTENT_TYPE": "", "QUERY_STRING": "", "REQUEST_METHOD": "GET", "REQUEST_URI": "/", "SCRIPT_NAME": "/index.php"},
		},
		{
			name:     "Correct values",
			input:    []byte{12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			inputLen: 100,
			expected: map[string]string{"CONTENT_LENGTH": "", "CONTENT_TYPE": "", "QUERY_STRING": "", "REQUEST_METHOD": "GET", "REQUEST_URI": "/ping", "SCRIPT_NAME": "/ping"},
		},
		{
			name:     "Empty",
			input:    []byte{},
			inputLen: 100,
			expected: map[string]string{},
		},
		{
			name:     "Short",
			input:    []byte{12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			inputLen: 23,
			expected: map[string]string{"QUERY_STRING": ""},
		},
		{
			name:     "Very Short",
			input:    []byte{12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			inputLen: 3,
			expected: map[string]string{},
		},
		{
			name:     "Broken at key",
			input:    []byte{1, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			inputLen: 3,
			expected: map[string]string{"Q": ""},
		},
		{
			name:     "Empty key for query string",
			input:    []byte{0, 12, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			inputLen: 100,
			expected: map[string]string{"CONTENT_LENGTH": "", "CONTENT_TYPE": "", "REQUEST_METHOD": "GET", "REQUEST_URI": "/ping", "SCRIPT_NAME": "/ping"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ilen := min(len(tt.input), tt.inputLen)
			res := parseCGITable(tt.input[0:ilen])
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestDetectFastCGI(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		output         []byte
		inputLen       int
		outputLen      int
		expectedMethod string
		expectedPath   string
		expectedResult int
		extraCheck     func(t *testing.T, path string)
	}{
		{
			name:           "Older PHP, small frame",
			input:          []byte("\x01\x01\x00\x01\x00\b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x04\x00\x01\x02\t\a\x00\x0f\x1eSCRIPT_FILENAME/var/www/html/public/index.php\f\x00QUERY_STRING\x0e\x03REQUEST_METHODGET\f\x00CONTENT_TYPE\x0e\x00CONTENT_LENGTH\v\nSCRIPT_NAME/inde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			output:         []byte{1, 0, 1, 0, 0},
			inputLen:       152,
			outputLen:      20,
			expectedMethod: "GET",
			expectedPath:   "",
			expectedResult: 200,
		},
		{
			name:           "Older PHP",
			input:          []byte("\x01\x01\x00\x01\x00\b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x04\x00\x01\x02\t\a\x00\x0f\x1eSCRIPT_FILENAME/var/www/html/public/index.php\f\x00QUERY_STRING\x0e\x03REQUEST_METHODGET\f\x00CONTENT_TYPE\x0e\x00CONTENT_LENGTH\v\nSCRIPT_NAME/index.php\v\x01REQUEST_URI/\f\nDOCUMENT_URI/index.php\r\x14DOCUMENT_ROOT/var/www/html/public\x0f\bSERVER_PROTOCOLHTTP/1.1\x0e"),
			output:         []byte{1, 0, 1, 0, 0},
			inputLen:       200,
			outputLen:      20,
			expectedMethod: "GET",
			expectedPath:   "/",
			expectedResult: 200,
		},
		{
			name:           "Correct values empty URI",
			input:          []byte("\x01\x01\x00\x01\x00\b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x04\x00\x01\x01\xdb\x05\x00\f\x00QUERY_STRING\x0e\x03REQUEST_METHODGET\f\x00CONTENT_TYPE\x0e\x00CONTENT_LENGTH\v\nSCRIPT_NAME/index.php\v\x01REQUEST_URI/\f\x01DOCUMENT_URI/\r\rDOCUMENT_ROOT/var/www/html\x0f\bSERVER_PROTOCOLHTTP/1.1\x0e\x04REQUEST_SCHEMEhttp\x11\aGATEWAY_INTERFACECGI/1.1\x0f\fSERVER_SOFTWAREn"),
			output:         []byte{1, 0, 1, 0, 0},
			inputLen:       200,
			outputLen:      20,
			expectedMethod: "GET",
			expectedPath:   "/",
			expectedResult: 200,
		},
		{
			name:           "Correct values",
			input:          []byte{1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 1, 217, 7, 0, 12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			output:         []byte{1, 0, 1, 0, 0},
			inputLen:       200,
			outputLen:      20,
			expectedMethod: "GET",
			expectedPath:   "/ping",
			expectedResult: 200,
		},
		{
			name:           "Correct values, error",
			input:          []byte{1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 1, 217, 7, 0, 12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			output:         []byte{1, 7, 1, 0, 0},
			inputLen:       200,
			outputLen:      20,
			expectedMethod: "GET",
			expectedPath:   "/ping",
			expectedResult: 500,
		},
		{
			name:           "Correct values, status 404",
			input:          []byte{1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 1, 217, 7, 0, 12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			output:         []byte{1, 6, 0, 1, 0, 106, 6, 0, 83, 116, 97, 116, 117, 115, 58, 32, 52, 48, 52, 32, 78, 111, 116, 32, 70, 111, 117, 110, 100, 13, 10, 88, 45, 80, 111, 119, 101, 114, 101, 100, 45, 66, 121, 58, 32, 80, 72, 80, 47, 56, 46, 52, 46, 49, 13, 10, 67, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 58, 32, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 85, 84, 70, 45, 56, 13, 10, 13, 10, 70, 105, 108, 101, 32, 110, 111, 116, 32, 102, 111, 117, 110, 100, 46, 10, 0, 0, 0, 0, 0, 0, 1, 3, 0, 1, 0, 8, 0, 0},
			inputLen:       200,
			outputLen:      200,
			expectedMethod: "GET",
			expectedPath:   "/ping",
			expectedResult: 404,
		},
		{
			// FastCGI passes REQUEST_URI and QUERY_STRING as independent CGI parameters.
			// OBI must reconstruct the full URI so the server span carries url.query.
			name: "REQUEST_URI and QUERY_STRING combined",
			// Packet: BEGIN_REQUEST (16 bytes) + PARAMS header (8 bytes) + params (57 bytes)
			// Params: REQUEST_METHOD=GET, REQUEST_URI=/, QUERY_STRING=cmd=BLABLA
			input:          []byte{1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 0, 57, 0, 0, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 11, 1, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 12, 10, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 99, 109, 100, 61, 66, 76, 65, 66, 76, 65},
			output:         []byte{1, 0, 1, 0, 0},
			inputLen:       200,
			outputLen:      20,
			expectedMethod: "GET",
			expectedPath:   "/?cmd=BLABLA",
			expectedResult: 200,
		},
		{
			// When REQUEST_URI already contains '?', QUERY_STRING must not be appended
			// again — the dedup guard prevents double query strings.
			name: "REQUEST_URI already contains query string, QUERY_STRING ignored",
			// Packet: BEGIN_REQUEST (16 bytes) + PARAMS header (8 bytes) + params (65 bytes)
			// Params: REQUEST_METHOD=GET, REQUEST_URI=/?existing=1, QUERY_STRING=other=2
			input:          []byte{1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 0, 65, 0, 0, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 11, 12, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 63, 101, 120, 105, 115, 116, 105, 110, 103, 61, 49, 12, 7, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 111, 116, 104, 101, 114, 61, 50},
			output:         []byte{1, 0, 1, 0, 0},
			inputLen:       200,
			outputLen:      20,
			expectedMethod: "GET",
			expectedPath:   "/?existing=1",
			expectedResult: 200,
			// Confirm QUERY_STRING=other=2 was not appended to the path.
			extraCheck: func(t *testing.T, path string) {
				assert.NotContains(t, path, "other=2")
			},
		},
		{
			// REQUEST_URI=/ping is in the packet but truncated at inputLen=100.
			// Path stays empty when REQUEST_URI is absent and there is no QUERY_STRING.
			name:           "Not enough data",
			input:          []byte{1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 1, 217, 7, 0, 12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			output:         []byte{1, 7, 1, 0, 0},
			inputLen:       100,
			outputLen:      1,
			expectedMethod: "GET",
			expectedPath:   "",
			expectedResult: 200,
		},
		{
			name:           "Empty",
			input:          []byte{1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 1, 1, 217, 7, 0, 12, 0, 81, 85, 69, 82, 89, 95, 83, 84, 82, 73, 78, 71, 14, 3, 82, 69, 81, 85, 69, 83, 84, 95, 77, 69, 84, 72, 79, 68, 71, 69, 84, 12, 0, 67, 79, 78, 84, 69, 78, 84, 95, 84, 89, 80, 69, 14, 0, 67, 79, 78, 84, 69, 78, 84, 95, 76, 69, 78, 71, 84, 72, 11, 5, 83, 67, 82, 73, 80, 84, 95, 78, 65, 77, 69, 47, 112, 105, 110, 103, 11, 5, 82, 69, 81, 85, 69, 83, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 12, 5, 68, 79, 67, 85, 77, 69, 78, 84, 95, 85, 82, 73, 47, 112, 105, 110, 103, 13, 13, 68, 79, 67, 85, 77, 69, 78, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			output:         []byte{},
			inputLen:       24,
			outputLen:      1,
			expectedMethod: "",
			expectedPath:   "",
			expectedResult: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ilen := min(len(tt.input), tt.inputLen)
			olen := min(len(tt.output), tt.outputLen)
			method, path, status := detectFastCGI(largebuf.NewLargeBufferFrom(tt.input[0:ilen]), largebuf.NewLargeBufferFrom(tt.output[0:olen]))
			assert.Equal(t, tt.expectedMethod, method)
			assert.Equal(t, tt.expectedPath, path)
			assert.Equal(t, tt.expectedResult, status)
			if tt.extraCheck != nil {
				tt.extraCheck(t, path)
			}
		})
	}
}

func TestTCPToFastCGIToSpanPathSplit(t *testing.T) {
	tests := []struct {
		name         string
		uri          string
		expectedPath string
		expectedFull string
	}{
		{
			name:         "query stripped from Path, preserved in FullPath",
			uri:          "/?cmd=BLABLA",
			expectedPath: "/",
			expectedFull: "/?cmd=BLABLA",
		},
		{
			// When REQUEST_URI is absent, detectFastCGI defaults to "/", so
			// TCPToFastCGIToSpan never receives a URI starting with "?".
			// This case documents what would happen if the default is bypassed.
			name:         "path defaults to / when uri is root-less",
			uri:          "/",
			expectedPath: "/",
			expectedFull: "/",
		},
		{
			name:         "no query string unchanged",
			uri:          "/ping",
			expectedPath: "/ping",
			expectedFull: "/ping",
		},
		{
			// When REQUEST_URI is absent from FastCGI params and QUERY_STRING is also
			// absent, detectFastCGI returns "" and the span carries no path at all.
			name:         "empty uri when REQUEST_URI and QUERY_STRING both absent",
			uri:          "",
			expectedPath: "",
			expectedFull: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := TCPToFastCGIToSpan(&TCPRequestInfo{}, "GET", tt.uri, 200)
			assert.Equal(t, tt.expectedPath, span.Path)
			assert.Equal(t, tt.expectedFull, span.FullPath)
		})
	}
}

func appendFastCGINameValue(dst []byte, name, value string) []byte {
	dst = append(dst, byte(len(name)), byte(len(value)))
	dst = append(dst, name...)
	dst = append(dst, value...)
	return dst
}

func appendFastCGIRecord(dst []byte, recordType byte, requestID uint16, content []byte) []byte {
	paddingLength := byte((8 - (len(content) % 8)) % 8)
	dst = append(dst,
		1,
		recordType,
		byte(requestID>>8), byte(requestID),
		byte(len(content)>>8), byte(len(content)),
		paddingLength,
		0,
	)
	dst = append(dst, content...)
	return append(dst, make([]byte, paddingLength)...)
}

// BenchmarkDetectFastCGI measures the cost of parsing a complete FastCGI request+response pair.
//
//	go test -bench=BenchmarkDetectFastCGI -benchmem ./pkg/ebpf/common/...
func BenchmarkDetectFastCGI(b *testing.B) {
	params := make([]byte, 0, 160)
	params = appendFastCGINameValue(params, "QUERY_STRING", "")
	params = appendFastCGINameValue(params, "REQUEST_METHOD", "GET")
	params = appendFastCGINameValue(params, "CONTENT_TYPE", "")
	params = appendFastCGINameValue(params, "CONTENT_LENGTH", "")
	params = appendFastCGINameValue(params, "SCRIPT_NAME", "/ping")
	params = appendFastCGINameValue(params, "REQUEST_URI", "/ping")
	params = appendFastCGINameValue(params, "DOCUMENT_URI", "/ping")
	params = appendFastCGINameValue(params, "DOCUMENT_ROOT", "/var/www/html/public")

	request := make([]byte, 0, 192)
	request = appendFastCGIRecord(request, 1, 1, []byte{0, 1, 0, 0, 0, 0, 0, 0})
	request = appendFastCGIRecord(request, 4, 1, params)

	responsePayload := []byte("Status: 404 Not Found\r\nContent-type: text/html; charset=UTF-8\r\n\r\nFile not found.\n")
	response := appendFastCGIRecord(nil, 6, 1, responsePayload)

	reqBuf := largebuf.NewLargeBufferFrom(request)
	respBuf := largebuf.NewLargeBufferFrom(response)
	method, path, status := detectFastCGI(reqBuf, respBuf)
	if method != "GET" || path != "/ping" || status != 404 {
		b.Fatalf("unexpected benchmark fixture result: method=%q path=%q status=%d", method, path, status)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		detectFastCGI(reqBuf, respBuf)
	}
}
