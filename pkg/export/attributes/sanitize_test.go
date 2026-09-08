// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeUTF8(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid UTF-8 string",
			input:    "valid-string",
			expected: "valid-string",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "binary data with null bytes",
			input:    "deb.debian.or 1498318199  0     0     100644  828       `\n\x1f\x8b\b",
			expected: "deb.debian.or 1498318199  0     0     100644  828       `\n\x1f\b",
		},
		{
			name:     "string with invalid UTF-8 sequence",
			input:    "test\xff\xfe",
			expected: "test",
		},
		{
			name:     "mixed valid and invalid UTF-8",
			input:    "hello\xff\xfeworld",
			expected: "helloworld",
		},
		{
			name:     "wholly invalid UTF-8 collapses to empty",
			input:    "\xff\xfe\xfd",
			expected: "",
		},
		{
			name:     "multi-byte runes are preserved",
			input:    "héllo-日本語",
			expected: "héllo-日本語",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeUTF8(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.True(t, utf8.ValidString(result))
		})
	}
}
