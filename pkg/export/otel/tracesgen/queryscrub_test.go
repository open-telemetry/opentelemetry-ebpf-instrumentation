// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScrubQuery(t *testing.T) {
	sensitiveKeys := []string{"sig", "token", "AWSAccessKeyId"}

	tests := []struct {
		name string
		qs   string
		keys []string
		want string
	}{
		{
			name: "sensitive key redacted",
			qs:   "cmd=OBIWANKENOBI&sig=abc123",
			keys: sensitiveKeys,
			want: "cmd=OBIWANKENOBI&sig=REDACTED",
		},
		{
			name: "non-sensitive keys unchanged",
			qs:   "cmd=OBIWANKENOBI&page=1",
			keys: sensitiveKeys,
			want: "cmd=OBIWANKENOBI&page=1",
		},
		{
			name: "multiple sensitive keys",
			qs:   "q=hello&token=secret&AWSAccessKeyId=AKID&page=2",
			keys: sensitiveKeys,
			want: "q=hello&token=REDACTED&AWSAccessKeyId=REDACTED&page=2",
		},
		{
			// OTel semconv requires case-sensitive matching — SIG != sig
			name: "case-sensitive key matching: wrong case not redacted",
			qs:   "SIG=abc123&cmd=test",
			keys: sensitiveKeys,
			want: "SIG=abc123&cmd=test",
		},
		{
			name: "empty sensitive list passes through unchanged",
			qs:   "sig=secret&cmd=test",
			keys: nil,
			want: "sig=secret&cmd=test",
		},
		{
			name: "empty query string",
			qs:   "",
			keys: sensitiveKeys,
			want: "",
		},
		{
			name: "key with no value preserved",
			qs:   "flag&cmd=test",
			keys: sensitiveKeys,
			want: "flag&cmd=test",
		},
		{
			name: "parameter order preserved",
			qs:   "z=1&a=2&sig=secret&m=3",
			keys: sensitiveKeys,
			want: "z=1&a=2&sig=REDACTED&m=3",
		},
		{
			name: "all params redacted produces non-empty string",
			qs:   "sig=secret&token=abc",
			keys: sensitiveKeys,
			want: "sig=REDACTED&token=REDACTED",
		},
		{
			// Percent-encoded key name must still be redacted; raw key preserved in output.
			// e.g. ?si%67=secret where %67 decodes to 'g', making the key "sig".
			name: "percent-encoded key name matched and redacted",
			qs:   "cmd=test&si%67=secret",
			keys: sensitiveKeys,
			want: "cmd=test&si%67=REDACTED",
		},
		{
			// Invalid percent-encoding falls back to raw key comparison (no match here).
			name: "invalid percent-encoding falls back to raw key — no false redaction",
			qs:   "si%ZZg=value&cmd=test",
			keys: sensitiveKeys,
			want: "si%ZZg=value&cmd=test",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, scrubQuery(tc.qs, buildRedactSet(tc.keys)))
		})
	}
}
