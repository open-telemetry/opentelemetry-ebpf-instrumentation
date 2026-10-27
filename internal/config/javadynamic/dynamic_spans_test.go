// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javadynamic

import (
	"strings"
	"testing"
)

func TestValidateV2DynamicSpans(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		languageGlobs []string
		languageRegex string
		spans         []V2SpanTarget
		wantErr       string
	}{
		{
			name:          "empty declarations",
			languageGlobs: []string{"nodejs"},
		},
		{
			name:          "valid Java declaration",
			languageGlobs: []string{"java"},
			spans:         []V2SpanTarget{{Function: "com.example.Service#run"}},
		},
		{
			name:          "wrong runtime",
			languageGlobs: []string{"nodejs"},
			spans:         []V2SpanTarget{{Function: "com.example.Service#run"}},
			wantErr:       "only for rules matching process.language_glob: [java]",
		},
		{
			name:          "language regex",
			languageGlobs: []string{"java"},
			languageRegex: "java",
			spans:         []V2SpanTarget{{Function: "com.example.Service#run"}},
			wantErr:       "only for rules matching process.language_glob: [java]",
		},
		{
			name:          "unsupported target",
			languageGlobs: []string{"java"},
			spans:         []V2SpanTarget{{FunctionNoRet: "com.example.Service#run"}},
			wantErr:       ".on.function is the only currently supported Java span target",
		},
		{
			name:          "attributes",
			languageGlobs: []string{"java"},
			spans:         []V2SpanTarget{{Function: "com.example.Service#run", HasAttributes: true}},
			wantErr:       ".attributes and automatic_attributes are not currently supported",
		},
		{
			name:          "invalid selector",
			languageGlobs: []string{"java"},
			spans:         []V2SpanTarget{{Function: "com.example.Service#"}},
			wantErr:       "invalid Java method reference",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateV2DynamicSpans(0, test.languageGlobs, test.languageRegex, test.spans)
			if test.wantErr == "" && err != nil {
				t.Fatalf("ValidateV2DynamicSpans() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("ValidateV2DynamicSpans() error = %v, want contains %q", err, test.wantErr)
			}
		})
	}
}
