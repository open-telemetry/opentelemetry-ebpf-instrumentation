// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dynamicspan

import (
	"strings"
	"testing"
)

func TestValidateV2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spans   []V2SpanTarget
		wantErr string
	}{
		{
			name: "empty declarations",
		},
		{
			name:  "valid declaration without language filter",
			spans: []V2SpanTarget{{Function: "com.example.Service#run"}},
		},
		{
			name:  "malformed selector deferred to runtime",
			spans: []V2SpanTarget{{Function: "com.example.Service#"}},
		},
		{
			name:    "unsupported target",
			spans:   []V2SpanTarget{{FunctionNoRet: "com.example.Service#run"}},
			wantErr: ".on.function is the only currently supported Java span target",
		},
		{
			name:    "attributes",
			spans:   []V2SpanTarget{{Function: "com.example.Service#run", HasAttributes: true}},
			wantErr: ".attributes and automatic_attributes are not currently supported",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateV2(0, test.spans)
			if test.wantErr == "" && err != nil {
				t.Fatalf("ValidateV2() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("ValidateV2() error = %v, want contains %q", err, test.wantErr)
			}
		})
	}
}
