// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFunctionReference(t *testing.T) {
	t.Parallel()

	got, err := ParseFunctionReference("@example/checkout#orders.create")
	require.NoError(t, err)
	require.Equal(t, "@example/checkout", got.ModuleSpecifier)
	require.Equal(t, []string{"orders", "create"}, got.ExportPath)
}

func TestParseFunctionReferenceRejectsUnsupportedSyntax(t *testing.T) {
	t.Parallel()

	for _, reference := range []string{
		"",
		"#create",
		"checkout#",
		"checkout#create#again",
		"checkout#orders.*",
		"checkout#orders.create-method",
		"checkout#orders create",
	} {
		t.Run(reference, func(t *testing.T) {
			t.Parallel()
			_, err := ParseFunctionReference(reference)
			require.Error(t, err)
		})
	}
}

func TestValidateV2DynamicSpans(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		languageGlobs []string
		languageRegex string
		span          V2SpanTarget
		wantErr       string
	}{
		{
			name:          "supported exact Node.js function",
			languageGlobs: []string{"nodejs"},
			span:          V2SpanTarget{Function: "./checkout.js#orders.placeOrder"},
		},
		{
			name:          "other runtime",
			languageGlobs: []string{"java"},
			span:          V2SpanTarget{Function: "com.example.Foo#bar"},
			wantErr:       "currently supported only",
		},
		{
			name:          "language regex",
			languageGlobs: []string{"nodejs"},
			languageRegex: "nodejs",
			span:          V2SpanTarget{Function: "./checkout.js#placeOrder"},
			wantErr:       "currently supported only",
		},
		{
			name:          "function noret",
			languageGlobs: []string{"nodejs"},
			span:          V2SpanTarget{FunctionNoRet: "./checkout.js#placeOrder"},
			wantErr:       "on.function is the only currently supported",
		},
		{
			name:          "attributes",
			languageGlobs: []string{"nodejs"},
			span:          V2SpanTarget{Function: "./checkout.js#placeOrder", HasAttributes: true},
			wantErr:       "attributes and automatic_attributes are not currently supported",
		},
		{
			name:          "automatic attributes",
			languageGlobs: []string{"nodejs"},
			span:          V2SpanTarget{Function: "./checkout.js#placeOrder", AutomaticAttributes: true},
			wantErr:       "attributes and automatic_attributes are not currently supported",
		},
		{
			name:          "invalid reference",
			languageGlobs: []string{"nodejs"},
			span:          V2SpanTarget{Function: "./checkout.js"},
			wantErr:       "moduleSpecifier#exportPath",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateV2DynamicSpans(0, test.languageGlobs, test.languageRegex, []V2SpanTarget{test.span})
			if test.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}
