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

