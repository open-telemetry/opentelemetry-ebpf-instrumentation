// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateFunctionReference(t *testing.T) {
	t.Parallel()

	require.NoError(t, ValidateFunctionReference("**:exports.orders.create"))
	require.NoError(t, ValidateFunctionReference("**/checkout.js:exports.orders.create"))
}

func TestValidateFunctionReferenceRejectsEmptyReference(t *testing.T) {
	t.Parallel()

	for _, reference := range []string{
		"",
		"  \t",
		"**:exports.orders.\ncreate",
	} {
		t.Run(reference, func(t *testing.T) {
			t.Parallel()
			require.Error(t, ValidateFunctionReference(reference))
		})
	}
}
