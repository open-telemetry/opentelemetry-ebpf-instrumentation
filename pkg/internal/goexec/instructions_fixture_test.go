// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoAutoSDKFlagLoadOffsetFromCompiledFixture(t *testing.T) {
	offsets, err := instrumentationPoints(
		minimalAutoSDKELF,
		[]string{goAutoSDKGlobalNewSpan},
	)
	require.NoError(t, err)

	function, ok := offsets[goAutoSDKGlobalNewSpan]
	require.True(t, ok,
		"compiled Auto SDK fixture must expose an exact flag-load admission point")
	require.NotZero(t, function.Admission)
	require.Greater(t, function.Admission, function.Start)
	require.NotEmpty(t, function.Returns)
}
