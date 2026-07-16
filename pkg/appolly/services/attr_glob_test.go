// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGlobAttrUnmarshalTextPreservesPatternForMarshalYAML(t *testing.T) {
	t.Parallel()

	var attr GlobAttr
	require.NoError(t, attr.UnmarshalText([]byte("{go,java}")))

	value, err := attr.MarshalYAML()

	require.NoError(t, err)
	require.Equal(t, "{go,java}", value)
	require.True(t, attr.MatchString("go"))
	require.False(t, attr.MatchString("python"))
}
