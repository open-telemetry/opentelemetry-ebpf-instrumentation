// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoExceptionDefaultsAndOverrides(t *testing.T) {
	yes, no := true, false
	defaults := ExceptionsConfig{Enabled: true}
	require.True(t, defaults.Go.PanicsEnabled())
	require.False(t, defaults.Go.FormattedErrors)
	resolved := (&ExceptionsOverride{Go: &GoExceptionsOverride{FormattedErrors: &yes}}).Resolve(defaults)
	require.True(t, resolved.Go.PanicsEnabled())
	require.True(t, resolved.Go.FormattedErrors)
	resolved = (&ExceptionsOverride{Go: &GoExceptionsOverride{Panics: &no}}).Resolve(resolved)
	require.False(t, resolved.Go.PanicsEnabled())
	require.True(t, resolved.Go.FormattedErrors)
	inherited := (&ExceptionsOverride{Enabled: &no}).Resolve(resolved)
	require.False(t, inherited.Enabled)
	require.False(t, inherited.Go.PanicsEnabled())
	require.True(t, inherited.Go.FormattedErrors)
	require.True(t, defaults.Go.PanicsEnabled(), "overrides preserve defaults")
}
