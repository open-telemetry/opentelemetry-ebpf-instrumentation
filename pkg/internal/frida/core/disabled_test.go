// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !obi_frida || !linux || (!amd64 && !arm64)

package core

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnavailableBackend(t *testing.T) {
	engine, err := Open(t.Context(), "/unused/libfrida-core.so")
	require.Nil(t, engine)
	require.ErrorIs(t, err, ErrUnavailable)
	require.ErrorContains(t, err, "requires a Linux amd64/arm64 OBI build with -tags=obi_frida")
}
