// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package runtime

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestResolverIsUnsupportedOffLinux(t *testing.T) {
	_, err := NewResolver().Resolve(t.Context(), app.PID(1), 1)
	require.ErrorIs(t, err, errUnsupportedLayout)

	_, err = ProcessStartTime(app.PID(1))
	require.ErrorIs(t, err, errUnsupportedLayout)
}
