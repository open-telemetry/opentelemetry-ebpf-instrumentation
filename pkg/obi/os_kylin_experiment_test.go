// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package obi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckOSSupport_Kernel419Experiment(t *testing.T) {
	previousKernel, previousRHEL, previousBTF := kernelVersion, isRHELBased, hasBTF
	t.Cleanup(func() {
		kernelVersion, isRHELBased, hasBTF = previousKernel, previousRHEL, previousBTF
	})
	isRHELBased = func() bool { return false }
	for _, tc := range []struct {
		name    string
		minor   int
		optIn   string
		btf     bool
		allowed bool
	}{
		{"disabled", 19, "", true, false},
		{"enabled", 19, "1", true, true},
		{"missing BTF", 19, "1", false, false},
		{"other old kernel", 18, "1", true, false},
		{"invalid opt-in", 19, "true", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OBI_LAB_ALLOW_KERNEL_419", tc.optIn)
			kernelVersion = func() (int, int) { return 4, tc.minor }
			hasBTF = func() bool { return tc.btf }
			if tc.allowed {
				require.NoError(t, checkOSSupport())
			} else {
				require.Error(t, checkOSSupport())
			}
		})
	}
}
