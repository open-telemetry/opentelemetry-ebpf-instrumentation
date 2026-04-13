// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package helpers

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

var (
	expectedProcCaps *OSCapabilities
	errResetCaps     error
)

// This needs to run in the main thread (called by TestMain() below)
// capset() can fail with EPERM when called from a different thread. From the
// manpage:
//
//	EPERM  The caller attempted to use capset() to modify the capabilities of
//	a thread other than itself, but lacked sufficient privilege.  For kernels
//	supporting VFS capabilities, this is never  permitted.
//	For  kernels  lacking  VFS  support,  the CAP_SETPCAP  capability  is  required.
//
// We need to drop capabilities to correctly test TestCheckOSCapabilities()
func resetProcCapabilities() {
	var err error

	expectedProcCaps, err = GetCurrentProcCapabilities()

	errRef := &err
	cleanup := func() {
		if *errRef != nil {
			errResetCaps = fmt.Errorf("failed to reset capabilities: %w", *errRef)
		}
	}

	defer cleanup()

	if err != nil {
		return
	}

	expectedProcCaps.Clear(unix.CAP_BPF)
	expectedProcCaps.Set(unix.CAP_BPF)

	err = SetCurrentProcCapabilities(expectedProcCaps)
}

func TestGetSetCurrentProcCaps(t *testing.T) {
	if errResetCaps != nil {
		assert.Fail(t, errResetCaps.Error())
	}

	caps, err := GetCurrentProcCapabilities()
	require.NoError(t, err)
	assert.Equal(t, expectedProcCaps, caps)
}

func TestMain(m *testing.M) {
	resetProcCapabilities()
	if errResetCaps != nil {
		_, _ = fmt.Fprintln(os.Stderr, errResetCaps.Error())
		os.Exit(1)
	}
	os.Exit(m.Run())
}
