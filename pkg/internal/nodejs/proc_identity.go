// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	errProcessReplaced      = errors.New("process is no longer the one that was injected")
	errSignalWouldTerminate = errors.New("process has no SIGUSR1 handler, signaling it would terminate it")
)

const (
	procStatStartTimeField = 22
	procStatCommField      = 2

	sigusr1Bit = 1 << (uint(unix.SIGUSR1) - 1)
)

// procCatchesSIGUSR1 reports whether the process installed a handler for
// SIGUSR1. Without one the kernel's default action terminates it, so this is
// the authoritative answer to "would signaling this process kill it". Unknown
// counts as no: the caller must not signal what it could not verify.
func procCatchesSIGUSR1(pid int) bool {
	buf, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}

	for line := range strings.SplitSeq(string(buf), "\n") {
		val, found := strings.CutPrefix(line, "SigCgt:")
		if !found {
			continue
		}

		mask, err := strconv.ParseUint(strings.TrimSpace(val), 16, 64)
		if err != nil {
			return false
		}

		return mask&sigusr1Bit != 0
	}

	return false
}

// procStartTime reads the process start time in clock ticks since boot. Paired
// with the pid it identifies one process for its whole lifetime: a recycled pid
// reports a different start time. Zero means the value could not be read.
func procStartTime(pid int) uint64 {
	buf, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}

	// The comm field is parenthesized and may contain spaces and parens of its
	// own, so the fields after it begin past the final ')'.
	stat := string(buf)

	commEnd := strings.LastIndexByte(stat, ')')
	if commEnd < 0 {
		return 0
	}

	fields := strings.Fields(stat[commEnd+1:])

	idx := procStatStartTimeField - procStatCommField - 1
	if len(fields) <= idx {
		return 0
	}

	ticks, err := strconv.ParseUint(fields[idx], 10, 64)
	if err != nil {
		return 0
	}

	return ticks
}

// signalInspectorOpen sends the SIGUSR1 that reopens a Node.js inspector, but
// only to the process that reported startTime. SIGUSR1 terminates a process
// that has no handler for it, so a pid recycled since injection must never be
// signaled. A pidfd pins the identity for the lifetime of the descriptor,
// which closes the window between the check and the signal; where pidfds are
// unavailable the start time is rechecked immediately before the kill.
func signalInspectorOpen(pid int, startTime uint64) error {
	if startTime == 0 {
		return errProcessReplaced
	}

	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if procStartTime(pid) != startTime {
			return errProcessReplaced
		}

		if !procCatchesSIGUSR1(pid) {
			return errSignalWouldTerminate
		}

		return syscall.Kill(pid, syscall.SIGUSR1)
	}
	defer unix.Close(pidfd)

	if procStartTime(pid) != startTime {
		return errProcessReplaced
	}

	if !procCatchesSIGUSR1(pid) {
		return errSignalWouldTerminate
	}

	return unix.PidfdSendSignal(pidfd, unix.SIGUSR1, nil, 0)
}
