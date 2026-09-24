// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procs

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func status(sigIgn, sigCgt string) []byte {
	return []byte(fmt.Sprintf(
		"Name:\tjava\nState:\tS (sleeping)\nThreads:\t24\nSigQ:\t0/47000\nSigPnd:\t0000000000000000\n"+
			"SigBlk:\t0000000000000000\nSigIgn:\t%s\nSigCgt:\t%s\nCapEff:\t0000000000000000\n",
		sigIgn, sigCgt))
}

func TestDispositionFromStatus(t *testing.T) {
	const (
		// Measured on a stock Temurin JDK 8, and on the same JVM under -Xrs.
		quitCaught = "2000000101005ccf"
		quitNotSet = "2000000101001cc8"

		quitOnly  = "0000000000000004" // signal 3
		noneAtAll = "0000000000000000"
		illOnly   = "0000000000000008" // signal 4, adjacent to SIGQUIT
		usr1Only  = "0000000000000200" // signal 10
	)

	for _, tc := range []struct {
		name   string
		sigIgn string
		sigCgt string
		signal unix.Signal
		want   SignalDisposition
	}{
		{"caught by the JVM", noneAtAll, quitCaught, unix.SIGQUIT, SignalDispositionHandled},
		{"-Xrs leaves the default action", noneAtAll, quitNotSet, unix.SIGQUIT, SignalDispositionFatal},
		{"ignored rather than caught", quitOnly, noneAtAll, unix.SIGQUIT, SignalDispositionHandled},
		{"caught and ignored", quitOnly, quitOnly, unix.SIGQUIT, SignalDispositionHandled},
		{"nothing handles it", noneAtAll, noneAtAll, unix.SIGQUIT, SignalDispositionFatal},
		{"only the adjacent signal is handled", illOnly, illOnly, unix.SIGQUIT, SignalDispositionFatal},
		{"the same file answers per signal", noneAtAll, usr1Only, unix.SIGUSR1, SignalDispositionHandled},
		{"and fatal for another signal", noneAtAll, usr1Only, unix.SIGQUIT, SignalDispositionFatal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, dispositionFromStatus(status(tc.sigIgn, tc.sigCgt), tc.signal))
		})
	}
}

func TestDispositionFromStatusSignalOutOfRange(t *testing.T) {
	full := status("ffffffffffffffff", "ffffffffffffffff")

	require.Equal(t, SignalDispositionUnknown, dispositionFromStatus(full, unix.Signal(0)))
	require.Equal(t, SignalDispositionUnknown, dispositionFromStatus(full, unix.Signal(65)))
	require.Equal(t, SignalDispositionUnknown, dispositionFromStatus(full, unix.Signal(-1)))
	require.Equal(t, SignalDispositionHandled, dispositionFromStatus(full, unix.Signal(1)))
	require.Equal(t, SignalDispositionHandled, dispositionFromStatus(full, unix.Signal(64)))
}

// Unparseable input must not read as handled: that is the direction that sends
// the signal.
func TestDispositionFromStatusUnparseable(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"no signal fields", []byte("Name:\tjava\nState:\tS (sleeping)\n")},
		{"SigCgt missing", []byte("SigIgn:\t0000000000000000\n")},
		{"SigIgn missing", []byte("SigCgt:\t0000000000000004\n")},
		{"SigCgt not hexadecimal", []byte("SigIgn:\t0000000000000000\nSigCgt:\tnot-a-mask\n")},
		{"SigCgt overflows 64 bits", []byte("SigIgn:\t0000000000000000\nSigCgt:\tffffffffffffffffff\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, SignalDispositionUnknown, dispositionFromStatus(tc.in, unix.SIGQUIT))
		})
	}
}

func TestSignalMask(t *testing.T) {
	s := status("0000000000000006", "2000000101005ccf")

	ign, ok := signalMask(s, "SigIgn:")
	require.True(t, ok)
	require.Equal(t, uint64(0x6), ign)

	cgt, ok := signalMask(s, "SigCgt:")
	require.True(t, ok)
	require.Equal(t, uint64(0x2000000101005ccf), cgt)

	// SigPnd: and SigBlk: precede the wanted fields and are zero, so asserting
	// the value rules out a match against the wrong line.
	pnd, ok := signalMask(s, "SigPnd:")
	require.True(t, ok)
	require.Equal(t, uint64(0), pnd)

	_, ok = signalMask(s, "SigFoo:")
	require.False(t, ok)
}
