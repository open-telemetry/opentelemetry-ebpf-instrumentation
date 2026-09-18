// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/require"
)

// AsyncLocalStorage was added in 13.10.0 and backported to 12.17.0, so the
// 13.x releases below 13.10 are a hole above the 12.17 bound.
func TestSupportsAsyncLocalStorage(t *testing.T) {
	for _, tc := range []struct {
		nodeVersion string
		supported   bool
	}{
		{"8.17.0", false},
		{"9.3.0", false},
		{"12.16.3", false},
		{"12.17.0", true},
		{"12.22.12", true},
		{"13.0.0", false},
		{"13.9.0", false},
		{"13.10.0", true},
		{"13.14.0", true},
		{"14.0.0", true},
		{"20.11.1", true},
		{"24.3.0", true},
	} {
		t.Run(tc.nodeVersion, func(t *testing.T) {
			require.Equal(t, tc.supported,
				supportsAsyncLocalStorage(version.Must(version.NewVersion(tc.nodeVersion))))
		})
	}
}

func TestNodeVersionFrom(t *testing.T) {
	for _, tc := range []struct {
		name  string
		data  string
		want  string
		found bool
	}{
		{"as Node.js embeds it", "...\x00node.js/v20.11.1\x00...", "20.11.1", true},
		{"the runtime that crashed in the field", "\x00node.js/v9.3.0\x00", "9.3.0", true},
		{"at the very start", "node.js/v12.17.0", "12.17.0", true},
		{"no version anywhere", "\x00some other rodata\x00", "", false},
		{"prefix without a version", "node.js/vnext", "", false},
		{"truncated version", "node.js/v20.11", "", false},
		{"empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, found := nodeVersionFrom([]byte(tc.data))
			require.Equal(t, tc.found, found)

			if tc.found {
				require.Equal(t, tc.want, got.String())
			}
		})
	}
}

// .rodata is read in pieces, so a version sitting across a read boundary must
// still be found. The first read fills chunkSize+versionLiteralMax bytes, so
// that offset — not chunkSize — is where the carry has to do its work; each
// case asserts it actually straddles it, since an earlier version of this test
// silently did not.
func TestScanNodeVersionAcrossChunkBoundary(t *testing.T) {
	const (
		literal   = "node.js/v18.19.0"
		chunkSize = 64
	)

	boundary := chunkSize + versionLiteralMax

	for _, at := range []int{
		boundary - len(literal) + 1, // one byte of the literal before the boundary
		boundary - len(literal)/2,   // split down the middle
		boundary - 1,                // all but one byte after it
	} {
		t.Run(fmt.Sprintf("literal-at-%d", at), func(t *testing.T) {
			require.Less(t, at, boundary, "case starts past the boundary")
			require.Greater(t, at+len(literal), boundary, "case ends before the boundary")

			rodata := append(bytes.Repeat([]byte{0}, at), literal...)
			rodata = append(rodata, bytes.Repeat([]byte{0}, chunkSize)...)

			got, found := scanNodeVersion(bytes.NewReader(rodata), chunkSize)
			require.True(t, found)
			require.Equal(t, "18.19.0", got.String())
		})
	}
}

// A match many chunks in has to survive every intervening carry.
func TestScanNodeVersionInALaterChunk(t *testing.T) {
	const chunkSize = 64

	rodata := append(bytes.Repeat([]byte{0}, 20*chunkSize), "node.js/v20.11.1"...)

	got, found := scanNodeVersion(bytes.NewReader(rodata), chunkSize)
	require.True(t, found)
	require.Equal(t, "20.11.1", got.String())
}

// A chunk size that leaves no room to read would let the scan loop without
// advancing, which times out rather than fails.
func TestScanNodeVersionAlwaysTerminates(t *testing.T) {
	for _, chunkSize := range []int{-1, 0, 1} {
		t.Run(fmt.Sprintf("chunk-size-%d", chunkSize), func(t *testing.T) {
			_, found := scanNodeVersion(bytes.NewReader(bytes.Repeat([]byte{0}, 4096)), chunkSize)
			require.False(t, found)
		})
	}
}

func TestScanNodeVersionFindsNothing(t *testing.T) {
	const chunkSize = 64

	_, found := scanNodeVersion(bytes.NewReader(bytes.Repeat([]byte{0}, 10*chunkSize)), chunkSize)
	require.False(t, found)
}

func TestRuntimeRefusal(t *testing.T) {
	// an unreadable executable is refused rather than injected: the version is
	// what tells us the agent can run at all
	require.Equal(t, refusalVersionUnknown, runtimeRefusal(nil))
}
