// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestResolveDiagnosticSocket(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pid       uint64
		version   string
		errorText string
	}{
		{"net8", 42, "8.0.30", ""},
		{"net9", 42, "9.0.0", ""},
		{"net10", 42, "10.0.0", ""},
		{"future", 42, "11.0.0", ""},
		{"pid", 43, "8.0.30", "reports PID 43"},
		{"old", 42, "7.0.0", "unsupported CLR version"},
		{"malformed", 42, "unknown", "unsupported CLR version"},
		{"invalid major", 42, "x.0.0", "unsupported CLR version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := processInfo2Fixture(t)
			binary.LittleEndian.PutUint64(payload, tc.pid)
			oldVersion := utf16.Encode([]rune("8.0.30\x00"))
			payload = payload[:len(payload)-4-2*len(oldVersion)]
			version := utf16.Encode([]rune(tc.version + "\x00"))
			payload = binary.LittleEndian.AppendUint32(payload, uint32(len(version)))
			for _, unit := range version {
				payload = binary.LittleEndian.AppendUint16(payload, unit)
			}
			response, err := encodeIPCMessage(ipcCommandSetServer, ipcResponseOK, payload)
			require.NoError(t, err)
			path, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
				if err := expectProcessInfo2Request(conn); err != nil {
					return err
				}
				_, err := io.Copy(conn, bytes.NewReader(response))
				return err
			})
			directory := filepath.Dir(path)
			candidate := filepath.Join(directory, "dotnet-diagnostic-42-1-socket")
			require.NoError(t, os.Rename(path, candidate))
			other, err := net.Listen("unix", filepath.Join(directory, "dotnet-diagnostic-42-2-socket"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, other.Close()) })
			selected, info, err := resolveDiagnosticSocket(t.Context(), directory, 42, 1)
			if tc.errorText != "" {
				require.ErrorContains(t, err, tc.errorText)
				if tc.errorText == "unsupported CLR version" {
					require.ErrorIs(t, err, errUnsupportedRuntime)
				}
				require.Empty(t, selected)
				require.Zero(t, info)
			} else {
				require.NoError(t, err)
				require.Equal(t, candidate, selected)
				require.Equal(t, uint64(42), info.PID)
			}
			require.NoError(t, <-done)
		})
	}
	_, _, err := resolveDiagnosticSocket(t.Context(), t.TempDir(), 99, 1)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestResolveDiagnosticSocketIgnoresOtherIncarnation(t *testing.T) {
	payload := processInfo2Fixture(t)
	binary.LittleEndian.PutUint64(payload, 42)
	payload = bytes.Replace(payload, []byte{'8', 0, '.', 0}, []byte{'7', 0, '.', 0}, 1)
	response, err := encodeIPCMessage(ipcCommandSetServer, ipcResponseOK, payload)
	require.NoError(t, err)
	path, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
		if err := expectProcessInfo2Request(conn); err != nil {
			return err
		}
		_, err := io.Copy(conn, bytes.NewReader(response))
		return err
	})
	directory := filepath.Dir(path)
	require.NoError(t, os.Rename(path, filepath.Join(directory, "dotnet-diagnostic-42-1-socket")))

	stalePath := filepath.Join(directory, "dotnet-diagnostic-42-2-socket")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: stalePath, Net: "unix"})
	require.NoError(t, err)
	listener.SetUnlinkOnClose(false)
	require.NoError(t, listener.Close())

	selected, info, err := resolveDiagnosticSocket(t.Context(), directory, 42, 1)
	require.ErrorContains(t, err, "unsupported CLR version")
	require.NotErrorIs(t, err, unix.ECONNREFUSED)
	require.ErrorIs(t, err, errUnsupportedRuntime)
	require.Empty(t, selected)
	require.Zero(t, info)
	require.NoError(t, <-done)
}

func TestFindDiagnosticSockets(t *testing.T) {
	directory := t.TempDir()
	var expected []string
	for _, name := range []string{
		"dotnet-diagnostic-42-123-socket",
		"dotnet-diagnostic-42-456-socket",
		"dotnet-diagnostic-420-123-socket",
		"dotnet-diagnostic-42--socket",
	} {
		path := filepath.Join(directory, name)
		listener, err := net.Listen("unix", path)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, listener.Close()) })
		if len(expected) < 1 {
			expected = append(expected, path)
		}
	}
	require.NoError(t, os.WriteFile(filepath.Join(directory, "dotnet-diagnostic-42-file-socket"), nil, 0o600))
	sockets, err := findDiagnosticSockets(directory, 42, 123)
	require.NoError(t, err)
	require.ElementsMatch(t, expected, sockets)
	sockets, err = findDiagnosticSockets(directory, 99, 123)
	require.NoError(t, err)
	require.Empty(t, sockets)
	selected, info, err := resolveDiagnosticSocket(t.Context(), directory, 42, 789)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Empty(t, selected)
	require.Zero(t, info)
	_, err = findDiagnosticSockets(directory, 0, 123)
	require.ErrorContains(t, err, "nonzero namespace PID")
	_, err = findDiagnosticSockets(filepath.Join(directory, "missing"), 42, 123)
	require.ErrorIs(t, err, os.ErrNotExist)
}
