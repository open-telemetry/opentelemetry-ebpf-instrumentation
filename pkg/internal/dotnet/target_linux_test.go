// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func TestResolveDiagnosticTarget(t *testing.T) {
	pid := app.PID(os.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	process, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, process.Close()) })
	pids, err := process.NamespacedPids()
	require.NoError(t, err)
	require.NotEmpty(t, pids)
	namespacePID := uint64(pids[len(pids)-1])

	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("pid_mismatch=%t", mismatch), func(t *testing.T) {
			responsePID := namespacePID
			if mismatch {
				responsePID++
			}
			payload := processInfo2Fixture(t)
			binary.LittleEndian.PutUint64(payload, responsePID)
			response, err := encodeIPCMessage(ipcCommandSetServer, ipcResponseOK, payload)
			require.NoError(t, err)
			path, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
				if err := expectProcessInfo2Request(conn); err != nil {
					return err
				}
				_, err := io.Copy(conn, bytes.NewReader(response))
				return err
			})
			tempDir := filepath.Dir(path)
			socketName := fmt.Sprintf("dotnet-diagnostic-%d-%d-socket", namespacePID, startTime)
			require.NoError(t, os.Rename(path, filepath.Join(tempDir, socketName)))

			target, err := resolveDiagnosticTarget(t.Context(), process, tempDir)
			if mismatch {
				require.ErrorContains(t, err, "reports PID")
				require.Zero(t, target)
			} else {
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, target.directory.Close()) })
				require.Equal(t, namespacePID, target.info.PID)
				require.Equal(t, fmt.Sprintf("/proc/self/fd/%d/%s", target.directory.Fd(), socketName), target.socketPath)
				_, err := os.Stat(target.socketPath)
				require.NoError(t, err)
			}
			require.NoError(t, <-done)
		})
	}
}

func TestOpenDiagnosticDirectory(t *testing.T) {
	pid := app.PID(os.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	process, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, process.Close()) })

	response, err := encodeIPCMessage(ipcCommandSetServer, ipcResponseOK, processInfo2Fixture(t))
	require.NoError(t, err)
	path, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
		if err := expectProcessInfo2Request(conn); err != nil {
			return err
		}
		_, err := io.Copy(conn, bytes.NewReader(response))
		return err
	})
	const socketName = "dotnet-diagnostic-42-1-socket"
	tempDir := filepath.Dir(path)
	require.NoError(t, os.Rename(path, filepath.Join(tempDir, socketName)))
	directory, err := openDiagnosticDirectory(process, tempDir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, directory.Close()) })

	// The descriptor must still reach the socket after the directory is renamed.
	renamed := tempDir + "-moved"
	require.NoError(t, os.Rename(tempDir, renamed))
	t.Cleanup(func() { require.NoError(t, os.Rename(renamed, tempDir)) })
	fdPath := fmt.Sprintf("/proc/self/fd/%d", directory.Fd())
	selected, info, err := resolveDiagnosticSocket(t.Context(), fdPath, 42, 1)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(fdPath, socketName), selected)
	require.Equal(t, uint64(42), info.PID)
	require.NoError(t, <-done)

	defaultDirectory, err := openDiagnosticDirectory(process, "")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, defaultDirectory.Close()) })
	actual, err := defaultDirectory.Stat()
	require.NoError(t, err)
	expected, err := os.Stat("/tmp")
	require.NoError(t, err)
	require.True(t, os.SameFile(expected, actual))

	_, err = openDiagnosticDirectory(process, "relative")
	require.ErrorContains(t, err, "must be absolute")
	_, err = openDiagnosticDirectory(process, filepath.Join(renamed, "missing"))
	require.ErrorIs(t, err, os.ErrNotExist)
}
