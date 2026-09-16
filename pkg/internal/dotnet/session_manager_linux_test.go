// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestSessionManagerReadSessionCancellation(t *testing.T) {
	const sessionID = uint64(42)
	path, stopped := serveDiagnosticIPC(t, func(conn net.Conn) error {
		message, err := readIPCMessage(conn)
		if err != nil {
			return err
		}
		if message.Header.CommandSet != ipcCommandSetEventPipe || message.Header.CommandID != ipcCommandStopTracing ||
			len(message.Payload) != 8 || binary.LittleEndian.Uint64(message.Payload) != sessionID {
			return errors.New("unexpected StopTracing request")
		}
		response, err := encodeIPCMessage(ipcCommandSetServer, ipcResponseOK, message.Payload)
		if err != nil {
			return err
		}
		_, err = io.Copy(conn, bytes.NewReader(response))
		return err
	})
	stream, runtime := net.Pipe()
	t.Cleanup(func() { _ = stream.Close() })
	t.Cleanup(func() { _ = runtime.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sessionManager := NewSessionManager(ctx, time.Hour, 100*time.Millisecond, nil)
	done := make(chan error, 1)
	go func() {
		done <- sessionManager.readSession(ctx, &eventPipeSession{id: sessionID, socketPath: path, stream: stream}, 1,
			func(*runtimemetrics.DotnetRuntimeMetricSnapshot) error {
				return errors.New("silent stream unexpectedly produced a snapshot")
			})
	}()
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("session reader did not stop after cancellation")
	}
	require.NoError(t, <-stopped)
	var buffer [1]byte
	_, err := runtime.Read(buffer[:])
	require.ErrorIs(t, err, io.EOF, "session must close the stream after the drain deadline")
}

func TestSessionManagerProcessLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	pid := app.PID(os.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	file := exec.New(exec.Init{
		Pid: pid, StartTime: startTime,
		Service: svc.Attrs{EnvVars: map[string]string{"TMPDIR": t.TempDir()}},
	})
	queue := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot]()
	snapshots := queue.Subscribe(msg.SubscriberName("test"))
	sessionManager := NewSessionManager(ctx, 100*time.Millisecond, time.Second, queue)
	t.Cleanup(sessionManager.Close)
	require.NoError(t, sessionManager.Start(file))
	sessionManager.mu.Lock()
	target := sessionManager.targets[pid]
	sessionManager.mu.Unlock()
	require.NotNil(t, target)
	require.NoError(t, sessionManager.Start(file))
	sessionManager.mu.Lock()
	duplicate := sessionManager.targets[pid]
	sessionManager.mu.Unlock()
	require.Same(t, target, duplicate)

	sessionManager.Remove(exec.New(exec.Init{Pid: pid, StartTime: startTime + 1}))
	select {
	case <-target.done:
		t.Fatal("stale deletion stopped the current session manager")
	case <-time.After(150 * time.Millisecond):
	}

	sessionManager.Remove(file)
	select {
	case <-target.done:
	case <-ctx.Done():
		t.Fatal("matching deletion did not stop the session manager")
	}
	select {
	case batch := <-snapshots:
		require.Len(t, batch, 1)
		require.True(t, batch[0].Removed)
		require.Equal(t, pid, batch[0].PID)
		require.Equal(t, file.RuntimeMetricGeneration(pid), batch[0].Generation)
		require.NotZero(t, batch[0].Generation)
		require.NotNil(t, batch[0].Dotnet)
	case <-ctx.Done():
		t.Fatal("session manager did not publish its removal marker")
	}
	sessionManager.Close()
	require.NoError(t, sessionManager.Start(file))
	sessionManager.mu.Lock()
	remaining := len(sessionManager.targets)
	sessionManager.mu.Unlock()
	require.Zero(t, remaining, "closed session manager must not start another worker")
}

func TestSessionManagerStopsForUnsupportedRuntime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		errors []uint32
	}{
		{"old version", nil},
		{"unknown command", []uint32{0x80131385}},
		// A temporary failure must reach the next request before the worker stops.
		{"temporary error then unknown command", []uint32{0x80131371, 0x80131385}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			pid := app.PID(os.Getpid())
			startTime, err := procs.StartTime(pid)
			require.NoError(t, err)
			pids, err := procs.FindNamespacedPids(pid)
			require.NoError(t, err)
			require.NotEmpty(t, pids)
			namespacePID := uint64(pids[len(pids)-1])
			payload := processInfo2Fixture(t)
			binary.LittleEndian.PutUint64(payload, namespacePID)
			payload = bytes.Replace(payload, []byte{'8', 0, '.', 0}, []byte{'7', 0, '.', 0}, 1)
			response, err := encodeIPCMessage(ipcCommandSetServer, ipcResponseOK, payload)
			require.NoError(t, err)
			responses := [][]byte{response}
			if len(tc.errors) > 0 {
				responses = nil
				for _, code := range tc.errors {
					response, err := encodeIPCMessage(ipcCommandSetServer, ipcResponseError, binary.LittleEndian.AppendUint32(nil, code))
					require.NoError(t, err)
					responses = append(responses, response)
				}
			}
			// Bind a short name to stay within the Unix socket path limit.
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "s")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			require.NoError(t, os.Rename(path, filepath.Join(tempDir, fmt.Sprintf("dotnet-diagnostic-%d-%d-socket", namespacePID, startTime))))
			require.NoError(t, listener.SetDeadline(time.Now().Add(2*time.Second)))
			served := make(chan error, 1)
			go func() {
				for _, response := range responses {
					conn, err := listener.Accept()
					if err != nil {
						served <- err
						return
					}
					err = conn.SetDeadline(time.Now().Add(time.Second))
					if err == nil {
						err = expectProcessInfo2Request(conn)
					}
					if err == nil {
						_, err = io.Copy(conn, bytes.NewReader(response))
					}
					_ = conn.Close()
					if err != nil {
						served <- err
						return
					}
				}
				served <- nil
			}()
			file := exec.New(exec.Init{
				Pid: pid, StartTime: startTime,
				Service: svc.Attrs{EnvVars: map[string]string{"TMPDIR": tempDir}},
			})
			queue := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot]()
			sessionManager := NewSessionManager(ctx, 100*time.Millisecond, time.Second, queue)
			t.Cleanup(sessionManager.Close)
			require.NoError(t, sessionManager.Start(file))

			done := make(chan struct{})
			go func() {
				sessionManager.workers.Wait()
				close(done)
			}()
			select {
			case <-done:
				require.NoError(t, ctx.Err(), "worker must stop before cancellation")
			case <-ctx.Done():
				t.Fatal("session manager kept retrying an unsupported runtime")
			}
			require.NoError(t, <-served)
			sessionManager.mu.Lock()
			remaining := len(sessionManager.targets)
			sessionManager.mu.Unlock()
			require.Zero(t, remaining)
		})
	}
}
