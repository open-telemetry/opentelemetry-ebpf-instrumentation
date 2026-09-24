// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"context"
	"encoding/binary"
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

func TestSessionManagerCumulativeReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	pid := app.PID(os.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	pids, err := procs.FindNamespacedPids(pid)
	require.NoError(t, err)
	require.NotEmpty(t, pids)
	namespacePID := uint64(pids[len(pids)-1])
	cycle := func(increment, absolute float64) []runtimeCounter {
		return []runtimeCounter{
			{Name: "working-set", Value: 1},
			{Name: "gen-0-gc-count", Increment: true},
			{Name: "gen-1-gc-count", Increment: true},
			{Name: "gen-2-gc-count", Increment: true},
			{Name: "alloc-rate", Value: increment, Increment: true},
			{Name: "total-pause-time-by-gc", Value: increment, Increment: true},
			{Name: "threadpool-completed-items-count", Value: increment, Increment: true},
			{Name: "monitor-lock-contention-count", Value: increment, Increment: true},
			{Name: "assembly-count", Value: 1},
			{Name: "il-bytes-jitted", Value: absolute},
			{Name: "methods-jitted-count", Value: absolute},
			{Name: "time-in-jit", Value: increment, Increment: true},
		}
	}
	firstCounters := append(cycle(100, 10), cycle(3, 20)...)
	partial := cycle(99, 900)
	firstCounters = append(firstCounters, partial[:len(partial)-3]...)
	firstStream := runtimeCounterStream(t, int32(namespacePID), firstCounters)
	// The interrupted cycle must not become the next session's baseline.
	firstStream = firstStream[:len(firstStream)-1]
	secondStream := runtimeCounterStream(t, int32(namespacePID), append(cycle(1000, 30), cycle(2, 40)...))
	info := processInfo2Fixture(t)
	binary.LittleEndian.PutUint64(info, namespacePID)
	encode := func(command byte, payload []byte) []byte {
		response, err := encodeIPCMessage(ipcCommandSetServer, command, payload)
		require.NoError(t, err)
		return response
	}
	infoResponse := encode(ipcResponseOK, info)
	sessionResponse := encode(ipcResponseOK, binary.LittleEndian.AppendUint64(nil, 42))
	requests := []struct {
		set      byte
		command  byte
		response []byte
	}{
		{ipcCommandSetProcess, ipcCommandProcessInfo2, infoResponse},
		{ipcCommandSetEventPipe, ipcCommandCollectTracing2, append(append([]byte(nil), sessionResponse...), firstStream...)},
		{ipcCommandSetEventPipe, ipcCommandStopTracing, sessionResponse},
		{ipcCommandSetProcess, ipcCommandProcessInfo2, infoResponse},
		{ipcCommandSetEventPipe, ipcCommandCollectTracing2, append(append([]byte(nil), sessionResponse...), secondStream...)},
		{ipcCommandSetEventPipe, ipcCommandStopTracing, sessionResponse},
		{ipcCommandSetProcess, ipcCommandProcessInfo2, encode(ipcResponseError, binary.LittleEndian.AppendUint32(nil, 0x80131385))},
	}
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "s")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	require.NoError(t, os.Rename(path, filepath.Join(tempDir, fmt.Sprintf("dotnet-diagnostic-%d-%d-socket", namespacePID, startTime))))
	require.NoError(t, listener.SetDeadline(time.Now().Add(4*time.Second)))
	served := make(chan error, 1)
	go func() {
		for _, expected := range requests {
			conn, err := listener.Accept()
			if err != nil {
				served <- err
				return
			}
			err = conn.SetDeadline(time.Now().Add(time.Second))
			if err == nil {
				var request ipcMessage
				request, err = readIPCMessage(conn)
				if err == nil && (request.Header.CommandSet != expected.set || request.Header.CommandID != expected.command) {
					err = fmt.Errorf("unexpected IPC command %d/%d", request.Header.CommandSet, request.Header.CommandID)
				}
			}
			if err == nil {
				_, err = io.Copy(conn, bytes.NewReader(expected.response))
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
	queue := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(8))
	batches := queue.Subscribe(msg.SubscriberName("reconnect"))
	manager := NewSessionManager(ctx, 10*time.Millisecond, time.Second, queue)
	t.Cleanup(manager.Close)
	require.NoError(t, manager.Start(file))
	for index, expected := range []uint64{0, 3, 3, 5} {
		select {
		case batch := <-batches:
			require.Len(t, batch, 1)
			require.False(t, batch[0].Removed)
			snapshot := batch[0].Dotnet
			require.NotNil(t, snapshot)
			for _, value := range []*uint64{snapshot.GCHeapTotalAllocated, snapshot.ThreadPoolWorkItemCount, snapshot.MonitorLockContentions} {
				require.NotNil(t, value)
				require.Equal(t, expected, *value)
			}
			for _, seconds := range []*float64{snapshot.GCPauseTime, snapshot.JITCompilationTime} {
				require.NotNil(t, seconds)
				require.InDelta(t, float64(expected)/1000, *seconds, 1e-12)
			}
			require.NotNil(t, snapshot.JITCompiledILSize)
			require.NotNil(t, snapshot.JITCompiledMethods)
			require.Equal(t, uint64((index+1)*10), *snapshot.JITCompiledILSize)
			require.Equal(t, uint64((index+1)*10), *snapshot.JITCompiledMethods)
		case <-ctx.Done():
			t.Fatal("session manager did not publish the expected cumulative snapshot")
		}
	}
	select {
	case batch := <-batches:
		require.Len(t, batch, 1)
		require.True(t, batch[0].Removed)
	case <-ctx.Done():
		t.Fatal("session manager did not stop after the final unsupported response")
	}
	require.NoError(t, <-served)
}
