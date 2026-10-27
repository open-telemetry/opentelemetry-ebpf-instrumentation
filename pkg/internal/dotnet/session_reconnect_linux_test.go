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
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestSessionManagerCumulativeReconnect(t *testing.T) {
	for _, version := range []string{"8.0.30", "9.0.20", "10.0.12"} {
		t.Run(version, func(t *testing.T) { testSessionManagerCumulativeReconnect(t, version) })
	}
}

func testSessionManagerCumulativeReconnect(t *testing.T, version string) {
	t.Helper()
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
	firstCounters := append([]runtimeCounter{{Name: "processor-count", Value: 2}}, cycle(100, 10)...)
	firstCounters = append(firstCounters, cycle(3, 20)...)
	partial := cycle(99, 900)
	firstCounters = append(firstCounters, partial[:len(partial)-3]...)
	secondCounters := append([]runtimeCounter{{Name: "processor-count", Value: 4}}, cycle(1000, 30)...)
	secondCounters = append(secondCounters, cycle(2, 40)...)
	streams := [][]runtimeCounter{firstCounters, secondCounters}
	streamFor := func(index int, sessionID string) []byte {
		var records []netTraceRuntimeEvent
		for _, counter := range streams[index] {
			records = append(records, netTraceRuntimeEvent{counter: counter})
			if counter.Name == "time-in-jit" {
				if sessionID == "" {
					for range 3 {
						records = append(records, netTraceRuntimeEvent{exceptionType: "Example.Failure"})
					}
				} else {
					records = append(records, netTraceRuntimeEvent{exceptionType: "Failure", exceptionCount: 3})
				}
			}
		}
		if index == 0 {
			records = append(records, netTraceRuntimeEvent{exceptionType: "Failure", exceptionCount: 99})
		}
		stream := runtimeEventStreamWithMeter(t, int32(namespacePID), records, false, sessionID)
		if index == 0 {
			// The interrupted cycle must not become the next session's baseline.
			stream = stream[:len(stream)-1]
		}
		return stream
	}
	info := processInfo2Fixture(t)
	binary.LittleEndian.PutUint64(info, namespacePID)
	oldVersion := utf16.Encode([]rune("8.0.30\x00"))
	info = info[:len(info)-4-2*len(oldVersion)]
	encodedVersion := utf16.Encode([]rune(version + "\x00"))
	info = binary.LittleEndian.AppendUint32(info, uint32(len(encodedVersion)))
	for _, unit := range encodedVersion {
		info = binary.LittleEndian.AppendUint16(info, unit)
	}
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
		{ipcCommandSetEventPipe, ipcCommandCollectTracing2, sessionResponse},
		{ipcCommandSetEventPipe, ipcCommandStopTracing, sessionResponse},
		{ipcCommandSetProcess, ipcCommandProcessInfo2, infoResponse},
		{ipcCommandSetEventPipe, ipcCommandCollectTracing2, sessionResponse},
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
		var previousSessionID string
		sessionIndex := 0
		for _, expected := range requests {
			conn, err := listener.Accept()
			if err != nil {
				served <- err
				return
			}
			response := expected.response
			err = conn.SetDeadline(time.Now().Add(time.Second))
			if err == nil {
				var request ipcMessage
				request, err = readIPCMessage(conn)
				if err == nil && (request.Header.CommandSet != expected.set || request.Header.CommandID != expected.command) {
					err = fmt.Errorf("unexpected IPC command %d/%d", request.Header.CommandSet, request.Header.CommandID)
				}
				if err == nil && expected.set == ipcCommandSetEventPipe && expected.command == ipcCommandCollectTracing2 {
					var sessionID string
					sessionID, err = exceptionSessionIDFromRequest(request.Payload)
					if err == nil && strings.HasPrefix(version, "8.") && sessionID != "" {
						err = errors.New("CLR 8 must use native exception events")
					}
					if err == nil && !strings.HasPrefix(version, "8.") && (sessionID == "" || sessionID == previousSessionID) {
						err = errors.New("Meter reconnect must use a fresh nonempty session ID")
					}
					if err == nil {
						var want []byte
						want, err = encodeEventPipeStart(10*time.Millisecond, strings.HasPrefix(version, "8."), sessionID)
						if err == nil && !bytes.Equal(request.Payload, want[binary.Size(ipcHeader{}):]) {
							err = fmt.Errorf("unexpected provider request for CLR %s", version)
						}
					}
					if err == nil {
						response = append(append([]byte(nil), response...), streamFor(sessionIndex, sessionID)...)
						previousSessionID = sessionID
						sessionIndex++
					}
				}
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
	queue := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(8))
	batches := queue.Subscribe(msg.SubscriberName("reconnect"))
	manager := NewSessionManager(ctx, 10*time.Millisecond, time.Second, queue)
	t.Cleanup(manager.Close)
	process, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, process.Close()) })
	beforeUser, beforeSystem, err := readProcessCPUTimes(process)
	require.NoError(t, err)
	require.NoError(t, manager.Start(file))
	for index, expected := range []uint64{0, 3, 3, 5} {
		select {
		case batch := <-batches:
			require.Len(t, batch, 1)
			require.False(t, batch[0].Removed)
			snapshot := batch[0].Dotnet
			require.NotNil(t, snapshot)
			require.Equal(t, uint64(3*(index+1)), snapshot.Exceptions["Failure"])
			require.NotNil(t, snapshot.ProcessCPUCount)
			require.Equal(t, int64(2*(index/2+1)), *snapshot.ProcessCPUCount)
			afterUser, afterSystem, err := readProcessCPUTimes(process)
			require.NoError(t, err)
			require.NotNil(t, snapshot.ProcessCPUTimeUser)
			require.NotNil(t, snapshot.ProcessCPUTimeSystem)
			require.GreaterOrEqual(t, *snapshot.ProcessCPUTimeUser, beforeUser)
			require.LessOrEqual(t, *snapshot.ProcessCPUTimeUser, afterUser)
			require.GreaterOrEqual(t, *snapshot.ProcessCPUTimeSystem, beforeSystem)
			require.LessOrEqual(t, *snapshot.ProcessCPUTimeSystem, afterSystem)
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

func exceptionSessionIDFromRequest(payload []byte) (string, error) {
	reader := bytes.NewReader(payload)
	// Buffer size, format and rundown flag precede the provider count.
	if _, err := io.CopyN(io.Discard, reader, 9); err != nil {
		return "", err
	}
	var providerCount uint32
	if err := binary.Read(reader, binary.LittleEndian, &providerCount); err != nil {
		return "", err
	}
	for range providerCount {
		if _, err := io.CopyN(io.Discard, reader, 12); err != nil {
			return "", err
		}
		provider, err := readIPCString(reader)
		if err != nil {
			return "", err
		}
		arguments, err := readIPCString(reader)
		if err != nil {
			return "", err
		}
		if provider != "System.Diagnostics.Metrics" {
			continue
		}
		value, ok := strings.CutPrefix(arguments, "SessionId=")
		if !ok {
			return "", errors.New("Meter provider has no session ID")
		}
		sessionID, _, _ := strings.Cut(value, ";")
		return sessionID, nil
	}
	return "", nil
}
