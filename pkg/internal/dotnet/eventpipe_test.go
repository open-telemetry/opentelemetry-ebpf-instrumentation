// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEncodeEventPipeStart(t *testing.T) {
	want, err := hex.DecodeString(
		"444f544e45545f4950435f563100870002030000" + // IPC header, size 135, CollectTracing2
			"10000000010000000001000000" + // 16 MiB, NetTrace, no rundown, one provider
			"020000000000000004000000" + // Keywords 0x2, Informational level
			"0f000000530079007300740065006d002e00520075006e00740069006d0065000000" + // System.Runtime
			"1a0000004500760065006e00740043006f0075006e0074006500720049006e00740065007200760061006c005300650063003d0031000000", // EventCounterIntervalSec=1
	)
	require.NoError(t, err)
	request, err := encodeEventPipeStart(time.Second)
	require.NoError(t, err)
	require.Equal(t, want, request)
}

func TestEncodeEventPipeStartSamplingInterval(t *testing.T) {
	for _, tc := range []struct {
		interval time.Duration
		argument string
	}{
		{250 * time.Millisecond, "EventCounterIntervalSec=0.25"},
		{2500 * time.Millisecond, "EventCounterIntervalSec=2.5"},
		{10 * time.Second, "EventCounterIntervalSec=10"},
	} {
		t.Run(tc.interval.String(), func(t *testing.T) {
			request, err := encodeEventPipeStart(tc.interval)
			require.NoError(t, err)
			// Skip the 20-byte IPC header and 25 bytes of fixed session/provider fields.
			reader := bytes.NewReader(request[45:])
			provider, err := readIPCString(reader)
			require.NoError(t, err)
			require.Equal(t, "System.Runtime", provider)
			argument, err := readIPCString(reader)
			require.NoError(t, err)
			require.Equal(t, tc.argument, argument)
			require.Zero(t, reader.Len())
		})
	}
}

func TestEncodeEventPipeStartInvalidInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		request, err := encodeEventPipeStart(interval)
		require.ErrorContains(t, err, "sampling interval must be greater than 0")
		require.Nil(t, request)
	}
}

func TestStartEventPipeRetainsStream(t *testing.T) {
	wantRequest, err := encodeEventPipeStart(250 * time.Millisecond)
	require.NoError(t, err)
	socketPath, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
		request := make([]byte, len(wantRequest))
		if _, err := io.ReadFull(conn, request); err != nil {
			return err
		}
		if !bytes.Equal(wantRequest, request) {
			return errors.New("unexpected EventPipe start request")
		}
		if _, err := io.WriteString(conn, "DOTNET_IPC_V1\x00\x1c\x00\xff\x00\x00\x00\x08\x07\x06\x05\x04\x03\x02\x01Nettrace"); err != nil {
			return err
		}
		var extra [1]byte
		if _, err := conn.Read(extra[:]); !errors.Is(err, io.EOF) {
			return errors.Join(errors.New("caller did not close the stream"), err)
		}
		return nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	session, err := startEventPipe(ctx, socketPath, 250*time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.stream.Close() })
	require.Equal(t, uint64(0x0102030405060708), session.id)
	require.Equal(t, socketPath, session.socketPath)

	// Canceling setup after success must leave the continuation readable.
	cancel()
	continuation := make([]byte, len("Nettrace"))
	_, err = io.ReadFull(session.stream, continuation)
	require.NoError(t, err)
	require.Equal(t, "Nettrace", string(continuation))
	require.NoError(t, session.stream.Close())
	require.NoError(t, <-done)
}

func TestStartEventPipeInvalidResponseClosesSocket(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
		err      string
	}{
		{"server error", "DOTNET_IPC_V1\x00\x18\x00\xff\xff\x00\x00\x85\x13\x13\x80", "HRESULT 0x80131385"},
		{"short session ID", "DOTNET_IPC_V1\x00\x1b\x00\xff\x00\x00\x001234567", "session ID payload size: 7"},
		{"long session ID", "DOTNET_IPC_V1\x00\x1d\x00\xff\x00\x00\x00123456789", "session ID payload size: 9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socketPath, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
				if _, err := readIPCMessage(conn); err != nil {
					return err
				}
				if _, err := io.WriteString(conn, tc.response); err != nil {
					return err
				}
				var extra [1]byte
				if _, err := conn.Read(extra[:]); !errors.Is(err, io.EOF) {
					return errors.Join(errors.New("failed start did not close the socket"), err)
				}
				return nil
			})
			session, err := startEventPipe(t.Context(), socketPath, time.Second)
			require.ErrorContains(t, err, tc.err)
			require.Nil(t, session)
			require.NoError(t, <-done)
		})
	}
}

func TestStartEventPipeCancellationClosesSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	socketPath, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
		if _, err := readIPCMessage(conn); err != nil {
			return err
		}
		cancel()
		var extra [1]byte
		if _, err := conn.Read(extra[:]); !errors.Is(err, io.EOF) {
			return errors.Join(errors.New("canceled start did not close the socket"), err)
		}
		return nil
	})
	session, err := startEventPipe(ctx, socketPath, time.Second)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, session)
	require.NoError(t, <-done)
}

func TestStopEventPipePreservesStream(t *testing.T) {
	socketPath, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
		want := []byte("DOTNET_IPC_V1\x00\x1c\x00\x02\x01\x00\x00\x08\x07\x06\x05\x04\x03\x02\x01")
		request := make([]byte, len(want))
		if _, err := io.ReadFull(conn, request); err != nil {
			return err
		}
		if !bytes.Equal(want, request) {
			return errors.New("unexpected EventPipe stop request")
		}
		if _, err := io.WriteString(conn, "DOTNET_IPC_V1\x00\x1c\x00\xff\x00\x00\x00\x08\x07\x06\x05\x04\x03\x02\x01"); err != nil {
			return err
		}
		var extra [1]byte
		if _, err := conn.Read(extra[:]); !errors.Is(err, io.EOF) {
			return errors.Join(errors.New("stop did not close its control connection"), err)
		}
		return nil
	})
	stream, producer := net.Pipe()
	t.Cleanup(func() {
		_ = stream.Close()
		_ = producer.Close()
	})
	require.NoError(t, stream.SetDeadline(time.Now().Add(2*time.Second)))
	require.NoError(t, producer.SetDeadline(time.Now().Add(2*time.Second)))
	session := &eventPipeSession{id: 0x0102030405060708, socketPath: socketPath, stream: stream}
	require.NoError(t, stopEventPipe(t.Context(), session))
	require.NoError(t, <-done)

	// Stopping collection leaves the original stream open for its final bytes.
	written := make(chan error, 1)
	go func() {
		_, err := io.WriteString(producer, "final events")
		_ = producer.Close()
		written <- err
	}()
	tail, err := io.ReadAll(session.stream)
	require.NoError(t, err)
	require.Equal(t, "final events", string(tail))
	require.NoError(t, <-written)
}

func TestStopEventPipeRejectsInvalidResponse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
		err      string
	}{
		{"server error", "DOTNET_IPC_V1\x00\x18\x00\xff\xff\x00\x00\x85\x13\x13\x80", "HRESULT 0x80131385"},
		{"short session ID", "DOTNET_IPC_V1\x00\x1b\x00\xff\x00\x00\x001234567", "stop payload size: 7"},
		{"wrong session ID", "DOTNET_IPC_V1\x00\x1c\x00\xff\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00", "returned session ID 0x2, expected 0x1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socketPath, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
				if _, err := readIPCMessage(conn); err != nil {
					return err
				}
				if _, err := io.WriteString(conn, tc.response); err != nil {
					return err
				}
				var extra [1]byte
				if _, err := conn.Read(extra[:]); !errors.Is(err, io.EOF) {
					return errors.Join(errors.New("failed stop did not close its control connection"), err)
				}
				return nil
			})
			err := stopEventPipe(t.Context(), &eventPipeSession{id: 1, socketPath: socketPath})
			require.ErrorContains(t, err, tc.err)
			require.NoError(t, <-done)
		})
	}
}

func TestStopEventPipeCancellationClosesSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	socketPath, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
		if _, err := readIPCMessage(conn); err != nil {
			return err
		}
		cancel()
		var extra [1]byte
		if _, err := conn.Read(extra[:]); !errors.Is(err, io.EOF) {
			return errors.Join(errors.New("canceled stop did not close its control connection"), err)
		}
		return nil
	})
	err := stopEventPipe(ctx, &eventPipeSession{id: 1, socketPath: socketPath})
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, <-done)
}
