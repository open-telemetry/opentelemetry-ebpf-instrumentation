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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func serveDiagnosticIPC(t *testing.T, handle func(net.Conn) error) (string, <-chan error) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "s")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			done <- err
			return
		}
		done <- handle(conn)
	}()
	return socketPath, done
}

func expectProcessInfo2Request(conn net.Conn) error {
	want := []byte("DOTNET_IPC_V1\x00\x14\x00\x04\x04\x00\x00")
	request := make([]byte, len(want))
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	if !bytes.Equal(want, request) {
		return fmt.Errorf("unexpected ProcessInfo2 request: %x", request)
	}
	return nil
}

func TestQueryProcessInfo2(t *testing.T) {
	payload := processInfo2Fixture(t)
	response := []byte("DOTNET_IPC_V1\x00\x00\x00\xff\x00\x00\x00")
	binary.LittleEndian.PutUint16(response[14:16], uint16(len(response)+len(payload)))
	response = append(response, payload...)
	socketPath, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
		if err := expectProcessInfo2Request(conn); err != nil {
			return err
		}
		if _, err := io.Copy(conn, bytes.NewReader(response)); err != nil {
			return err
		}
		var extra [1]byte
		if _, err := conn.Read(extra[:]); !errors.Is(err, io.EOF) {
			return errors.Join(errors.New("expected client to close after response"), err)
		}
		return nil
	})

	info, err := queryProcessInfo2(t.Context(), socketPath)
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.Equal(t, uint64(42), info.PID)
	require.Equal(t, "8.0.30", info.CLRVersion)
	require.Equal(t, "Linux", info.OperatingSystem)
}

func TestQueryProcessInfo2ServerError(t *testing.T) {
	socketPath, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
		if err := expectProcessInfo2Request(conn); err != nil {
			return err
		}
		_, err := io.WriteString(conn, "DOTNET_IPC_V1\x00\x18\x00\xff\xff\x00\x00\x85\x13\x13\x80")
		return err
	})
	info, err := queryProcessInfo2(t.Context(), socketPath)
	require.ErrorContains(t, err, "HRESULT 0x80131385")
	require.Zero(t, info)
	require.NoError(t, <-done)
}

func TestQueryProcessInfo2CancellationClosesSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	socketPath, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
		if err := expectProcessInfo2Request(conn); err != nil {
			return err
		}
		cancel()
		var extra [1]byte
		if _, err := conn.Read(extra[:]); !errors.Is(err, io.EOF) {
			return errors.Join(errors.New("expected client to close on cancellation"), err)
		}
		return nil
	})
	info, err := queryProcessInfo2(ctx, socketPath)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, info)
	require.NoError(t, <-done)
}

func TestQueryProcessInfo2MissingSocket(t *testing.T) {
	info, err := queryProcessInfo2(t.Context(), filepath.Join(t.TempDir(), "missing"))
	require.ErrorContains(t, err, "connecting to diagnostic socket")
	require.Zero(t, info)
}

func TestQueryProcessInfo2DeadlineClosesSocket(t *testing.T) {
	requestReceived := make(chan struct{})
	socketPath, done := serveDiagnosticIPC(t, func(conn net.Conn) error {
		if err := expectProcessInfo2Request(conn); err != nil {
			return err
		}
		close(requestReceived)
		var extra [1]byte
		if _, err := conn.Read(extra[:]); !errors.Is(err, io.EOF) {
			return errors.Join(errors.New("expected client to close at the context deadline"), err)
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	info, err := queryProcessInfo2(ctx, socketPath)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Zero(t, info)
	select {
	case <-requestReceived:
	default:
		t.Fatal("deadline expired before the server received the request")
	}
	require.NoError(t, <-done)
}
