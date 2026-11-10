// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"bytes"
	"encoding/binary"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

func TestHTTP2InjectedContextProcessIsolation(t *testing.T) {
	for _, own := range []bool{false, true} {
		name := "foreign_uprobe"
		if own {
			name = "own_uprobe"
		}
		t.Run(name, func(t *testing.T) {
			objects := loadJavaHTTP1Reservations(t, true)
			old := BpfTpInfoPidT{Pid: uint32(os.Getpid() + 1), Valid: 1, Written: 1, ReqType: 3}
			if own {
				old.Pid = uint32(os.Getpid())
			}
			copy(old.Tp.TraceId[:], bytes.Repeat([]byte{0x11}, 16))
			copy(old.Tp.SpanId[:], bytes.Repeat([]byte{0x22}, 8))
			old.Tp.Flags = 1
			require.NoError(t, objects.Outgoing.Update(BpfEgressKeyT{S_port: 40000, D_port: 443, StreamId: 1}, old, ebpf.UpdateAny))
			var payload bytes.Buffer
			payload.WriteString(http2.ClientPreface)
			fr := http2.NewFramer(&payload, nil)
			block := []byte{0x83, 0x86, 0x04, 0x05, '/', 'w', 'o', 'r', 'k', 0, 11}
			block = append(block, []byte("traceparent")...)
			block = append(block, 55)
			block = append(block, []byte("00-33333333333333333333333333333333-4444444444444444-01")...)
			require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true}))
			javaHTTP1Data(javaHTTP1Packet(40000), javaHTTP1SendOp, payload.Bytes())
			var key BpfHttp2ConnStreamT
			var info BpfHttp2GrpcRequestT
			iter := objects.HTTP2.Iterate()
			require.True(t, iter.Next(&key, &info), "outgoing HTTP/2 stream was recorded")
			require.NoError(t, iter.Err())
			if own {
				require.Equal(t, old.Tp.TraceId, info.Tp.TraceId)
				require.Equal(t, old.Tp.SpanId, info.Tp.SpanId)
			} else {
				require.NotEqual(t, old.Tp.TraceId, info.Tp.TraceId, "foreign cache context must not replace the client trace")
				require.NotEqual(t, old.Tp.SpanId, info.Tp.SpanId)
			}
		})
	}
}

func TestFailedConnectDoesNotPublishPropagationContext(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	objects := loadJavaHTTP1Reservations(t, true)
	for _, hook := range []struct {
		name    string
		program *ebpf.Program
	}{
		{"sys_connect", objects.SysConnect}, {"tcp_connect", objects.Connect}, {"sock_def_error_report", objects.ConnectError},
	} {
		attachment, err := kprobe.Attach(hook.name, hook.program, false)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, attachment.Close()) })
	}
	reader, err := ringbuf.NewReader(objects.Events)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reader.Close()) })
	reader.SetDeadline(time.Now().Add(2 * time.Second))
	// Reserve a port without listening: connect is deterministically refused.
	reserved, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(reserved)
	require.NoError(t, unix.Bind(reserved, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}))
	addr, err := unix.Getsockname(reserved)
	require.NoError(t, err)
	target := addr.(*unix.SockaddrInet4)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	require.ErrorIs(t, unix.Connect(fd, target), unix.ECONNREFUSED)
	record, err := reader.Read()
	require.NoError(t, err, "the failed CONNECT must still be exported")
	require.Equal(t, byte(15), record.RawSample[0])
	var event BpfTcpReqT
	require.NoError(t, binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &event))
	require.NotZero(t, event.Tp.TraceId)
	require.NotZero(t, event.Tp.SpanId)
	conn := event.ConnInfo
	if conn.D_port > conn.S_port {
		conn.S_addr, conn.D_addr = conn.D_addr, conn.S_addr
		conn.S_port, conn.D_port = conn.D_port, conn.S_port
	}
	var leaked BpfTpInfoPidT
	require.ErrorIs(t, objects.Outgoing.Lookup(BpfEgressKeyT{S_port: conn.S_port, D_port: conn.D_port}, &leaked), ebpf.ErrKeyNotExist,
		"an already failed connection must not publish context for later sends")
	// A health request on a different destination cannot inherit a client trace
	// either; the connection correlation key deliberately omits destination.
	conn.D_addr = [16]uint8{}
	conn.D_port = 0
	require.ErrorIs(t, objects.Traces.Lookup(BpfTraceMapKeyT{Conn: conn, Type: 2}, &leaked), ebpf.ErrKeyNotExist)
}
