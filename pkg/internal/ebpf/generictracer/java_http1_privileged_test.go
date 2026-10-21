// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

const (
	javaHTTP1SendOp          = 1
	javaHTTP1ReceiveOp       = 2
	javaHTTP1Parent          = 8
	javaHTTP1Reserve         = 9
	javaHTTP1Release         = 10
	javaHTTP1IoctlCmd        = 0x0b10b1
	javaHTTP1ClientTraceType = 2 // TRACE_TYPE_CLIENT in bpf/common/tracing.h

	// Wire layout shared with JdkHttpClientPropagation and java_tls.c.
	javaHTTP1AddressSize        = 16
	javaHTTP1SourceAddress      = 1 // follows the opcode
	javaHTTP1DestinationAddress = javaHTTP1SourceAddress + javaHTTP1AddressSize
	javaHTTP1SourcePort         = javaHTTP1DestinationAddress + javaHTTP1AddressSize
	javaHTTP1DestinationPort    = javaHTTP1SourcePort + 2
	javaHTTP1LengthField        = javaHTTP1DestinationPort + 2
	javaHTTP1ValueOffset        = javaHTTP1LengthField + 4
	javaHTTP1TraceparentSize    = 55
	javaHTTP1ParentOffset       = javaHTTP1ValueOffset + javaHTTP1TraceparentSize
	javaHTTP1TraceIDSize        = 16
	javaHTTP1SpanIDSize         = 8
	javaHTTP1ParentFlags        = javaHTTP1ParentOffset + javaHTTP1TraceIDSize + javaHTTP1SpanIDSize
	javaHTTP1ParentStatus       = javaHTTP1ParentFlags + 1
	javaHTTP1PacketSize         = javaHTTP1ParentStatus + 1

	// Pad test headers to exercise matching at a nonzero offset in the plaintext.
	javaHTTP1HeaderValueOffset = 100
)

type javaHTTP1TestObjects struct {
	Ioctl    *ebpf.Program `ebpf:"obi_kprobe_sys_ioctl"`
	Requests *ebpf.Map     `ebpf:"java_http1_requests"`
	Jumps    *ebpf.Map     `ebpf:"jump_table"`
	HTTP     *ebpf.Map     `ebpf:"ongoing_http"`
	Traces   *ebpf.Map     `ebpf:"trace_map"`
	Outgoing *ebpf.Map     `ebpf:"outgoing_trace_map"`
	SSL      *ebpf.Map     `ebpf:"active_ssl_connections"`
}

func loadJavaHTTP1Reservations(t *testing.T, enabled bool) *javaHTTP1TestObjects {
	t.Helper()
	require.NoError(t, rlimit.RemoveMemlock())
	spec, err := LoadBpf()
	require.NoError(t, err)
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
		if m.MaxEntries == 0 && m.Type == ebpf.RingBuf {
			m.MaxEntries = uint32(unix.Getpagesize())
		}
	}
	spec.Maps["java_http1_requests"].MaxEntries = 1
	require.Equal(t, uint32(unix.BPF_F_NO_PREALLOC), spec.Maps["java_http1_requests"].Flags)
	require.NoError(t, ebpfconvenience.RewriteConstants(spec, map[string]any{
		"filter_pids":                    int32(0),
		"g_bpf_java_http1_enabled":       enabled,
		"g_bpf_header_propagation":       true,
		"g_bpf_probe_write_user_enabled": true,
		"g_bpf_traceparent_enabled":      true,
		"capture_header_buffer":          int32(1),
		"max_transaction_time":           uint64(time.Minute),
	}))
	var objs javaHTTP1TestObjects
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() {
		objs.Ioctl.Close()
		objs.Requests.Close()
		objs.Jumps.Close()
		objs.HTTP.Close()
		objs.Traces.Close()
		objs.Outgoing.Close()
		objs.SSL.Close()
	})
	info, err := objs.Ioctl.Info()
	require.NoError(t, err)
	instructions, err := info.Instructions()
	require.NoError(t, err)
	hasCAS := false
	for _, instruction := range instructions {
		hasCAS = hasCAS || instruction.OpCode.AtomicOp() == asm.CmpXchg
	}
	require.Equal(t, enabled, hasCAS, "the disabled path removes unsupported atomics before JIT")
	attachment, err := kprobe.Attach("sys_ioctl", objs.Ioctl, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, attachment.Close()) })
	return &objs
}

func javaHTTP1Packet(port uint16) []byte {
	packet := make([]byte, javaHTTP1PacketSize)
	packet[0] = javaHTTP1Reserve
	packet[javaHTTP1DestinationAddress-1] = 1
	packet[javaHTTP1SourcePort-1] = 2
	binary.NativeEndian.PutUint16(packet[javaHTTP1SourcePort:], port)
	binary.NativeEndian.PutUint16(packet[javaHTTP1DestinationPort:], 443)
	binary.NativeEndian.PutUint32(packet[javaHTTP1LengthField:], javaHTTP1HeaderValueOffset)
	return packet
}

func javaHTTP1Ioctl(packet []byte) {
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, 0, javaHTTP1IoctlCmd, uintptr(unsafe.Pointer(&packet[0])))
	runtime.KeepAlive(packet)
}

func javaHTTP1Send(reservation []byte) {
	javaHTTP1Data(reservation, javaHTTP1SendOp, javaHTTP1Headers(reservation))
}

func javaHTTP1Headers(reservation []byte) []byte {
	offset := int(binary.NativeEndian.Uint32(reservation[javaHTTP1LengthField:]))
	headers := []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Padding: ")
	headers = append(headers, bytes.Repeat([]byte{'x'}, offset-len(headers)-len("\r\ntraceparent: "))...)
	headers = append(headers, []byte("\r\ntraceparent: ")...)
	headers = append(headers, reservation[javaHTTP1ValueOffset:javaHTTP1ParentOffset]...)
	headers = append(headers, []byte("\r\n\r\n")...)
	return headers
}

func javaHTTP1Data(reservation []byte, opcode byte, payload []byte) {
	packet := make([]byte, javaHTTP1ValueOffset+len(payload))
	packet[0] = opcode
	copy(packet[javaHTTP1SourceAddress:javaHTTP1LengthField], reservation[javaHTTP1SourceAddress:javaHTTP1LengthField])
	if opcode == javaHTTP1ReceiveOp {
		copy(packet[javaHTTP1SourceAddress:javaHTTP1DestinationAddress], reservation[javaHTTP1DestinationAddress:javaHTTP1SourcePort])
		copy(packet[javaHTTP1DestinationAddress:javaHTTP1SourcePort], reservation[javaHTTP1SourceAddress:javaHTTP1DestinationAddress])
		copy(packet[javaHTTP1SourcePort:javaHTTP1DestinationPort], reservation[javaHTTP1DestinationPort:javaHTTP1LengthField])
		copy(packet[javaHTTP1DestinationPort:javaHTTP1LengthField], reservation[javaHTTP1SourcePort:javaHTTP1DestinationPort])
	}
	binary.NativeEndian.PutUint32(packet[javaHTTP1LengthField:], uint32(len(payload)))
	copy(packet[javaHTTP1ValueOffset:], payload)
	javaHTTP1Ioctl(packet)
}

func javaHTTP1MapSize(t *testing.T, reservations *ebpf.Map) int {
	t.Helper()
	key := make([]byte, reservations.KeySize())
	value := make([]byte, reservations.ValueSize())
	iter := reservations.Iterate()
	count := 0
	for iter.Next(&key, &value) {
		count++
	}
	require.NoError(t, iter.Err())
	return count
}

func TestJavaHTTP1ReservationLifecycle(t *testing.T) {
	if !supportsJavaHTTP1ReservationCleanup() {
		t.Skip("this test requires CMPXCHG support")
	}
	objects := loadJavaHTTP1Reservations(t, true)
	reservations, httpRequests := objects.Requests, objects.HTTP
	a := javaHTTP1Packet(40000)
	javaHTTP1Ioctl(a)
	require.Zero(t, a[0], "reservation acknowledged")
	require.Equal(t, 1, javaHTTP1MapSize(t, reservations))

	overflow := javaHTTP1Packet(40001)
	javaHTTP1Ioctl(overflow)
	require.Equal(t, byte(javaHTTP1Reserve), overflow[0], "full map fails open without acknowledgment")
	require.Equal(t, 1, javaHTTP1MapSize(t, reservations))

	a[0] = javaHTTP1Release
	javaHTTP1Ioctl(a)
	require.Zero(t, javaHTTP1MapSize(t, reservations), "an unobserved failed send is released")
	b := javaHTTP1Packet(40000)
	copy(b[javaHTTP1ParentOffset:javaHTTP1ParentOffset+javaHTTP1TraceIDSize], bytes.Repeat([]byte{0x33}, javaHTTP1TraceIDSize))
	copy(b[javaHTTP1ParentOffset+javaHTTP1TraceIDSize:javaHTTP1ParentFlags], bytes.Repeat([]byte{0x44}, javaHTTP1SpanIDSize))
	b[javaHTTP1ParentFlags] = 1
	b[javaHTTP1ParentStatus] = 1
	javaHTTP1Ioctl(b)
	require.Zero(t, b[0])
	require.NotEqual(t, a[javaHTTP1ValueOffset:javaHTTP1ParentOffset], b[javaHTTP1ValueOffset:javaHTTP1ParentOffset])
	javaHTTP1Ioctl(a)
	require.Equal(t, 1, javaHTTP1MapSize(t, reservations), "stale release preserves a newer reservation")
	javaHTTP1Send(a)
	require.Equal(t, 1, javaHTTP1MapSize(t, httpRequests), "the delayed plaintext reached the HTTP parser")
	require.Equal(t, 1, javaHTTP1MapSize(t, reservations), "a mismatching plaintext request preserves B")
	javaHTTP1Data(a, javaHTTP1ReceiveOp, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	javaHTTP1Send(b)
	require.Zero(t, javaHTTP1MapSize(t, reservations), "B's matching plaintext consumes B")
	var key BpfPidConnectionInfoT
	var info BpfHttpInfoT
	iterator := httpRequests.Iterate()
	require.True(t, iterator.Next(&key, &info))
	require.NoError(t, iterator.Err())
	traceparentFields := bytes.Split(b[javaHTTP1ValueOffset:javaHTTP1ParentOffset], []byte("-"))
	require.Len(t, traceparentFields, 4)
	require.Equal(t, string(traceparentFields[1]), hex.EncodeToString(info.Tp.TraceId[:]))
	require.Equal(t, string(traceparentFields[2]), hex.EncodeToString(info.Tp.SpanId[:]))
	require.Equal(t, bytes.Repeat([]byte{0x44}, javaHTTP1SpanIDSize), info.Tp.ParentId[:])
	b[0] = javaHTTP1Release
	javaHTTP1Ioctl(b)
	require.Zero(t, javaHTTP1MapSize(t, reservations))

	// Reading the parent succeeds, but writing the returned parent into the
	// read-only second page fails after insertion. The handler must roll back.
	pages, err := unix.Mmap(-1, 0, 2*unix.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, unix.Munmap(pages)) })
	start := unix.Getpagesize() - javaHTTP1ParentOffset
	packet := pages[start : start+javaHTTP1PacketSize]
	copy(packet, javaHTTP1Packet(40002))
	require.NoError(t, unix.Mprotect(pages[unix.Getpagesize():], unix.PROT_READ))
	javaHTTP1Ioctl(packet)
	require.Equal(t, byte(javaHTTP1Reserve), packet[0])
	require.Zero(t, javaHTTP1MapSize(t, reservations), "failed acknowledgment rolls back the insertion")
}

func TestJavaHTTP1ReservationsUnsupported(t *testing.T) {
	objects := loadJavaHTTP1Reservations(t, false)
	reservations := objects.Requests
	packet := javaHTTP1Packet(40000)
	javaHTTP1Ioctl(packet)
	require.Equal(t, byte(javaHTTP1Reserve), packet[0])
	require.Zero(t, javaHTTP1MapSize(t, reservations))
}

func TestJavaHTTP1ReservationSurvivesTraceMapReplacement(t *testing.T) {
	if !supportsJavaHTTP1ReservationCleanup() {
		t.Skip("this test requires CMPXCHG support")
	}
	objects := loadJavaHTTP1Reservations(t, true)
	httpRequests, traces := objects.HTTP, objects.Traces
	conn := BpfPidConnectionInfoT{Pid: uint32(os.Getpid())}
	conn.Conn.S_addr[15] = 1
	conn.Conn.D_addr[15] = 2
	conn.Conn.S_port = 40000
	conn.Conn.D_port = 443
	traceKey := BpfTraceMapKeyT{Conn: conn.Conn, Type: javaHTTP1ClientTraceType}
	traceKey.Conn.D_addr = [16]uint8{}
	traceKey.Conn.D_port = 0
	replacement := BpfTpInfoPidT{Valid: 1}
	replacement.Tp.TraceId[0] = 0xee
	replacement.Tp.SpanId[0] = 0xdd

	// Connection trace state can change on another CPU between reservation
	// adoption and the HTTP continuation. The request must retain its own span.
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
				if err := traces.Put(&traceKey, &replacement); err != nil {
					done <- err
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		require.NoError(t, <-done)
	})
	for range 1000 {
		packet := javaHTTP1Packet(conn.Conn.S_port)
		javaHTTP1Ioctl(packet)
		require.Zero(t, packet[0])
		javaHTTP1Send(packet)
		var info BpfHttpInfoT
		require.NoError(t, httpRequests.Lookup(&conn, &info))
		fields := bytes.Split(packet[javaHTTP1ValueOffset:javaHTTP1ParentOffset], []byte("-"))
		require.Equal(t, string(fields[1]), hex.EncodeToString(info.Tp.TraceId[:]))
		require.Equal(t, string(fields[2]), hex.EncodeToString(info.Tp.SpanId[:]))
		javaHTTP1Data(packet, javaHTTP1ReceiveOp, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}
}

func TestJavaHTTP1ParentAfterUnparsedResponse(t *testing.T) {
	if !supportsJavaHTTP1ReservationCleanup() {
		t.Skip("this test requires CMPXCHG support")
	}
	loadJavaHTTP1Reservations(t, true)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	capture := func() []byte {
		parent := make([]byte, 1+javaHTTP1TraceIDSize+javaHTTP1SpanIDSize+2)
		parent[0] = javaHTTP1Parent
		javaHTTP1Ioctl(parent)
		require.Zero(t, parent[0], "parent capture acknowledged")
		return parent[1 : 1+javaHTTP1TraceIDSize]
	}

	first := javaHTTP1Packet(40000)
	javaHTTP1Data(first, javaHTTP1ReceiveOp, []byte("GET /first HTTP/1.1\r\ntraceparent: 00-11111111111111111111111111111111-2222222222222222-01\r\n\r\n"))
	require.Equal(t, bytes.Repeat([]byte{0x11}, javaHTTP1TraceIDSize), capture())
	javaHTTP1Data(first, javaHTTP1SendOp, []byte("a response without a parsed status line"))

	// A worker can serve another connection after sending an unparsed response.
	// That completed request must not invalidate its next request's parent.
	second := javaHTTP1Packet(40001)
	javaHTTP1Data(second, javaHTTP1ReceiveOp, []byte("GET /second HTTP/1.1\r\ntraceparent: 00-33333333333333333333333333333333-4444444444444444-01\r\n\r\n"))
	require.Equal(t, bytes.Repeat([]byte{0x33}, javaHTTP1TraceIDSize), capture())
}

func TestJavaHTTP1AmbiguousParentSkipsInjection(t *testing.T) {
	if !supportsJavaHTTP1ReservationCleanup() {
		t.Skip("this test requires CMPXCHG support")
	}
	loadJavaHTTP1Reservations(t, true)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Two unanswered server requests on one thread have no unambiguous parent.
	// Returning an acknowledged empty context would invent a new trace instead.
	javaHTTP1Data(javaHTTP1Packet(40000), javaHTTP1ReceiveOp, []byte("GET /first HTTP/1.1\r\n\r\n"))
	javaHTTP1Data(javaHTTP1Packet(40001), javaHTTP1ReceiveOp, []byte("GET /second HTTP/1.1\r\n\r\n"))
	parent := make([]byte, 1+javaHTTP1TraceIDSize+javaHTTP1SpanIDSize+2)
	parent[0] = javaHTTP1Parent
	javaHTTP1Ioctl(parent)
	require.Equal(t, byte(javaHTTP1Parent), parent[0], "an ambiguous capture is not acknowledged")
}
