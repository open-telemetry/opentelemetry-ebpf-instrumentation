// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
)

const (
	wireSizePayload = 64 << 20
	// Ethernet + IPv4 without options + TCP with timestamps
	wireSizeSegHeader = 14 + 20 + 32
)

var wireSizeCases = []struct {
	name string
	// IPv4 options the client sends in every packet, which move the TCP header further from the
	// start of the IPv4 header
	ipOptions []byte
}{
	{"no-ip-options", nil},
	// three No Operation options and an End of Options List, padding the header to 24 bytes
	{"ip-options", []byte{1, 1, 1, 0}},
}

func TestWireSize_SocketFilter(t *testing.T) {
	for _, c := range wireSizeCases {
		t.Run(c.name, func(t *testing.T) {
			if rerunInNewNetNS(t) {
				return
			}
			setUpLoopback(t)
			// loopback hands every packet to the socket twice, as it is sent and as it is received,
			// and both copies have the same flow key
			assertWireSize(t, newSockFetcher(t, config.MapReaderAuto), 2, c.ipOptions)
		})
	}
}

func TestWireSize_TCEgress(t *testing.T) {
	for _, c := range wireSizeCases {
		t.Run(c.name, func(t *testing.T) {
			if rerunInNewNetNS(t) {
				return
			}
			setUpLoopback(t)
			assertWireSize(t, newTCFetcher(t, false, true, config.MapReaderAuto), 1, c.ipOptions)
		})
	}
}

func TestWireSize_TCIngress(t *testing.T) {
	for _, c := range wireSizeCases {
		t.Run(c.name, func(t *testing.T) {
			if rerunInNewNetNS(t) {
				return
			}
			setUpLoopback(t)
			assertWireSize(t, newTCFetcher(t, true, false, config.MapReaderAuto), 1, c.ipOptions)
		})
	}
}

// sends a known amount of TCP data over loopback and checks that the fetcher counts one packet and
// one set of headers per segment the kernel sent, for each copy of the packet the hooks see
func assertWireSize(t *testing.T, fetcher *flowFetcher, copies uint64, ipOptions []byte) {
	ln, err := net.Listen("tcp4", "127.0.0.2:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	received := make(chan int64, 1)
	go func() {
		srv, err := ln.Accept()
		if err != nil {
			received <- -1
			return
		}
		defer srv.Close()
		n, _ := io.Copy(io.Discard, srv)
		received <- n
	}()

	dialer := loopbackDialer
	dialer.Control = func(_, _ string, c syscall.RawConn) error {
		var optErr error
		if err := c.Control(func(fd uintptr) {
			if len(ipOptions) > 0 {
				optErr = unix.SetsockoptString(int(fd), unix.IPPROTO_IP, unix.IP_OPTIONS, string(ipOptions))
			}
		}); err != nil {
			return err
		}
		return optErr
	}
	conn, err := dialer.Dial("tcp4", ln.Addr().String())
	require.NoError(t, err)
	client := conn.(*net.TCPConn)
	buf := make([]byte, 64<<10)
	for sent := 0; sent < wireSizePayload; sent += len(buf) {
		_, err := client.Write(buf)
		require.NoError(t, err)
	}
	require.NoError(t, client.CloseWrite())
	require.Equal(t, int64(wireSizePayload), <-received)

	raw, err := client.SyscallConn()
	require.NoError(t, err)
	var info *unix.TCPInfo
	var infoErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}))
	require.NoError(t, infoErr)
	clientPort := uint16(client.LocalAddr().(*net.TCPAddr).Port)
	serverPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	client.Close()

	// retransmitted segments are on the wire too: tcpi_bytes_sent (Linux 4.19+) counts their payload
	payload := info.Bytes_sent
	if payload == 0 {
		require.Zero(t, info.Total_retrans)
		payload = wireSizePayload
	}
	segs := uint64(info.Segs_out)
	// TSO/GRO only merge segments when there are many of them
	require.Greater(t, segs, uint64(wireSizePayload/loopbackMTU))
	wireBytes := payload + segs*(wireSizeSegHeader+uint64(len(ipOptions)))

	var packets, bytes uint64
	for id, m := range fetcher.LookupAndDeleteMap() {
		if id.SrcPort == clientPort && id.DstPort == serverPort {
			packets += uint64(m.Packets)
			bytes += m.Bytes
		}
	}
	t.Logf("counted %d packets, %d bytes; the kernel sent %d segments, %d bytes on the wire",
		packets, bytes, segs, wireBytes)

	// the SYN and the FIN carry slightly different headers than data segments
	assert.InEpsilon(t, float64(copies*segs), float64(packets), 0.001, "packets")
	assert.InEpsilon(t, float64(copies*wireBytes), float64(bytes), 0.001, "bytes")
}
