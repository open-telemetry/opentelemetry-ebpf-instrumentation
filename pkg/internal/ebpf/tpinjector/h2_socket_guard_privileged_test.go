// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
)

// sk_h2_conn_flag values (k_h2_sock_* in bpf/tpinjector/tpinjector.c)
const (
	h2SockNone      uint8 = 0
	h2SockConfirmed uint8 = 2
	h2SockRejected  uint8 = 3
	h2SockProbation uint8 = 4
)

// EPHEMERAL_PORT_MIN in bpf/common/protocol_defs.h
const ephemeralPortMin = 32768

var (
	h2Preface       = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h2EmptySettings = []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}
	// connection-level WINDOW_UPDATE, increment 4096
	h2WindowUpdate = []byte{0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0x10, 0}
	// yamux header: version 0, window update, SYN, stream 3, length 20
	yamuxHeader = []byte{0, 1, 0, 1, 0, 0, 0, 3, 0, 0, 0, 20}
	// the 4-byte length prefix the yamux test component writes before each body
	lengthPrefix = []byte{0, 0, 0, 20}
	// TLS 1.2+ application data record with an 8-byte body
	tlsRecord = []byte{0x17, 3, 3, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}
)

// Loads tpinjector and runs its sk_msg entry program on every socket added to
// sock_dir. The test adds its client sockets by hand, so no cgroup or sockops
// attach is needed, and nothing but the test's own connections is touched.
func loadSocketGuardHarness(t *testing.T) *BpfObjects {
	objs := loadTPInjectorObjects(t, nil)

	attach := link.RawAttachProgramOptions{
		Target:  objs.SockDir.FD(),
		Program: objs.ObiPacketExtender,
		Attach:  ebpf.AttachSkMsgVerdict,
	}
	require.NoError(t, link.RawAttachProgram(attach))
	t.Cleanup(func() { link.RawDetachProgram(link.RawDetachProgramOptions(attach)) }) //nolint:errcheck

	return objs
}

// One loopback connection whose client side runs through tpinjector. Every
// write is a separate sendmsg, so each one is a separate sk_msg run.
type guardConn struct {
	t      *testing.T
	objs   *BpfObjects
	client *net.TCPConn
	peer   *net.TCPConn
	fd     int
	sent   []byte
}

func newGuardConn(t *testing.T, objs *BpfObjects) *guardConn {
	client, peer, err := h2ProbeTCPPair()
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
		peer.Close()
	})

	fd, err := h2ProbeSocketFD(client)
	require.NoError(t, err)
	require.NoError(t, objs.SockDir.Update(socketCookie(t, client), uint32(fd), ebpf.UpdateAny))

	return &guardConn{t: t, objs: objs, client: client, peer: peer, fd: fd}
}

func (c *guardConn) send(chunks ...[]byte) {
	data := bytes.Join(chunks, nil)
	require.NoError(c.t, h2ProbeWrite(c.fd, data))
	c.sent = append(c.sent, data...)
}

// sk_msg runs inside sendmsg, so the state is final once send returns
func (c *guardConn) state() uint8 {
	var state uint8
	err := c.objs.SkH2ConnFlag.Lookup(uint32(c.fd), &state)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return h2SockNone
	}
	require.NoError(c.t, err)
	return state
}

func (c *guardConn) received() []byte {
	require.NoError(c.t, c.client.CloseWrite())
	got, err := io.ReadAll(c.peer)
	require.NoError(c.t, err)
	return got
}

// Marks the connection as TLS the way the SSL uprobes do. The key is the one
// sk_msg builds: local side as source, pid-stamped, sort_connection_info applied.
func (c *guardConn) markSSL() {
	local := c.client.LocalAddr().(*net.TCPAddr)
	remote := c.client.RemoteAddr().(*net.TCPAddr)

	key := BpfPidConnectionInfoT{Pid: uint32(os.Getpid())}
	copy(key.Conn.S_addr[:], local.IP.To16())
	copy(key.Conn.D_addr[:], remote.IP.To16())
	key.Conn.S_port = uint16(local.Port)
	key.Conn.D_port = uint16(remote.Port)
	sortConnectionInfo(&key.Conn)

	require.NoError(c.t, c.objs.ActiveSslConnections.Update(key, uint64(1), ebpf.UpdateAny))
}

// sort_connection_info in bpf/common/connection_info.h
func sortConnectionInfo(conn *BpfConnectionInfoT) {
	sEphemeral := conn.S_port >= ephemeralPortMin
	dEphemeral := conn.D_port >= ephemeralPortMin

	if sEphemeral && !dEphemeral {
		return
	}
	if (dEphemeral && !sEphemeral) || conn.D_port > conn.S_port {
		conn.S_addr, conn.D_addr = conn.D_addr, conn.S_addr
		conn.S_port, conn.D_port = conn.D_port, conn.S_port
	}
}

func h2DataFrame(streamID uint32) []byte {
	frame := []byte{0, 0, 5, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	return frame
}

func requirePristine(t *testing.T, c *guardConn) {
	require.Equal(t, c.sent, c.received(), "the wire must carry exactly what the client wrote")
}

func requireInjected(t *testing.T, c *guardConn, fields int) {
	got := c.received()
	require.Len(t, got, len(c.sent)+fields*h2ProbeHPACKLen)
	require.Equal(t, fields, bytes.Count(got, []byte("traceparent")))
}

func TestH2SocketGuard(t *testing.T) {
	objs := loadSocketGuardHarness(t)

	confirm := func(t *testing.T) *guardConn {
		c := newGuardConn(t, objs)
		c.send(h2Preface, h2EmptySettings)
		require.Equal(t, h2SockConfirmed, c.state(), "preface + SETTINGS confirms the socket")
		return c
	}

	sniff := func(t *testing.T) *guardConn {
		c := newGuardConn(t, objs)
		c.send(h2ProbeFrame(1), h2DataFrame(1))
		require.Equal(t, h2SockProbation, c.state(), "one sniffed send only puts the socket on probation")
		return c
	}

	// control: proves the harness reaches the injection path at all
	t.Run("confirmed socket is injected", func(t *testing.T) {
		c := confirm(t)
		c.send(h2ProbeFrame(1))
		require.Equal(t, h2SockConfirmed, c.state())
		requireInjected(t, c, 1)
	})

	// The frames are H2-shaped on purpose: record-aligned ciphertext never parses
	// as a frame, so this models a socket classified before its TLS was known.
	t.Run("ssl mark rejects a confirmed socket", func(t *testing.T) {
		c := confirm(t)
		c.markSSL()
		c.send(h2ProbeFrame(1))
		require.Equal(t, h2SockRejected, c.state())
		c.send(h2ProbeFrame(3))
		requirePristine(t, c)
	})

	t.Run("sniffed send is not injected", func(t *testing.T) {
		c := sniff(t)
		requirePristine(t, c)
	})

	rejections := []struct {
		name string
		next []byte
	}{
		{name: "yamux header", next: yamuxHeader},
		{name: "length prefix", next: lengthPrefix},
		{name: "tls record", next: tlsRecord},
	}
	for _, r := range rejections {
		t.Run("probation rejects on "+r.name, func(t *testing.T) {
			c := sniff(t)
			c.send(r.next)
			require.Equal(t, h2SockRejected, c.state())
			c.send(h2ProbeFrame(3))
			require.Equal(t, h2SockRejected, c.state())
			requirePristine(t, c)
		})
	}

	// the walk stops at k_h2_sniff_max_frames (8): a longer send proves nothing either way
	t.Run("probation waits on a send longer than the frame walk", func(t *testing.T) {
		c := sniff(t)
		c.send(bytes.Repeat(h2WindowUpdate, 9))
		require.Equal(t, h2SockProbation, c.state())
		c.send(h2WindowUpdate)
		require.Equal(t, h2SockConfirmed, c.state())
		c.send(h2ProbeFrame(3))
		requireInjected(t, c, 1)
	})

	t.Run("probation confirms on a second send that frames as h2", func(t *testing.T) {
		c := sniff(t)
		c.send(h2WindowUpdate)
		require.Equal(t, h2SockConfirmed, c.state())
		c.send(h2ProbeFrame(3))
		requireInjected(t, c, 1)
	})

	// only the framing decides probation, so legal frames the first sniff refuses confirm too
	legal := []struct {
		name  string
		frame []byte
	}{
		{name: "empty DATA without END_STREAM", frame: []byte{0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{name: "unknown frame type", frame: []byte{0, 0, 4, 0x2b, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}
	for _, l := range legal {
		t.Run("probation confirms on "+l.name, func(t *testing.T) {
			c := sniff(t)
			c.send(l.frame)
			require.Equal(t, h2SockConfirmed, c.state())
			c.send(h2ProbeFrame(3))
			requireInjected(t, c, 1)
		})
	}

	malformed := []struct {
		name  string
		frame func() []byte
	}{
		{name: "even stream id", frame: func() []byte { return h2ProbeFrame(2) }},
		{name: "reserved stream bit", frame: func() []byte {
			f := h2ProbeFrame(1)
			f[5] |= 0x80
			return f
		}},
		{name: "undefined flag", frame: func() []byte {
			f := h2ProbeFrame(1)
			f[4] |= 0x40
			return f
		}},
	}
	for _, m := range malformed {
		t.Run("confirmed socket skips HEADERS with "+m.name, func(t *testing.T) {
			c := confirm(t)
			c.send(m.frame())
			require.Equal(t, h2SockConfirmed, c.state(), "one bad send must not demote a confirmed socket")
			c.send(h2ProbeFrame(5))
			requireInjected(t, c, 1)
		})
	}
}
