// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

// Exercise the restricted helper path on private sockets, including the actual wire bytes.
func TestSKMsgCompatibilityTraffic(t *testing.T) {
	if os.Getenv("OBI_TEST_SKMSG_COMPAT") != "1" {
		t.Skip("set OBI_TEST_SKMSG_COMPAT=1 to exercise SK_MSG compatibility")
	}
	objs := loadTPInjectorObjects(t, map[string]any{
		"sk_msg_tracing_helpers": false,
		"filter_pids":            int32(1),
		"inject_flags":           uint32(1),
		"max_transaction_time":   uint64(time.Minute),
	})
	word := uint32(os.Getpid() / 64)
	require.NoError(t, objs.InstrumentedPids.Put(word, uint64(1)<<uint(os.Getpid()%64)))
	start, err := link.Kprobe("sock_sendmsg", objs.ObiKprobeSkmsgSender, nil)
	require.NoError(t, err)
	t.Cleanup(func() { start.Close() })
	end, err := link.Kretprobe("sock_sendmsg", objs.ObiKretprobeSkmsgSender, nil)
	require.NoError(t, err)
	t.Cleanup(func() { end.Close() })
	attach := link.RawAttachProgramOptions{Target: objs.SockDir.FD(), Program: objs.ObiPacketExtender, Attach: ebpf.AttachSkMsgVerdict}
	require.NoError(t, link.RawAttachProgram(attach))
	t.Cleanup(func() { link.RawDetachProgram(link.RawDetachProgramOptions(attach)) }) //nolint:errcheck
	for _, parent := range []string{"", "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"} {
		t.Run(parent, func(t *testing.T) {
			c := newGuardConn(t, objs)
			require.NoError(t, c.peer.SetReadDeadline(time.Now().Add(2*time.Second)))
			wire := "GET /compat HTTP/1.1\r\nHost: test\r\n"
			if parent != "" {
				wire += "Traceparent: " + parent + "\r\n"
			}
			c.send([]byte(wire + "\r\n"))
			req, err := http.ReadRequest(bufio.NewReader(c.peer))
			require.NoError(t, err)
			require.Equal(t, "/compat", req.URL.Path)
			require.Len(t, req.Header.Values("Traceparent"), 1)
			if parent != "" {
				require.Equal(t, parent, req.Header.Get("Traceparent"))
			}
		})
	}
	t.Run("HTTP2", func(t *testing.T) {
		c := newGuardConn(t, objs)
		require.NoError(t, c.peer.SetReadDeadline(time.Now().Add(2*time.Second)))
		c.send(h2Preface, h2EmptySettings)
		preface := make([]byte, len(h2Preface)+len(h2EmptySettings))
		_, err := io.ReadFull(c.peer, preface)
		require.NoError(t, err)
		require.Equal(t, bytes.Join([][]byte{h2Preface, h2EmptySettings}, nil), preface)
		frame := []byte{0, 0, 3, 1, 5, 0, 0, 0, 1, 0x82, 0x86, 0x84}
		c.send(frame)
		got := make([]byte, len(frame)+h2ProbeHPACKLen)
		_, err = io.ReadFull(c.peer, got)
		require.NoError(t, err)
		require.Equal(t, byte(3+h2ProbeHPACKLen), got[2])
		fields, err := hpack.NewDecoder(4096, nil).DecodeFull(got[9:])
		require.NoError(t, err)
		parents := 0
		for _, field := range fields {
			if field.Name == "traceparent" {
				parents++
				require.Len(t, field.Value, 55)
			}
		}
		require.Equal(t, 1, parents)
	})
	t.Run("HTTP2MultipleStreams", func(t *testing.T) {
		c := newGuardConn(t, objs)
		require.NoError(t, c.peer.SetReadDeadline(time.Now().Add(2*time.Second)))
		c.send(h2Preface, h2EmptySettings)
		first := []byte{0, 0, 3, 1, 5, 0, 0, 0, 1, 0x82, 0x86, 0x84}
		second := append([]byte(nil), first...)
		second[8] = 3
		c.send(first, second)
		requireInjected(t, c, 2)
	})
	t.Run("UnselectedSender", func(t *testing.T) {
		require.NoError(t, objs.InstrumentedPids.Put(word, uint64(0)))
		c := newGuardConn(t, objs)
		require.NoError(t, c.peer.SetReadDeadline(time.Now().Add(2*time.Second)))
		c.send([]byte("GET /unselected HTTP/1.1\r\nHost: test\r\n\r\n"))
		requirePristine(t, c)
	})
}

func TestSockhashReceiveSemantics(t *testing.T) {
	want := os.Getenv("OBI_TEST_SOCKHASH_RECEIVE")
	if want != "safe" && want != "broken" {
		t.Skip("set OBI_TEST_SOCKHASH_RECEIVE=safe or broken")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	err := sockhashReceiveProbe()
	if want == "broken" {
		require.ErrorContains(t, err, "empty connected socket returned n=0 without EAGAIN")
	} else {
		require.NoError(t, err)
	}
	t.Logf("sockhash receive probe: %v", err)
}
