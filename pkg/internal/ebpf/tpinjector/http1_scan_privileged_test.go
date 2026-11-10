// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

func TestHTTP1ExistingTraceparentScan(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	const traceID = "0123456789abcdef0123456789abcdef"
	const spanID = "fedcba9876543210"
	const header = "Traceparent: 00-" + traceID + "-" + spanID + "-01\r\n"
	for _, tc := range []struct {
		name      string
		padding   int
		invalid   bool
		unsampled bool
	}{
		{name: "first_chunk"},
		{name: "later_chunk", padding: 1100},
		{name: "malformed_value", invalid: true},
		{name: "unsampled", unsampled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := LoadBpf()
			require.NoError(t, err)
			require.NoError(t, spec.Variables["inject_flags"].Set(uint32(0)))
			for _, m := range spec.Maps {
				m.Pinning = ebpf.PinNone
				if m.MaxEntries == 0 {
					switch m.Type {
					case ebpf.RingBuf:
						m.MaxEntries = uint32(os.Getpagesize())
					case ebpf.SkStorage, ebpf.InodeStorage, ebpf.TaskStorage, ebpf.CgroupStorage:
					default:
						m.MaxEntries = 1
					}
				}
			}
			collection, err := ebpf.NewCollection(spec)
			require.NoError(t, err)
			t.Cleanup(collection.Close)
			sockets, err := ebpf.NewMap(&ebpf.MapSpec{
				Type: ebpf.SockMap, KeySize: 4, ValueSize: 4, MaxEntries: 1,
			})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, sockets.Close()) })
			attach := link.RawAttachProgramOptions{
				Target: sockets.FD(), Program: collection.Programs[BpfProgObiPacketExtenderFindExistingTp],
				Attach: ebpf.AttachSkMsgVerdict,
			}
			require.NoError(t, link.RawAttachProgram(attach))
			t.Cleanup(func() { require.NoError(t, link.RawDetachProgram(link.RawDetachProgramOptions(attach))) })

			client, peer, err := h2ProbeTCPPair()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, client.Close()) })
			t.Cleanup(func() { require.NoError(t, peer.Close()) })
			fd, err := h2ProbeSocketFD(client)
			require.NoError(t, err)
			require.NoError(t, sockets.Put(uint32(0), uint32(fd)))

			value := header
			if tc.invalid {
				value = strings.Replace(header, traceID+"-", traceID+"x", 1)
			}
			wantFlags := uint8(1)
			if tc.unsampled {
				value = strings.Replace(header, "-01\r\n", "-00\r\n", 1)
				wantFlags = 0
			}
			payload := []byte("GET / HTTP/1.1\r\nX-Padding: " + strings.Repeat("a", tc.padding) + "\r\n" + value + "\r\n")
			require.NoError(t, h2ProbeWrite(fd, payload))
			received := make([]byte, len(payload))
			_, err = io.ReadFull(peer, received)
			require.NoError(t, err)
			require.Equal(t, payload, received)

			var got BpfTpInfoPidT
			err = collection.Maps[BpfMapOutgoingTraceMap].Lookup(BpfEgressKeyT{}, &got)
			if tc.invalid {
				require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
				return
			}
			require.NoError(t, err)
			require.Equal(t, traceID, hex.EncodeToString(got.Tp.TraceId[:]))
			require.Equal(t, spanID, hex.EncodeToString(got.Tp.SpanId[:]))
			require.Equal(t, wantFlags, got.Tp.Flags)
			require.Equal(t, uint8(1), got.Valid)
			require.Equal(t, uint8(1), got.Written)
		})
	}
}
