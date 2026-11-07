// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

func TestHTTP1ExistingTraceparentScan(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	const traceID = "0123456789abcdef0123456789abcdef"
	const spanID = "fedcba9876543210"
	const header = "Traceparent: 00-" + traceID + "-" + spanID + "-01\r\n"
	const requestPrefix = "GET / HTTP/1.1\r\nX-Padding: "
	for _, tc := range []struct {
		name      string
		padding   int
		invalid   bool
		unsampled bool
		modern    bool
		fragment  int
		absent    bool
		// the application's traceparent arrives after the cork limit, so OBI adds its own
		capped bool
		// sent as is: a request line with no header block must not be held back
		request string
	}{
		{name: "first_chunk"},
		{name: "later_chunk", padding: 1100},
		{name: "malformed_value", invalid: true},
		{name: "unsampled", unsampled: true},
		{name: "large_single_write", modern: true, padding: 12 * 1024},
		{name: "large_fragmented", modern: true, padding: 12 * 1024, fragment: 2048},
		{name: "exact_limit", modern: true, padding: 16*1024 - len(header) - len(requestPrefix), fragment: 2048},
		{name: "malformed_fragmented", modern: true, padding: 8 * 1024, fragment: 2048, invalid: true},
		{name: "unsampled_fragmented", modern: true, padding: 8 * 1024, fragment: 2048, unsampled: true},
		{name: "inject_short", modern: true, absent: true},
		{name: "inject_fragmented", modern: true, absent: true, padding: 12 * 1024, fragment: 2048},
		{name: "inject_at_limit", modern: true, absent: true, padding: 18 * 1024},
		{name: "inject_after_cork_limit", modern: true, absent: true, padding: 12 * 1024, fragment: 137},
		{name: "existing_after_cork_limit", modern: true, capped: true, padding: 12 * 1024, fragment: 137},
		{name: "unversioned_request_line", modern: true, request: "GET /index.html\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.modern && !ebpfcommon.SupportsEBPFLoops(slog.Default(), false) {
				t.Skip("fragmented HTTP headers require bpf_loop")
			}
			spec, err := LoadBpf()
			require.NoError(t, err)
			if !tc.modern {
				spec.Programs[BpfProgObiPacketExtenderFindExistingTp] = spec.Programs[BpfProgObiPacketExtenderFindExistingTpLegacy]
				spec.Programs[BpfProgObiPacketExtenderFindExistingTp].Name = BpfProgObiPacketExtenderFindExistingTp
			}
			ebpfcommon.FixupSpec(spec, false)
			require.NoError(t, spec.Variables["g_bpf_loop_enabled"].Set(tc.modern))
			require.NoError(t, spec.Variables["inject_flags"].Set(uint32(1)))
			require.NoError(t, spec.Variables["filter_pids"].Set(int32(0)))
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
				Target: sockets.FD(), Program: collection.Programs[BpfProgObiPacketExtender],
				Attach: ebpf.AttachSkMsgVerdict,
			}
			require.NoError(t, link.RawAttachProgram(attach))
			t.Cleanup(func() { require.NoError(t, link.RawDetachProgram(link.RawDetachProgramOptions(attach))) })

			client, peer, err := h2ProbeTCPPair()
			require.NoError(t, err)
			require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
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
			if tc.absent {
				value = ""
			}
			payload := []byte(requestPrefix + strings.Repeat("a", tc.padding) + "\r\n" + value + "\r\n")
			if tc.request != "" {
				payload = []byte(tc.request)
			}
			injected := tc.absent || tc.capped
			wantTraceparents := 1
			if tc.capped {
				wantTraceparents = 2
			}
			if tc.fragment > 0 {
				for pos := 0; pos < len(payload)-10; {
					end := min(pos+tc.fragment, len(payload)-10)
					require.NoError(t, h2ProbeWrite(fd, payload[pos:end]))
					pos = end
				}
				require.NoError(t, h2ProbeWrite(fd, payload[len(payload)-10:]))
			} else {
				require.NoError(t, h2ProbeWrite(fd, payload))
			}
			wantSize := len(payload)
			if injected {
				wantSize += len(header)
			}
			received := make([]byte, wantSize)
			_, err = io.ReadFull(peer, received)
			require.NoError(t, err)
			if injected {
				headers, _, _ := strings.Cut(string(received), "\r\n\r\n")
				require.Equal(t, wantTraceparents, strings.Count(strings.ToLower(headers), "traceparent:"))
				return
			}
			require.Equal(t, payload, received)
			if tc.request != "" {
				return
			}

			var got BpfTpInfoPidT
			source := uint16(client.LocalAddr().(*net.TCPAddr).Port)
			dest := uint16(client.RemoteAddr().(*net.TCPAddr).Port)
			if source < dest {
				source, dest = dest, source
			}
			err = collection.Maps[BpfMapOutgoingTraceMap].Lookup(BpfEgressKeyT{S_port: source, D_port: dest}, &got)
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
