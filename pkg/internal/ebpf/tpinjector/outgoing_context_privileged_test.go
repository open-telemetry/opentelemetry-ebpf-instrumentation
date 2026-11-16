// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
)

// A different process (such as kubelet) can reuse both ports in the node-wide
// outgoing map. Exercise actual sk_msg injection and the bytes received by HTTP.
func TestOutgoingContextProcessIsolation(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		own, monitored, valid bool
	}{
		{"unmonitored_probe", false, false, true},
		{"monitored_client", false, true, true},
		{"foreign_tls_marker", false, false, false},
		{"own_uprobe_context_without_pid_filter", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filter := int32(1)
			if tc.monitored {
				filter = 0
			}
			objs := loadTPInjectorObjects(t, map[string]any{
				"filter_pids": filter, "inject_flags": uint32(3),
			})
			attach := link.RawAttachProgramOptions{
				Target: objs.SockDir.FD(), Program: objs.ObiPacketExtender,
				Attach: ebpf.AttachSkMsgVerdict,
			}
			require.NoError(t, link.RawAttachProgram(attach))
			t.Cleanup(func() { require.NoError(t, link.RawDetachProgram(link.RawDetachProgramOptions(attach))) })
			c := newGuardConn(t, objs)
			local := c.client.LocalAddr().(*net.TCPAddr)
			remote := c.client.RemoteAddr().(*net.TCPAddr)
			conn := BpfConnectionInfoT{S_port: uint16(local.Port), D_port: uint16(remote.Port)}
			sortConnectionInfo(&conn)
			key := BpfEgressKeyT{S_port: conn.S_port, D_port: conn.D_port}
			old := BpfTpInfoPidT{Pid: uint32(os.Getpid() + 1), Valid: 1, ReqType: 8}
			old.Tp.Ts = 1
			old.Tp.Flags = 1
			copy(old.Tp.TraceId[:], bytes.Repeat([]byte{0x11}, 16))
			copy(old.Tp.SpanId[:], bytes.Repeat([]byte{0x22}, 8))
			if tc.own {
				old.Pid = uint32(os.Getpid())
			}
			if !tc.valid {
				old.Valid = 0
			}
			require.NoError(t, objs.OutgoingTraceMap.Update(key, old, ebpf.UpdateAny))
			payload := []byte("GET /healthz HTTP/1.1\r\nHost: localhost\r\nUser-Agent: kube-probe/1.35\r\n\r\n")
			c.send(payload)
			got := c.received()
			tid := []byte(hex.EncodeToString(old.Tp.TraceId[:]))
			if tc.own {
				require.Contains(t, string(got), string(tid), "an owning uprobe may propagate even outside the generic pid filter")
				return
			}
			require.NotContains(t, string(got), string(tid), "a reused port pair must never inject another process's context")
			if !tc.monitored {
				require.Equal(t, payload, got, "unmonitored probes remain unchanged")
				var stored BpfTpInfoPidT
				require.ErrorIs(t, objs.SkTpInfoPidMap.Lookup(uint32(c.fd), &stored), ebpf.ErrKeyNotExist,
					"foreign context must not be scheduled into TCP options either")
				require.NoError(t, objs.OutgoingTraceMap.Lookup(key, &stored))
				require.Equal(t, old, stored, "a bystander must not consume, modify, or delete another process's entry")
			} else {
				require.Contains(t, string(got), "Traceparent: ", "monitored clients still get fresh context")
			}
		})
	}
}
