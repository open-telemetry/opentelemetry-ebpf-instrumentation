// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
)

// Keep sockops confined to this process, following the tpinjector test harness.
func javaHTTP1TCPCgroup(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	var current string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			current = filepath.Join("/sys/fs/cgroup", path)
			break
		}
	}
	require.NotEmpty(t, current, "cgroup v2 is required")
	path := filepath.Join(current, fmt.Sprintf("obi-java-http1-tcp-%d", os.Getpid()))
	require.NoError(t, os.Mkdir(path, 0o755))
	pid := []byte(strconv.Itoa(os.Getpid()))
	t.Cleanup(func() {
		require.NoError(t, os.WriteFile(filepath.Join(current, "cgroup.procs"), pid, 0o644))
		require.NoError(t, os.Remove(path))
	})
	require.NoError(t, os.WriteFile(filepath.Join(path, "cgroup.procs"), pid, 0o644))
	return path
}

func TestJavaHTTP1ReservationPreservesTCPOptions(t *testing.T) {
	if !ebpfcommon.SupportsJavaHTTP1ReservationCleanup() {
		t.Skip("this test requires CMPXCHG support")
	}
	java := loadJavaHTTP1Reservations(t, true)
	cgroup := javaHTTP1TCPCgroup(t)
	spec, err := tpinjector.LoadBpf()
	require.NoError(t, err)
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	require.NoError(t, ebpfconvenience.RewriteConstants(spec, map[string]any{
		"filter_pids": int32(0),
		// k_inject_http_headers | k_inject_tcp_options: context_propagation=all.
		"inject_flags": uint32(1<<0 | 1<<1),
	}))
	injector, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"outgoing_trace_map":     java.Outgoing,
			"active_ssl_connections": java.SSL,
		},
	})
	require.NoError(t, err)
	t.Cleanup(injector.Close)
	sockops, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroup, Attach: ebpf.AttachCGroupSockOps,
		Program: injector.Programs[tpinjector.BpfProgObiSockmapTracker],
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sockops.Close()) })
	attach := link.RawAttachProgramOptions{
		Target:  injector.Maps[tpinjector.BpfMapSockDir].FD(),
		Program: injector.Programs[tpinjector.BpfProgObiPacketExtender], Attach: ebpf.AttachSkMsgVerdict,
	}
	require.NoError(t, link.RawAttachProgram(attach))
	t.Cleanup(func() { require.NoError(t, link.RawDetachProgram(link.RawDetachProgramOptions(attach))) })

	headersReceived := make(chan []string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersReceived <- r.Header.Values("Traceparent")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsConfig.NextProtos = []string{"http/1.1"}
	client, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", server.Listener.Addr().String(), tlsConfig)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	local, remote := client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr)
	packet := javaHTTP1Packet(uint16(local.Port))
	copy(packet[javaHTTP1SourceAddress:javaHTTP1DestinationAddress], local.IP.To16())
	copy(packet[javaHTTP1DestinationAddress:javaHTTP1SourcePort], remote.IP.To16())
	binary.NativeEndian.PutUint16(packet[javaHTTP1DestinationPort:], uint16(remote.Port))
	// The injected value lies beyond the downstream 1 KiB header scanner.
	binary.NativeEndian.PutUint32(packet[javaHTTP1LengthField:], 2*1024)
	copy(packet[javaHTTP1ParentOffset:javaHTTP1ParentOffset+javaHTTP1TraceIDSize], bytes.Repeat([]byte{0x11}, javaHTTP1TraceIDSize))
	copy(packet[javaHTTP1ParentOffset+javaHTTP1TraceIDSize:javaHTTP1ParentFlags], bytes.Repeat([]byte{0x22}, javaHTTP1SpanIDSize))
	packet[javaHTTP1ParentFlags], packet[javaHTTP1ParentStatus] = 1, 1
	javaHTTP1Ioctl(packet)
	require.Zero(t, packet[0], "reservation acknowledged")
	javaHTTP1Send(packet)
	require.Zero(t, javaHTTP1MapSize(t, java.Requests), "plaintext adopted the reservation")
	_, err = client.Write(javaHTTP1Headers(packet))
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	value := string(packet[javaHTTP1ValueOffset:javaHTTP1ParentOffset])
	require.Equal(t, []string{value}, <-headersReceived, "TLS delivers exactly the injected header")

	// This map is populated by parsing the TCP option at the receiving socket,
	// independently of the HTTP header and generic HTTP parser.
	var connection tpinjector.BpfConnectionInfoT
	var incoming tpinjector.BpfTpInfoPidT
	iterator := injector.Maps[tpinjector.BpfMapIncomingTraceMap].Iterate()
	require.True(t, iterator.Next(&connection, &incoming), "the receiver must observe the TCP option in all mode")
	require.NoError(t, iterator.Err())
	fields := strings.Split(value, "-")
	require.Equal(t, fields[1], hex.EncodeToString(incoming.Tp.TraceId[:]))
	require.Equal(t, fields[2], hex.EncodeToString(incoming.Tp.SpanId[:]))
	require.Equal(t, fields[3], hex.EncodeToString([]byte{incoming.Tp.Flags}))
	require.ElementsMatch(t, []uint16{uint16(local.Port), uint16(remote.Port)}, []uint16{connection.S_port, connection.D_port})
}
