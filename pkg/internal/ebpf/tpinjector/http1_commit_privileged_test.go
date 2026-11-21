// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
)

func TestHTTP1TCPOnlyContextIsCommitted(t *testing.T) {
	objs := loadSocketGuardHarnessWith(t, map[string]any{
		"filter_pids": int32(0), "inject_flags": uint32(config.ContextPropagationTCP),
	})
	conn := newGuardConn(t, objs)
	payload := []byte("GET /tcp-only HTTP/1.1\r\nHost: localhost\r\n\r\n")
	conn.send(payload)
	require.Equal(t, payload, conn.received())

	var outgoing, tcp BpfTpInfoPidT
	require.NoError(t, objs.OutgoingTraceMap.Lookup(conn.egressKey(0), &outgoing))
	require.Equal(t, uint8(1), outgoing.Written, "generic capture must adopt the context scheduled for TCP propagation")
	require.NoError(t, objs.SkTpInfoPidMap.Lookup(uint32(conn.fd), &tcp))
	require.Equal(t, tcp.Tp, outgoing.Tp)
}
