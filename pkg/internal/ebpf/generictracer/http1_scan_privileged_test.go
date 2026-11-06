// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

func TestHTTP1FragmentedTraceparent(t *testing.T) {
	if !ebpfcommon.SupportsEBPFLoops(slog.Default(), false) {
		t.Skip("fragmented HTTP headers require bpf_loop")
	}
	objects := loadJavaHTTP1ReservationsWithLoops(t, true, true)

	for i, offset := range []int{1020, 4090, 8190, 16*1024 - len("Traceparent: ") - javaHTTP1TraceparentSize} {
		t.Run(strconv.Itoa(offset), func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			const parentID = "fedcba9876543210"
			traceID := fmt.Sprintf("%032x", i+1)
			prefix := "GET /fragmented HTTP/1.1\r\nX-Padding: "
			payload := []byte(prefix + strings.Repeat("a", offset-len(prefix)-2) +
				"\r\nTraceparent: 00-" + traceID + "-" + parentID + "-01\r\n\r\n")
			if offset > 2048 {
				copy(payload[1024:], "GET /padding-value")
			}
			port := uint16(40000 + i)
			connection := javaHTTP1Packet(port)
			const fragmentSize = 512
			for pos := 0; pos < len(payload); pos += fragmentSize {
				javaHTTP1Data(connection, javaHTTP1ReceiveOp, payload[pos:min(pos+fragmentSize, len(payload))])
			}

			var key BpfPidConnectionInfoT
			var info BpfHttpInfoT
			iterator := objects.HTTP.Iterate()
			found := false
			for iterator.Next(&key, &info) {
				if key.Conn.S_port == port {
					found = true
					break
				}
			}
			require.NoError(t, iterator.Err())
			require.True(t, found)
			require.Equal(t, traceID, hex.EncodeToString(info.Tp.TraceId[:]))
			require.Equal(t, parentID, hex.EncodeToString(info.Tp.ParentId[:]))
			require.True(t, strings.HasPrefix(string(info.Buf[:]), "GET /fragmented HTTP/1.1"))
			require.Equal(t, len(payload), int(info.Len))
			require.Zero(t, javaHTTP1MapSize(t, objects.HeaderScans))

			parent := make([]byte, 1+javaHTTP1TraceIDSize+javaHTTP1SpanIDSize+2)
			parent[0] = javaHTTP1Parent
			javaHTTP1Ioctl(parent)
			require.Zero(t, parent[0])
			require.Equal(t, traceID, hex.EncodeToString(parent[1:1+javaHTTP1TraceIDSize]))

			var thread uint64
			var context BpfObiCtxInfoT
			contexts := objects.ThreadContexts.Iterate()
			found = false
			for contexts.Next(&thread, &context) {
				if bytes.Equal(context.SpanId[:], info.Tp.SpanId[:]) {
					require.Equal(t, traceID, hex.EncodeToString(context.TraceId[:]))
					found = true
				}
			}
			require.NoError(t, contexts.Err())
			require.True(t, found, "log correlation must use the adopted trace")

			var auxiliaryKey BpfConnectionInfoPartT
			var auxiliary BpfTpInfoPidT
			auxiliaryTraces := objects.ServerAux.Iterate()
			found = false
			for auxiliaryTraces.Next(&auxiliaryKey, &auxiliary) {
				if bytes.Equal(auxiliary.Tp.SpanId[:], info.Tp.SpanId[:]) {
					require.Equal(t, traceID, hex.EncodeToString(auxiliary.Tp.TraceId[:]))
					found = true
				}
			}
			require.NoError(t, auxiliaryTraces.Err())
			require.True(t, found, "asynchronous propagation must use the adopted trace")
			javaHTTP1Data(connection, javaHTTP1SendOp, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		})
	}
}
