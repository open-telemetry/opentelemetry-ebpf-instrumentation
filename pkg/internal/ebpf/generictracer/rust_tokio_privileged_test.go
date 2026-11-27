// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	ebpftracer "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestRustTokioTaskInheritance(t *testing.T) {
	binary := os.Getenv("OBI_RUST_TOKIO_BINARY")
	if binary == "" {
		t.Skip("requires the rusttokio fixture")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	for _, runtime := range []string{"current_thread", "multi_thread"} {
		t.Run(runtime, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary)
			if runtime == "current_thread" {
				cmd.Env = append(os.Environ(), "OBI_RUST_CURRENT_THREAD=1")
			}
			stdout, err := cmd.StdoutPipe()
			require.NoError(t, err)
			cmd.Stderr = os.Stderr
			require.NoError(t, cmd.Start())
			defer func() { cancel(); _ = cmd.Wait() }()
			output := bufio.NewScanner(stdout)
			require.True(t, output.Scan())
			address, ok := strings.CutPrefix(output.Text(), "READY ")
			require.True(t, ok)

			cfg := obi.DefaultConfig
			cfg.Rust.Enabled = true
			cfg.EBPF.BPFFSPath = privateBPFFSPath(t, cfg.EBPF.BPFFSPath)
			cfg.EBPF.TrackRequestHeaders = true
			pids := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), rustTestReporter{})
			tracer := New(pids, &cfg, rustTestReporter{})
			process := ebpftracer.NewProcessTracer(ebpftracer.Generic, []ebpftracer.Tracer{tracer}, &cfg, rustTestReporter{})
			events := ebpfcommon.NewEBPFEventContext()
			events.CommonPIDsFilter = pids
			require.NoError(t, process.Init(events, &cfg))
			pid := app.PID(cmd.Process.Pid)
			fi := rustProcessFileInfo(t, pid)
			process.AllowPID(pid, fi.Ns(), fi)
			executable, err := fi.OpenExecutable()
			require.NoError(t, err)
			defer executable.Close()
			require.NoError(t, process.NewExecutableFile(executable, &ebpftracer.Instrumentable{Type: svc.InstrumentableRust, FileInfo: fi}))
			var capabilities BpfRustCapabilitiesT
			require.NoError(t, tracer.bpfObjects.RustCapabilities.Lookup(uint32(pid), &capabilities))
			require.EqualValues(t, 1, capabilities.TaskContext)

			runCtx, stop := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				process.Run(runCtx, events, msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100)))
			}()
			defer func() { stop(); <-done }()

			conn, err := net.DialTimeout("tcp", address, 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()
			const traceID = "00000000000000000000000000000042"
			_, err = io.WriteString(conn, "GET /spawn HTTP/1.1\r\nHost: localhost\r\ntraceparent: 00-"+traceID+"-1111111111111111-01\r\n\r\n")
			require.NoError(t, err)
			require.True(t, output.Scan())
			require.Equal(t, "CHILD", output.Text())
			var parent, child BpfTpInfoPidT
			var key BpfRustTaskKeyT
			var value BpfTpInfoPidT
			tasks := tracer.bpfObjects.RustTaskContext.Iterate()
			for tasks.Next(&key, &value) {
				if key.Pid != uint32(pid) || fmt.Sprintf("%x", value.Tp.TraceId) != traceID {
					continue
				}
				if value.ResponseSent != 0 {
					child = value
				} else {
					parent = value
				}
			}
			require.NoError(t, tasks.Err())
			require.NotZero(t, parent.Valid, "server task must own the incoming trace")
			require.NotZero(t, child.Valid, "spawned task must inherit the server context")
			require.Equal(t, parent.Tp.SpanId, child.Tp.SpanId)
		})
	}
}
