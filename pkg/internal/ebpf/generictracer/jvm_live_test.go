// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && jvm_live

package generictracer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpftracer "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

const (
	jvmLiveServiceName      = "jvm-live"
	jvmLiveServiceNamespace = "integration-test"
	jvmLiveTargetClass      = "OBIJvmRuntimeProbeTarget"
)

func TestJVMRuntimeEventsLiveFromHotSpotProbes(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "live eBPF JVM test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	java := startJVMRuntimeProbeTarget(t)
	events := startJVMRuntimeEventTracer(t, java.pid)

	waitForJVMRuntimeEvents(t, events, java.triggerGC)
}

type jvmRuntimeProbeTarget struct {
	pid       app.PID
	triggerGC func()
}

func startJVMRuntimeProbeTarget(t *testing.T) jvmRuntimeProbeTarget {
	t.Helper()

	java, err := osexec.LookPath("java")
	require.NoError(t, err)
	javac, err := osexec.LookPath("javac")
	require.NoError(t, err)

	targetDir := t.TempDir()
	sourcePath := filepath.Join(targetDir, jvmLiveTargetClass+".java")
	require.NoError(t, os.WriteFile(sourcePath, []byte(jvmRuntimeProbeTargetSource), 0o600))

	out, err := osexec.Command(javac, sourcePath).CombinedOutput()
	require.NoErrorf(t, err, "javac output:\n%s", string(out))

	ctx, cancel := context.WithCancel(context.Background())
	cmd := osexec.CommandContext(ctx, java,
		"-Xms128m",
		"-Xmx128m",
		"-XX:+UseSerialGC",
		"-Xlog:gc",
		"-cp",
		targetDir,
		jvmLiveTargetClass,
	)

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)

	require.NoError(t, cmd.Start())

	stdoutLines := collectProcessLines(t, "java stdout", stdout)
	_ = collectProcessLines(t, "java stderr", stderr)
	waitForProcessLine(t, stdoutLines, "READY", 10*time.Second)

	t.Cleanup(func() {
		_, _ = io.WriteString(stdin, "EXIT\n")
		cancel()
		_ = cmd.Wait()
	})

	return jvmRuntimeProbeTarget{
		pid: app.PID(cmd.Process.Pid),
		triggerGC: func() {
			_, err := io.WriteString(stdin, "GC\n")
			require.NoError(t, err)
		},
	}
}

func collectProcessLines(t *testing.T, name string, r io.Reader) <-chan string {
	t.Helper()

	lines := make(chan string, 100)
	go func() {
		defer close(lines)

		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("%s: %s", name, line)
			lines <- line
		}
		if err := scanner.Err(); err != nil {
			t.Logf("%s scanner stopped: %v", name, err)
		}
	}()
	return lines
}

func waitForProcessLine(t *testing.T, lines <-chan string, want string, timeout time.Duration) {
	t.Helper()

	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-lines:
			require.Truef(t, ok, "process output closed before %q", want)
			if strings.Contains(line, want) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for process line containing %q", want)
		}
	}
}

func startJVMRuntimeEventTracer(
	t *testing.T,
	pid app.PID,
) <-chan []runtimemetrics.RuntimeMetricSnapshot {
	t.Helper()

	cfg := obi.DefaultConfig
	cfg.LogLevel = obi.LogLevelDebug
	cfg.EBPF.BpfDebug = true
	cfg.Metrics.Features = export.FeatureApplicationRuntime
	cfg.JVMRuntimeMetrics.SamplingInterval = 10 * time.Millisecond

	pidsFilter := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.With("component", "jvm-live-pids"), imetrics.NoopReporter{})
	genericTracer := New(pidsFilter, &cfg, imetrics.NoopReporter{})
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.CommonPIDsFilter = pidsFilter

	processTracer := ebpftracer.NewProcessTracer(ebpftracer.Generic, []ebpftracer.Tracer{genericTracer}, &cfg, imetrics.NoopReporter{})
	require.NoError(t, processTracer.Init(eventContext, &cfg))

	runtimeMetrics := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(100))
	events := runtimeMetrics.Subscribe(msg.SubscriberName("jvm-live-test"))
	eventContext.RuntimeMetrics = runtimemetrics.NewQueueSender(runtimeMetrics)

	fileInfo := javaProcessFileInfo(t, pid)
	requireLibJVMMap(t, pid)
	processTracer.AllowPID(pid, fileInfo.Ns(), fileInfo)

	executable, err := link.OpenExecutable(fileInfo.ProExeLinkPath())
	require.NoError(t, err)
	require.NoError(t, processTracer.NewExecutable(executable, &ebpftracer.Instrumentable{
		Type:     svc.InstrumentableJava,
		FileInfo: fileInfo,
	}))

	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		processTracer.Run(runCtx, eventContext, spans)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Log("timed out waiting for JVM runtime ProcessTracer to stop")
		}
		spans.Close()
		runtimeMetrics.Close()
	})

	return events
}

func requireLibJVMMap(t *testing.T, pid app.PID) {
	t.Helper()

	maps, err := procs.FindLibMaps(pid)
	require.NoError(t, err)
	libjvm := procs.LibPath("libjvm.so", maps)
	require.NotNil(t, libjvm, "libjvm.so must be mapped before attaching JVM runtime probes")
}

func javaProcessFileInfo(t *testing.T, pid app.PID) *discexec.FileInfo {
	t.Helper()

	ns, err := procs.FindNamespace(pid)
	require.NoError(t, err)

	procExeLinkPath := fmt.Sprintf("/proc/%d/exe", pid)
	cmdExePath, err := os.Readlink(procExeLinkPath)
	require.NoError(t, err)

	info, err := os.Stat(procExeLinkPath)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)

	return discexec.New(discexec.Init{
		Service: svc.Attrs{
			UID:         svc.UID{Name: jvmLiveServiceName, Namespace: jvmLiveServiceNamespace},
			SDKLanguage: svc.InstrumentableJava,
			Features:    export.FeatureApplicationRuntime,
		},
		CmdExePath:     cmdExePath,
		ProExeLinkPath: procExeLinkPath,
		Pid:            pid,
		Dev:            uint64(stat.Dev),
		Ino:            stat.Ino,
		Ns:             ns,
	})
}

func waitForJVMRuntimeEvents(
	t *testing.T,
	events <-chan []runtimemetrics.RuntimeMetricSnapshot,
	triggerGC func(),
) {
	t.Helper()

	var (
		received           []runtimemetrics.RuntimeMetricSnapshot
		seenHeapMemoryPool bool
	)

	triggerGC()
	retry := time.NewTicker(500 * time.Millisecond)
	defer retry.Stop()

	deadline := time.After(30 * time.Second)
	for {
		select {
		case batch := <-events:
			received = append(received, batch...)
			for _, snapshot := range batch {
				require.NotNil(t, snapshot.JVM)
				assert.Equal(t, jvmLiveServiceName, snapshot.Service.UID.Name)
				assert.Equal(t, jvmLiveServiceNamespace, snapshot.Service.UID.Namespace)
				assert.NotZero(t, snapshot.PID)
				assert.NotZero(t, snapshot.Time)

				if snapshot.JVM.Kind == jvmruntime.JVMMetricMemoryUsed &&
					snapshot.JVM.PoolName != "" &&
					snapshot.JVM.MemoryType == jvmruntime.JVMMemoryTypeHeap {
					seenHeapMemoryPool = true
					assert.Equal(t, jvmruntime.JVMMemoryTypeHeap, snapshot.JVM.MemoryType)
					assert.Positive(t, snapshot.JVM.ValueBytes)
				}
				if strings.HasPrefix(string(snapshot.JVM.Kind), "jvm.memory.") && snapshot.JVM.PoolName != "" {
					assert.NotEmpty(t, snapshot.JVM.MemoryType)
					assert.NotEmpty(t, snapshot.JVM.GCPhase)
				}
			}
			if seenHeapMemoryPool {
				return
			}
		case <-retry.C:
			triggerGC()
		case <-deadline:
			require.Failf(t,
				"timed out waiting for JVM runtime events",
				"seenHeapMemoryPool=%t received=%+v",
				seenHeapMemoryPool,
				received,
			)
		}
	}
}

const jvmRuntimeProbeTargetSource = `
import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class OBIJvmRuntimeProbeTarget {
    public static void main(String[] args) throws Exception {
        System.out.println("READY");
        System.out.flush();

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = reader.readLine()) != null) {
            if ("GC".equals(line)) {
                byte[][] allocations = new byte[64][];
                for (int i = 0; i < allocations.length; i++) {
                    allocations[i] = new byte[1024 * 1024];
                }
                allocations = null;
                for (int i = 0; i < 3; i++) {
                    System.gc();
                    Thread.sleep(50);
                }
                System.out.println("DONE");
                System.out.flush();
            } else if ("EXIT".equals(line)) {
                return;
            }
        }
    }
}
`
