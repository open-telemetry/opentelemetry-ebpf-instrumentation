// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package discover

import (
	"context"
	"io"
	"log/slog"
	"os"
	osexec "os/exec"
	"path/filepath"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestExecveDiscovery(t *testing.T) {
	launcher, target := buildExecveRepro(t)
	child := startExecveRepro(t, launcher, target)
	child.expect(t, 'L')
	pid := app.PID(child.cmd.Process.Pid)
	oldPids := processPidsFunc
	processPidsFunc = func() ([]int32, error) { return []int32{int32(pid)}, nil }
	t.Cleanup(func() { processPidsFunc = oldPids })
	beforeDev, beforeIno, err := FindINodeForPID(pid)
	require.NoError(t, err)
	beforeStart, err := procs.StartTime(pid)
	require.NoError(t, err)
	acc := pollAccounter{cfg: &obi.Config{}, executableReady: ExecutableReady}
	snapshot := func() []Event[ProcessAttrs] {
		all, err := fetchProcessPorts(false)
		require.NoError(t, err)
		require.Contains(t, all, pid)
		return acc.snapshot(all, false)
	}
	initial := snapshot()
	require.Len(t, initial, 1)
	matcher := Matcher{
		Log:      slog.Default(),
		Criteria: []services.Selector{&services.RegexSelector{Path: services.NewRegexp("launcher$")}},
		ProcessHistory: map[app.PID]ProcessMatch{
			pid:                  {Process: &services.ProcessInfo{Pid: pid, ExePath: launcher}},
			app.PID(os.Getpid()): {Process: &services.ProcessInfo{Pid: app.PID(os.Getpid())}},
		},
	}
	original, err := findExecElf(matcher.ProcessHistory[pid].Process, &svc.Attrs{})
	require.NoError(t, err)
	cache, err := lru.New[cacheKey, instrumentedExecutable](10)
	require.NoError(t, err)
	cfg := &obi.Config{}
	cfg.Discovery.SkipGoSpecificTracers = true
	typer := typer{cfg: cfg, log: slog.Default(), currentPids: map[app.PID]*discexec.FileInfo{pid: original}, instrumentableCache: cache}
	instrumentables, tracerEvents := startReusingGenericAttacher(t)
	t.Cleanup(func() {
		instrumentables.Close()
		testutil.DrainUntilClosed(tracerEvents)
		require.NoError(t, original.ELF().Close())
		for _, info := range typer.currentPids {
			require.NoError(t, info.ELF().Close())
		}
	})
	instrumentables.Send([]Event[ebpf.Instrumentable]{{Type: EventCreated, Obj: ebpf.Instrumentable{
		Type: svc.InstrumentableGeneric, FileInfo: original,
	}}})
	attached := testutil.ReadChannel(t, tracerEvents, testTimeout)
	require.Equal(t, EventCreated, attached.Type)
	require.Same(t, original, attached.Obj.FileInfo)

	child.send(t)
	child.expect(t, 'R')
	afterDev, afterIno, err := FindINodeForPID(pid)
	require.NoError(t, err)
	afterStart, err := procs.StartTime(pid)
	require.NoError(t, err)
	require.Equal(t, beforeStart, afterStart)
	require.NotEqual(t, [2]uint64{beforeDev, beforeIno}, [2]uint64{afterDev, afterIno})
	events := snapshot()
	require.Len(t, events, 2)
	require.Equal(t, EventDeleted, events[0].Type)
	require.Equal(t, EventCreated, events[1].Type)
	matches := matcher.filter(events)
	require.Len(t, matches, 2)
	require.Equal(t, launcher, matches[0].Obj.Process.ExePath)
	require.Equal(t, target, matches[1].Obj.Process.ExePath)
	classified := typer.FilterClassify(matches)
	require.Len(t, classified, 2)
	require.Equal(t, EventDeleted, classified[0].Type)
	require.Same(t, original, classified[0].Obj.FileInfo)
	require.Equal(t, EventCreated, classified[1].Type)
	replacement := classified[1].Obj.FileInfo
	require.Equal(t, afterDev, replacement.Dev())
	require.Equal(t, afterIno, replacement.Ino())
	require.Same(t, replacement, typer.currentPids[pid])
	instrumentables.Send(classified)
	retired := testutil.ReadChannel(t, tracerEvents, testTimeout)
	require.Equal(t, EventDeleted, retired.Type)
	require.Same(t, original, retired.Obj.FileInfo)
	attached = testutil.ReadChannel(t, tracerEvents, testTimeout)
	require.Equal(t, EventCreated, attached.Type)
	require.Same(t, replacement, attached.Obj.FileInfo)
	require.Empty(t, snapshot())
	child.send(t)
	child.expect(t, 'S')
	require.NoError(t, child.wait())
}

func TestExecveAttachmentIdentity(t *testing.T) {
	launcher, target := buildExecveRepro(t)
	child := startExecveRepro(t, launcher, target)
	child.expect(t, 'L')
	pid := app.PID(child.cmd.Process.Pid)
	info, err := findExecElf(&services.ProcessInfo{Pid: pid, ExePath: launcher}, &svc.Attrs{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, info.ELF().Close()) })
	attacher := traceAttacher{log: slog.Default()}
	inst := ebpf.Instrumentable{FileInfo: info}
	pinned, ok := attacher.loadExecutable(&inst)
	require.True(t, ok)
	defer pinned.Close()
	child.send(t)
	child.expect(t, 'R')
	stat, err := pinned.Stat()
	require.NoError(t, err)
	launcherStat, err := os.Stat(launcher)
	require.NoError(t, err)
	require.True(t, os.SameFile(stat, launcherStat))
	reopened, ok := attacher.loadExecutable(&inst)
	require.False(t, ok, "stale offsets must not be attached to the replacement executable")
	require.Nil(t, reopened)
	child.send(t)
	child.expect(t, 'S')
	require.NoError(t, child.wait())
}

func buildExecveRepro(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	launcher, target := filepath.Join(dir, "launcher"), filepath.Join(dir, "target")
	for _, bin := range []string{launcher, target} {
		source := filepath.Join("testdata", "execve", filepath.Base(bin), "main.go")
		cmd := osexec.CommandContext(t.Context(), "go", "build", "-o", bin, source)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
	}
	return launcher, target
}

type execveReproProcess struct {
	cmd    *osexec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	waited bool
}

func startExecveRepro(t *testing.T, binary string, args ...string) *execveReproProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := osexec.CommandContext(ctx, binary, args...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	p := &execveReproProcess{cmd: cmd, stdin: stdin, stdout: stdout}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = stdout.Close()
		if !p.waited {
			_ = cmd.Process.Kill()
			_ = p.wait()
		}
	})
	return p
}

func (p *execveReproProcess) expect(t *testing.T, want byte) {
	t.Helper()
	var got [1]byte
	_, err := io.ReadFull(p.stdout, got[:])
	require.NoError(t, err)
	require.Equal(t, want, got[0])
}

func (p *execveReproProcess) send(t *testing.T) {
	t.Helper()
	_, err := p.stdin.Write([]byte{'\n'})
	require.NoError(t, err)
}

func (p *execveReproProcess) wait() error {
	p.waited = true
	return p.cmd.Wait()
}
