// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestAsInstrumentable_DotnetProcessLifecycle(t *testing.T) {
	// Exercise uncached language detection through the real process maps.
	file, err := os.Create(filepath.Join(t.TempDir(), "libcoreclr.so"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	require.NoError(t, file.Truncate(int64(os.Getpagesize())))
	mapping, err := unix.Mmap(int(file.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, unix.Munmap(mapping)) })

	for _, childFirst := range []bool{true, false} {
		name := "parent-first"
		if childFirst {
			name = "child-first"
		}
		t.Run(name, func(t *testing.T) {
			cache, err := lru.New[cacheKey, *goexec.Offsets](100)
			require.NoError(t, err)
			parent := exec.New(exec.Init{
				Pid: app.PID(os.Getpid()), StartTime: 10, Dev: 42, Ino: 15, CmdExePath: "/usr/bin/dotnet",
			})
			child := exec.New(exec.Init{
				Pid: 1 << 30, Ppid: parent.Pid(), StartTime: 20, Dev: 42, Ino: 15, CmdExePath: "/usr/bin/dotnet",
			})
			cfg := obi.DefaultConfig
			cfg.Discovery.SkipGoSpecificTracers = true
			ty := typer{
				cfg: &cfg, log: slog.Default(), goOffsetsCache: cache,
				currentPids: map[app.PID]*exec.FileInfo{parent.Pid(): parent, child.Pid(): child},
			}
			order := []*exec.FileInfo{parent, child}
			if childFirst {
				order = []*exec.FileInfo{child, parent}
			}
			for _, process := range order {
				instrumentable := ty.asInstrumentable(process)
				require.Equal(t, svc.InstrumentableDotnet, instrumentable.Type)
				assert.Same(t, process, instrumentable.FileInfo)
				assert.Empty(t, instrumentable.ChildPids)
				assert.Nil(t, process.RuntimeMetricServiceSource())
			}

			for _, process := range []*exec.FileInfo{child, parent} {
				deleted := ty.FilterClassify([]Event[ProcessMatch]{{
					Type: EventDeleted, Obj: ProcessMatch{Process: &services.ProcessInfo{Pid: process.Pid()}},
				}})
				require.Len(t, deleted, 1)
				assert.Same(t, process, deleted[0].Obj.FileInfo)
				assert.NotContains(t, ty.currentPids, process.Pid())
				if process == child {
					assert.Same(t, parent, ty.currentPids[parent.Pid()])
				}
			}
		})
	}
}

func TestDotnetRuntimeMappingAfterRestart(t *testing.T) {
	if mappingPath, child := os.LookupEnv("OBI_TEST_RUNTIME_MAPPING"); child {
		if mappingPath != "" {
			file, err := os.Open(mappingPath)
			require.NoError(t, err)
			defer file.Close()
			mapping, err := unix.Mmap(int(file.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_PRIVATE)
			require.NoError(t, err)
			defer func() { require.NoError(t, unix.Munmap(mapping)) }()
		}
		_, err := os.Stdout.Write([]byte{'R'})
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, os.Stdin)
		require.NoError(t, err)
		return
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	runtimePath := filepath.Join(t.TempDir(), "libcoreclr.so")
	require.NoError(t, os.WriteFile(runtimePath, make([]byte, os.Getpagesize()), 0o600))

	ty := newRestartTestTyper(t)
	cfg := *ty.cfg
	cfg.Discovery.SkipGoSpecificTracers = true
	ty.cfg = &cfg
	ld := newTestDecorator(nil)
	var key cacheKey
	for i, tc := range []struct {
		mapping string
		lang    svc.InstrumentableType
	}{
		{"", svc.InstrumentableGolang},
		{runtimePath, svc.InstrumentableDotnet},
		{"", svc.InstrumentableGolang},
	} {
		t.Setenv("OBI_TEST_RUNTIME_MAPPING", tc.mapping)
		child := startExecveRepro(t, exe, "-test.run=^TestDotnetRuntimeMappingAfterRestart$")
		child.expect(t, 'R')
		pid := app.PID(child.cmd.Process.Pid)
		ev := Event[ProcessAttrs]{Type: EventCreated, Obj: ProcessAttrs{pid: pid}}
		ld.decorateEvent(&ev)
		require.Equal(t, tc.lang, ev.Obj.detectedType)
		match := ProcessMatch{Process: &services.ProcessInfo{Pid: pid, ExePath: exe}}
		created := ty.FilterClassify([]Event[ProcessMatch]{{Type: EventCreated, Obj: match}})
		require.Len(t, created, 1)
		got := created[0].Obj
		t.Cleanup(func() { _ = got.FileInfo.ELF().Close() })
		require.Equal(t, tc.lang, got.Type)
		require.NoError(t, got.InstrumentationError)
		if i == 0 {
			key = executableCacheKey(got.FileInfo)
		} else {
			require.Equal(t, key, executableCacheKey(got.FileInfo))
		}
		require.NoError(t, child.stdin.Close())
		require.NoError(t, child.wait())
		require.Len(t, ty.FilterClassify([]Event[ProcessMatch]{{Type: EventDeleted, Obj: match}}), 1)
	}
}
