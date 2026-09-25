// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
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
			cache, err := lru.New[cacheKey, instrumentedExecutable](100)
			require.NoError(t, err)
			parent := exec.New(exec.Init{
				Pid: app.PID(os.Getpid()), StartTime: 10, Dev: 42, Ino: 15, CmdExePath: "/usr/bin/dotnet",
			})
			child := exec.New(exec.Init{
				Pid: parent.Pid() + 1, Ppid: parent.Pid(), StartTime: 20, Dev: 42, Ino: 15, CmdExePath: "/usr/bin/dotnet",
			})
			cfg := obi.DefaultConfig
			cfg.Discovery.SkipGoSpecificTracers = true
			ty := typer{
				cfg: &cfg, log: slog.Default(), instrumentableCache: cache,
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
