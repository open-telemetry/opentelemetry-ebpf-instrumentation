// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type rustTestReporter struct{ imetrics.NoopReporter }

// Live checks run concurrently against one host bpffs, so each pins its shared
// maps in its own directory instead of racing on the same pin.
func privateBPFFSPath(t *testing.T, root string) string {
	dir, err := os.MkdirTemp(root, "obi-rust-test-") //nolint:usetesting // BPF maps must be pinned on bpffs.
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func rustProcessFileInfo(t *testing.T, pid app.PID) *discexec.FileInfo {
	t.Helper()
	path := fmt.Sprintf("/proc/%d/exe", pid)
	info, err := os.Stat(path)
	require.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)
	ns, err := procs.FindNamespace(pid)
	require.NoError(t, err)
	start, err := procs.StartTime(pid)
	require.NoError(t, err)
	return discexec.New(discexec.Init{
		Service:        svc.Attrs{UID: svc.UID{Name: "rust-context"}, SDKLanguage: svc.InstrumentableRust},
		ProExeLinkPath: path, Pid: pid, Dev: stat.Dev, Ino: stat.Ino, Ns: ns, StartTime: start,
	})
}
