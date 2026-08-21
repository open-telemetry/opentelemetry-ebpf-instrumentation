// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher

import (
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func newPipeTestTracer(t *testing.T) *Tracer {
	t.Helper()

	tr := newTestTracer(t, false)
	tr.trackedPids = map[uint32]struct{}{}
	tr.logPipes = map[uint64]map[uint32][]int{}
	tr.pidPipes = map[uint32]map[int]uint64{}
	tr.fdCache = expirable.NewLRU[string, *os.File](128, func(_ string, f *os.File) {
		_ = f.Close()
	}, time.Minute)
	t.Cleanup(tr.fdCache.Purge)

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("removing memlock failed: %v", err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "log_pipes_test",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 16,
	})
	if err != nil {
		t.Skipf("ebpf map create failed: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	tr.bpfObjects.LogPipes = m

	return tr
}

func fdIno(t *testing.T, f *os.File) uint64 {
	t.Helper()

	var st unix.Stat_t
	require.NoError(t, unix.Fstat(int(f.Fd()), &st))
	return st.Ino
}

// child process whose stdout/stderr are the given files
func startChild(t *testing.T, stdout, stderr *os.File, args ...string) *osexec.Cmd {
	t.Helper()

	cmd := osexec.Command(args[0], args[1:]...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	return cmd
}

func bpfHasIno(t *testing.T, tr *Tracer, ino uint64) bool {
	t.Helper()

	var v uint8
	err := tr.bpfObjects.LogPipes.Lookup(ino, &v)
	if err == nil {
		return true
	}
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	return false
}

func registeredIno(tr *Tracer, pid uint32, fd int) uint64 {
	tr.pidsMU.Lock()
	defer tr.pidsMU.Unlock()

	return tr.pidPipes[pid][fd]
}

func trackAndRegister(tr *Tracer, pid uint32) {
	tr.pidsMU.Lock()
	defer tr.pidsMU.Unlock()

	tr.trackedPids[pid] = struct{}{}
	tr.registerLogPipes(pid)
}

func TestLogPipeRegistration(t *testing.T) {
	tr := newPipeTestTracer(t)

	outR, outW, err := os.Pipe()
	require.NoError(t, err)
	defer outR.Close()
	defer outW.Close()
	errR, errW, err := os.Pipe()
	require.NoError(t, err)
	defer errR.Close()
	defer errW.Close()

	cmd := startChild(t, outW, errW, "sleep", "30")
	pid := uint32(cmd.Process.Pid)

	trackAndRegister(tr, pid)

	outIno := fdIno(t, outW)
	errIno := fdIno(t, errW)
	assert.Equal(t, outIno, registeredIno(tr, pid, 1))
	assert.Equal(t, errIno, registeredIno(tr, pid, 2))
	assert.True(t, bpfHasIno(t, tr, outIno))
	assert.True(t, bpfHasIno(t, tr, errIno))
	assert.NotEmpty(t, tr.pipeDestCandidates(outIno))
}

// controllableChild runs a shell that redirects its stdout to redirectTo when
// one byte arrives on stdin, then keeps running
func controllableChild(t *testing.T, stdout *os.File, redirectTo string) (*osexec.Cmd, io.WriteCloser) {
	t.Helper()

	cmd := osexec.Command("/bin/sh", "-c", `read a; exec > "$0"; read b`, redirectTo)
	cmd.Stdout = stdout
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	return cmd, stdin
}

// wait until /proc/<pid>/fd/1 no longer points at ino (the redirect happened)
func waitRedirected(t *testing.T, pid uint32, ino uint64) {
	t.Helper()

	require.Eventually(t, func() bool {
		var st unix.Stat_t
		if err := unix.Stat(procFdPath(pid, 1), &st); err != nil {
			return false
		}
		return st.Ino != ino
	}, 5*time.Second, 10*time.Millisecond)
}

func TestReconcileDetectsRedirect(t *testing.T) {
	tr := newPipeTestTracer(t)

	oldR, oldW, err := os.Pipe()
	require.NoError(t, err)
	defer oldR.Close()
	defer oldW.Close()

	fifo := filepath.Join(t.TempDir(), "redir")
	require.NoError(t, unix.Mkfifo(fifo, 0o600))

	cmd, stdin := controllableChild(t, oldW, fifo)
	pid := uint32(cmd.Process.Pid)
	oldIno := fdIno(t, oldW)

	trackAndRegister(tr, pid)
	require.Equal(t, oldIno, registeredIno(tr, pid, 1))

	// open the fifo's read end so the child's redirect can complete
	fifoOpened := make(chan *os.File, 1)
	go func() {
		f, _ := os.Open(fifo)
		fifoOpened <- f
	}()

	_, err = stdin.Write([]byte("\n"))
	require.NoError(t, err)
	waitRedirected(t, pid, oldIno)

	tr.reconcileLogPipes()

	fifoFile := <-fifoOpened
	require.NotNil(t, fifoFile)
	defer fifoFile.Close()

	var st unix.Stat_t
	require.NoError(t, unix.Stat(procFdPath(pid, 1), &st))
	assert.Equal(t, st.Ino, registeredIno(tr, pid, 1), "new pipe must be registered")
	assert.True(t, bpfHasIno(t, tr, st.Ino))

	assert.Empty(t, tr.pipeDestCandidates(oldIno), "old pipe must have no owners left")
	assert.False(t, bpfHasIno(t, tr, oldIno), "old pipe must be retired from the BPF map")
}

func TestReconcileReleasesCachedHandle(t *testing.T) {
	tr := newPipeTestTracer(t)

	oldR, oldW, err := os.Pipe()
	require.NoError(t, err)
	defer oldR.Close()

	fifo := filepath.Join(t.TempDir(), "redir")
	require.NoError(t, unix.Mkfifo(fifo, 0o600))

	cmd, stdin := controllableChild(t, oldW, fifo)
	pid := uint32(cmd.Process.Pid)
	oldIno := fdIno(t, oldW)

	trackAndRegister(tr, pid)

	// warm the cache like event capture does, then drop our own write end so
	// the cached handle is the only writer left besides the child
	_, err = tr.openLogDestination(procFdPath(pid, 1), oldIno)
	require.NoError(t, err)
	require.NoError(t, oldW.Close())

	fifoOpened := make(chan *os.File, 1)
	go func() {
		f, _ := os.Open(fifo)
		fifoOpened <- f
	}()

	_, err = stdin.Write([]byte("\n"))
	require.NoError(t, err)
	waitRedirected(t, pid, oldIno)

	tr.reconcileLogPipes()

	if f := <-fifoOpened; f != nil {
		defer f.Close()
	}

	// child redirected away and the cache handle is closed: EOF must arrive
	done := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(oldR)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not see EOF: a stale write end is still held")
	}
}

func TestReconcileKeepsUnchangedRegistration(t *testing.T) {
	tr := newPipeTestTracer(t)

	outR, outW, err := os.Pipe()
	require.NoError(t, err)
	defer outR.Close()
	defer outW.Close()

	cmd := startChild(t, outW, outW, "sleep", "30")
	pid := uint32(cmd.Process.Pid)

	trackAndRegister(tr, pid)

	ino := fdIno(t, outW)
	f, err := tr.openLogDestination(procFdPath(pid, 1), ino)
	require.NoError(t, err)

	tr.reconcileLogPipes()
	tr.reconcileLogPipes()

	assert.True(t, bpfHasIno(t, tr, ino), "unchanged pipe must stay registered")
	cached, ok := tr.fdCache.Get(procFdPath(pid, 1))
	require.True(t, ok, "unchanged pipe must keep its cached handle")
	assert.Same(t, f, cached)
}

func TestReconcileRetiresExitedPidSharedPipe(t *testing.T) {
	tr := newPipeTestTracer(t)

	outR, outW, err := os.Pipe()
	require.NoError(t, err)
	defer outR.Close()
	defer outW.Close()

	cmdA := startChild(t, outW, outW, "sleep", "30")
	cmdB := startChild(t, outW, outW, "sleep", "30")
	pidA := uint32(cmdA.Process.Pid)
	pidB := uint32(cmdB.Process.Pid)

	trackAndRegister(tr, pidA)
	trackAndRegister(tr, pidB)

	ino := fdIno(t, outW)
	require.NoError(t, cmdA.Process.Kill())
	_, err = cmdA.Process.Wait()
	require.NoError(t, err)

	tr.reconcileLogPipes()

	assert.Zero(t, registeredIno(tr, pidA, 1), "exited pid must be retired")
	assert.Equal(t, ino, registeredIno(tr, pidB, 1), "surviving pid must keep the pipe")
	assert.True(t, bpfHasIno(t, tr, ino), "shared pipe must survive one owner's exit")
}
