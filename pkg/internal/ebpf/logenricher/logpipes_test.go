// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher

import (
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"unsafe"

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
	tr.logPipes = map[pipeKey]map[uint32][]int{}
	tr.pidPipes = map[uint32]map[int]pipeKey{}
	tr.fdCache = expirable.NewLRU[string, *os.File](128, func(_ string, f *os.File) {
		_ = f.Close()
	}, time.Minute)
	t.Cleanup(tr.fdCache.Purge)

	tr.bpfObjects.LogPipes = newLogPipesMap(t, 16)

	return tr
}

func newLogPipesMap(t *testing.T, maxEntries uint32) *ebpf.Map {
	t.Helper()

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("removing memlock failed: %v", err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "log_pipes_test",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(pipeKey{})),
		ValueSize:  1,
		MaxEntries: maxEntries,
	})
	if err != nil {
		t.Skipf("ebpf map create failed: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func fdKey(t *testing.T, f *os.File) pipeKey {
	t.Helper()

	var st unix.Stat_t
	require.NoError(t, unix.Fstat(int(f.Fd()), &st))
	return pipeKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}
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

func bpfHasKey(t *testing.T, tr *Tracer, key pipeKey) bool {
	t.Helper()

	var v uint8
	err := tr.bpfObjects.LogPipes.Lookup(key, &v)
	if err == nil {
		return true
	}
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	return false
}

func registeredKey(tr *Tracer, pid uint32, fd int) pipeKey {
	tr.pipesMU.RLock()
	defer tr.pipesMU.RUnlock()

	return tr.pidPipes[pid][fd]
}

func trackAndRegister(tr *Tracer, pid uint32) {
	tr.pipesMU.Lock()
	tr.trackedPids[pid] = struct{}{}
	tr.pipesMU.Unlock()

	tr.registerLogPipes(pid)
}

func untrack(tr *Tracer, pid uint32) {
	tr.pipesMU.Lock()
	defer tr.pipesMU.Unlock()

	delete(tr.trackedPids, pid)
	tr.unregisterLogPipes(pid)
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

	outKey := fdKey(t, outW)
	errKey := fdKey(t, errW)
	assert.Equal(t, outKey, registeredKey(tr, pid, 1))
	assert.Equal(t, errKey, registeredKey(tr, pid, 2))
	assert.True(t, bpfHasKey(t, tr, outKey))
	assert.True(t, bpfHasKey(t, tr, errKey))
	assert.NotEmpty(t, tr.pipeDestCandidates(outKey))
}

// same inode number on a different filesystem must not match the registration
func TestLogPipeKeyIncludesDevice(t *testing.T) {
	tr := newPipeTestTracer(t)

	outR, outW, err := os.Pipe()
	require.NoError(t, err)
	defer outR.Close()
	defer outW.Close()

	cmd := startChild(t, outW, outW, "sleep", "30")
	pid := uint32(cmd.Process.Pid)

	trackAndRegister(tr, pid)

	key := fdKey(t, outW)
	require.NotZero(t, key.Dev, "pipefs device must be part of the key")
	assert.True(t, bpfHasKey(t, tr, key))

	collided := pipeKey{Ino: key.Ino, Dev: key.Dev + 1}
	assert.False(t, bpfHasKey(t, tr, collided), "same ino on another device must not match")
	assert.Empty(t, tr.pipeDestCandidates(collided))
	assert.False(t, tr.pipeRegistered(collided))
}

// a failed BPF map update must not be recorded as registered: the next
// reconcile retries it once there is room again
func TestFailedPipeRegistrationIsRetried(t *testing.T) {
	tr := newPipeTestTracer(t)
	tr.bpfObjects.LogPipes = newLogPipesMap(t, 1)

	aR, aW, err := os.Pipe()
	require.NoError(t, err)
	defer aR.Close()
	defer aW.Close()
	bR, bW, err := os.Pipe()
	require.NoError(t, err)
	defer bR.Close()
	defer bW.Close()

	cmdA := startChild(t, aW, aW, "sleep", "30")
	cmdB := startChild(t, bW, bW, "sleep", "30")
	pidA := uint32(cmdA.Process.Pid)
	pidB := uint32(cmdB.Process.Pid)

	trackAndRegister(tr, pidA)
	keyA := fdKey(t, aW)
	require.True(t, bpfHasKey(t, tr, keyA))

	// the map is full: B's registration must fail and leave no state behind
	trackAndRegister(tr, pidB)
	keyB := fdKey(t, bW)
	assert.Equal(t, pipeKey{}, registeredKey(tr, pidB, 1), "failed registration must not be recorded")
	assert.False(t, bpfHasKey(t, tr, keyB))

	untrack(tr, pidA)
	require.False(t, bpfHasKey(t, tr, keyA))

	tr.reconcileLogPipes()

	assert.Equal(t, keyB, registeredKey(tr, pidB, 1), "reconcile must retry the failed registration")
	assert.True(t, bpfHasKey(t, tr, keyB))
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

// wait until /proc/<pid>/fd/1 no longer points at key (the redirect happened)
func waitRedirected(t *testing.T, pid uint32, key pipeKey) {
	t.Helper()

	require.Eventually(t, func() bool {
		var st unix.Stat_t
		if err := unix.Stat(procFdPath(pid, 1), &st); err != nil {
			return false
		}
		return (pipeKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}) != key
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
	oldKey := fdKey(t, oldW)

	trackAndRegister(tr, pid)
	require.Equal(t, oldKey, registeredKey(tr, pid, 1))

	// open the fifo's read end so the child's redirect can complete
	fifoOpened := make(chan *os.File, 1)
	go func() {
		f, _ := os.Open(fifo)
		fifoOpened <- f
	}()

	_, err = stdin.Write([]byte("\n"))
	require.NoError(t, err)
	waitRedirected(t, pid, oldKey)

	tr.reconcileLogPipes()

	fifoFile := <-fifoOpened
	require.NotNil(t, fifoFile)
	defer fifoFile.Close()

	var st unix.Stat_t
	require.NoError(t, unix.Stat(procFdPath(pid, 1), &st))
	newKey := pipeKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}
	assert.Equal(t, newKey, registeredKey(tr, pid, 1), "new pipe must be registered")
	assert.True(t, bpfHasKey(t, tr, newKey))

	assert.Empty(t, tr.pipeDestCandidates(oldKey), "old pipe must have no owners left")
	assert.False(t, bpfHasKey(t, tr, oldKey), "old pipe must be retired from the BPF map")
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
	oldKey := fdKey(t, oldW)

	trackAndRegister(tr, pid)

	// warm the cache like event capture does, then drop our own write end so
	// the cached handle is the only writer left besides the child
	_, err = tr.openLogDestination(procFdPath(pid, 1), oldKey)
	require.NoError(t, err)
	require.NoError(t, oldW.Close())

	fifoOpened := make(chan *os.File, 1)
	go func() {
		f, _ := os.Open(fifo)
		fifoOpened <- f
	}()

	_, err = stdin.Write([]byte("\n"))
	require.NoError(t, err)
	waitRedirected(t, pid, oldKey)

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

	key := fdKey(t, outW)
	f, err := tr.openLogDestination(procFdPath(pid, 1), key)
	require.NoError(t, err)

	tr.reconcileLogPipes()
	tr.reconcileLogPipes()

	assert.True(t, bpfHasKey(t, tr, key), "unchanged pipe must stay registered")
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

	key := fdKey(t, outW)
	require.NoError(t, cmdA.Process.Kill())
	_, err = cmdA.Process.Wait()
	require.NoError(t, err)

	tr.reconcileLogPipes()

	assert.Equal(t, pipeKey{}, registeredKey(tr, pidA, 1), "exited pid must be retired")
	assert.Equal(t, key, registeredKey(tr, pidB, 1), "surviving pid must keep the pipe")
	assert.True(t, bpfHasKey(t, tr, key), "shared pipe must survive one owner's exit")
}

// the tty fallback pin must reject a /proc fd path that re-pointed at another
// file after the identity was taken
func TestFallbackPinRejectsRepointedFd(t *testing.T) {
	tr := newPipeTestTracer(t)

	dir := t.TempDir()
	fileA, err := os.Create(filepath.Join(dir, "a.log"))
	require.NoError(t, err)
	defer fileA.Close()

	cmd, stdin := controllableChild(t, fileA, filepath.Join(dir, "b.log"))
	pid := uint32(cmd.Process.Pid)
	path := procFdPath(pid, 1)

	pin, ok := tr.fallbackDest(path)
	require.True(t, ok, "regular file fallback must be accepted")
	require.Equal(t, fdKey(t, fileA), pin)

	_, err = tr.openLogDestination(path, pin)
	require.NoError(t, err)

	_, err = stdin.Write([]byte("\n"))
	require.NoError(t, err)
	waitRedirected(t, pid, pin)

	// with the cache evicted, reopening through the re-pointed path must be
	// detected instead of leaking lines into b.log
	tr.fdCache.Purge()
	_, err = tr.openLogDestination(path, pin)
	require.ErrorIs(t, err, errStaleDestination)
}

func TestFallbackDestPipeRegistration(t *testing.T) {
	tr := newPipeTestTracer(t)

	outR, outW, err := os.Pipe()
	require.NoError(t, err)
	defer outR.Close()
	defer outW.Close()

	cmd := startChild(t, outW, outW, "sleep", "30")
	pid := uint32(cmd.Process.Pid)
	path := procFdPath(pid, 1)

	_, ok := tr.fallbackDest(path)
	assert.False(t, ok, "unregistered pipe fallback must be rejected")

	trackAndRegister(tr, pid)

	pin, ok := tr.fallbackDest(path)
	assert.True(t, ok, "registered pipe fallback must be accepted")
	assert.Equal(t, fdKey(t, outW), pin)
}

// candidate churn must not move a pipe's lines to another shard
func TestShardKeyStableAcrossOwnerChange(t *testing.T) {
	viaOwnerA := LogEvent{dest: "/proc/100/fd/1"}
	viaOwnerA.orig.Fd = 1
	viaOwnerA.orig.Ino = 42
	viaOwnerA.orig.Dev = 7

	viaOwnerB := LogEvent{dest: "/proc/200/fd/2"}
	viaOwnerB.orig.Fd = 2
	viaOwnerB.orig.Ino = 42
	viaOwnerB.orig.Dev = 7

	assert.Equal(t, viaOwnerA.shardKey(), viaOwnerB.shardKey())

	otherPipe := viaOwnerA
	otherPipe.orig.Dev = 8
	assert.NotEqual(t, viaOwnerA.shardKey(), otherPipe.shardKey())

	tty := LogEvent{dest: "/dev/pts/0"}
	assert.Equal(t, "/dev/pts/0", tty.shardKey())
}

// opening a reader-less fifo must fail fast instead of blocking the caller
func TestOpenDestinationReaderlessFifoFailsFast(t *testing.T) {
	tr := newPipeTestTracer(t)

	fifo := filepath.Join(t.TempDir(), "noreader")
	require.NoError(t, unix.Mkfifo(fifo, 0o600))

	errCh := make(chan error, 1)
	go func() {
		_, err := tr.openLogDestination(fifo, pipeKey{})
		errCh <- err
	}()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, unix.ENXIO)
	case <-time.After(2 * time.Second):
		t.Fatal("open blocked on a reader-less fifo")
	}

	// with a reader present the open succeeds and the write path is blocking
	reader, err := os.OpenFile(fifo, os.O_RDONLY|unix.O_NONBLOCK, 0)
	require.NoError(t, err)
	defer reader.Close()

	f, err := tr.openLogDestination(fifo, pipeKey{})
	require.NoError(t, err)

	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	require.NoError(t, err)
	assert.Zero(t, flags&unix.O_NONBLOCK, "write path must be blocking for backpressure")
}

// a line warmed through one owner must still land when that owner retires
// while the line is queued and another registered owner remains
func TestQueuedLineSurvivesWarmedOwnerExit(t *testing.T) {
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
	key := fdKey(t, outW)

	// capture-time warm open through owner A, like handleLogEvent does
	e := LogEvent{dest: procFdPath(pidA, 1), pin: key, logLine: "queued line\n"}
	e.orig.Fd = 1
	_, err = tr.openLogDestination(e.dest, e.pin)
	require.NoError(t, err)

	// owner A exits and is retired before the async writer gets to the line:
	// its cached handle is closed and its /proc path is gone
	require.NoError(t, cmdA.Process.Kill())
	_, err = cmdA.Process.Wait()
	require.NoError(t, err)
	untrack(tr, pidA)

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := outR.Read(buf)
		done <- buf[:n]
	}()

	tr.handle(e)

	select {
	case got := <-done:
		assert.Equal(t, "queued line\n", string(got), "line must be delivered through the surviving owner")
	case <-time.After(5 * time.Second):
		t.Fatal("queued line was dropped after the warmed owner exited")
	}
}

// exercised under -race: registration, reconcile, and the event hot path
// must be safe to run concurrently
func TestConcurrentPipeAccess(t *testing.T) {
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
	key := fdKey(t, outW)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				tr.reconcileLogPipes()
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				tr.pipeDestCandidates(key)
				tr.pipeRegistered(key)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				trackAndRegister(tr, pidB)
				untrack(tr, pidB)
			}
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	assert.NotEmpty(t, tr.pipeDestCandidates(key), "pid A must remain registered")
}
