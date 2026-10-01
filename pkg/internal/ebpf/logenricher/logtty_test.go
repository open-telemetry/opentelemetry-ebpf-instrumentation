// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher

import (
	"os"
	"slices"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/shardedqueue"
)

func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()

	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty support: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })

	require.NoError(t, unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0))
	index, err := unix.IoctlGetUint32(int(master.Fd()), unix.TIOCGPTN)
	require.NoError(t, err)

	slave, err = os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(index), 10), os.O_RDWR|unix.O_NOCTTY, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = slave.Close() })

	return master, slave
}

func logRecord(event BpfLogEventT, line string) *ringbuf.Record {
	event.Len = uint32(len(line))
	hdr := unsafe.Slice((*byte)(unsafe.Pointer(&event)), unsafe.Offsetof(event.Log))

	return &ringbuf.Record{RawSample: append(slices.Clone(hdr), line...)}
}

// the writer's fd is used only while it still is the terminal the kernel saw
func TestTTYEventReopensWritersTerminal(t *testing.T) {
	master, slave := openPTY(t)
	cmd := startChild(t, slave, slave, "sleep", "30")
	pid := uint32(cmd.Process.Pid)

	tr := newPipeTestTracer(t)
	tr.ctx = t.Context()
	queued := make(chan LogEvent, 1)
	tr.asyncWriter = shardedqueue.NewShardedQueue(1, 1, LogEvent.shardKey, func(_ int, ch <-chan LogEvent) {
		for e := range ch {
			queued <- e
		}
	})
	t.Cleanup(tr.asyncWriter.Close)

	key := fdKey(t, slave)
	event := BpfLogEventT{Tgid: pid, Fd: 1, Ino: key.Ino, Dev: uint32(key.Dev), DestKind: logDestTTY}

	other := event
	other.Ino++
	_, _, err := tr.handleLogEvent(logRecord(other, "leaked line\n"))
	require.NoError(t, err)
	require.Zero(t, tr.fdCache.Len(), "a different terminal must not be opened through the writer's fd")

	_, _, err = tr.handleLogEvent(logRecord(event, "terminal line\n"))
	require.NoError(t, err)

	var e LogEvent
	select {
	case e = <-queued:
	case <-time.After(5 * time.Second):
		t.Fatal("line for the writer's terminal was dropped")
	}
	assert.Equal(t, procFdPath(pid, 1), e.dest)

	read := make(chan string, 1)
	go func() {
		buf := make([]byte, 128)
		n, _ := master.Read(buf)
		read <- string(buf[:n])
	}()

	tr.handle(e)

	select {
	case got := <-read:
		assert.Contains(t, got, "terminal line")
	case <-time.After(5 * time.Second):
		t.Fatal("line did not reach the writer's terminal")
	}
}
