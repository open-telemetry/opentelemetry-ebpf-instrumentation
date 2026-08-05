// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Converted from C code from the jattach project
package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	MaxNotifyFiles      = 256
	openJ9PollInterval  = 10 * time.Millisecond
	openJ9AcceptTimeout = 5 * time.Second
	openJ9DetachTimeout = 5 * time.Second
)

type j9Attacher struct {
	notifyLock [MaxNotifyFiles]int
	logger     *slog.Logger
	mu         sync.Mutex
	connection *j9Connection
}

func newJ9Attacher(logger *slog.Logger) *j9Attacher {
	if logger == nil {
		logger = slog.Default()
	}

	return &j9Attacher{logger: logger}
}

// Translate HotSpot command to OpenJ9 equivalent
func translateCommand(argv []string) string {
	if len(argv) == 0 {
		return ""
	}

	argc := len(argv)
	cmd := argv[0]
	var result string

	switch cmd {
	case "load":
		if argc >= 2 {
			arg3 := ""
			if argc > 3 {
				arg3 = argv[3]
			}
			if argc > 2 && argv[2] == "true" {
				result = fmt.Sprintf("ATTACH_LOADAGENTPATH(%s,%s)", argv[1], arg3)
			} else {
				result = fmt.Sprintf("ATTACH_LOADAGENT(%s,%s)", argv[1], arg3)
			}
		}

	case "jcmd":
		arg1 := "help"
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:" + strings.Join(append([]string{arg1}, argv[2:]...), ",")

	case "threaddump":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:Thread.print," + arg1

	case "dumpheap":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:Dump.heap," + arg1

	case "inspectheap":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:GC.class_histogram," + arg1

	case "datadump":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:Dump.java," + arg1

	case "properties":
		result = "ATTACH_GETSYSTEMPROPERTIES"

	case "agentProperties":
		result = "ATTACH_GETAGENTPROPERTIES"

	default:
		result = cmd
	}

	return result
}

// Send command with arguments to socket
func writeCommand(fd int, cmd string) error {
	data := []byte(cmd)
	data = append(data, 0) // null terminator

	off := 0
	for off < len(data) {
		n, err := syscall.Write(fd, data[off:])
		if err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		if n <= 0 {
			return fmt.Errorf("write failed: %w", io.ErrShortWrite)
		}
		off += n
	}
	return nil
}

func writeCommandContext(ctx context.Context, conn net.Conn, cmd string) error {
	data := append([]byte(cmd), 0)
	for len(data) > 0 {
		n, err := writeConnectionContext(ctx, conn, data)
		data = data[n:]
		if err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("write failed: %w", io.ErrShortWrite)
		}
	}
	return nil
}

func readFullContext(ctx context.Context, conn net.Conn, buf []byte) (int, error) {
	off := 0
	for off < len(buf) {
		n, err := readConnectionContext(ctx, conn, buf[off:])
		off += n
		if err != nil {
			return off, err
		}
		if n == 0 {
			return off, io.ErrUnexpectedEOF
		}
	}
	return off, nil
}

func readConnectionContext(ctx context.Context, conn net.Conn, buf []byte) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := conn.SetReadDeadline(nextOpenJ9Deadline(ctx)); err != nil {
			return 0, err
		}

		n, err := conn.Read(buf)
		if n > 0 || err == nil {
			return n, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, ctxErr
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			continue
		}
		return 0, err
	}
}

func writeConnectionContext(ctx context.Context, conn net.Conn, buf []byte) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := conn.SetWriteDeadline(nextOpenJ9Deadline(ctx)); err != nil {
			return 0, err
		}

		n, err := conn.Write(buf)
		if n > 0 || err == nil {
			return n, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, ctxErr
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			continue
		}
		return 0, err
	}
}

func nextOpenJ9Deadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(openJ9PollInterval)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func closeWithErrno(fd int) {
	_ = syscall.Close(fd)
}

func acquireLock(ctx context.Context, tmpPath, subdir, filename string) (int, error) {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", subdir, filename)

	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_CLOEXEC, 0o666)
	if err != nil {
		return -1, err
	}

	for {
		if err := ctx.Err(); err != nil {
			return -1, errors.Join(err, syscall.Close(fd))
		}
		if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return fd, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return -1, errors.Join(err, syscall.Close(fd))
		}
		if err := sleepContext(ctx, openJ9PollInterval); err != nil {
			return -1, errors.Join(err, syscall.Close(fd))
		}
	}
}

func releaseLock(lockFd int) error {
	return errors.Join(
		syscall.Flock(lockFd, syscall.LOCK_UN),
		syscall.Close(lockFd),
	)
}

func createAttachSocket() (int, int, error) {
	// Try IPv6 socket first, then fall back to IPv4
	s, err := syscall.Socket(
		syscall.AF_INET6,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
		0,
	)
	if err == nil {
		addr := &syscall.SockaddrInet6{}
		if err := syscall.Bind(s, addr); err == nil {
			if err := syscall.Listen(s, 0); err == nil {
				sa, err := syscall.Getsockname(s)
				if err == nil {
					if sa6, ok := sa.(*syscall.SockaddrInet6); ok {
						return s, sa6.Port, nil
					}
				}
			}
		}
		closeWithErrno(s)
	}

	// Fall back to IPv4
	s, err = syscall.Socket(
		syscall.AF_INET,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
		0,
	)
	if err != nil {
		return -1, 0, err
	}

	addr := &syscall.SockaddrInet4{}
	if err := syscall.Bind(s, addr); err != nil {
		closeWithErrno(s)
		return -1, 0, err
	}

	if err := syscall.Listen(s, 0); err != nil {
		closeWithErrno(s)
		return -1, 0, err
	}

	sa, err := syscall.Getsockname(s)
	if err != nil {
		closeWithErrno(s)
		return -1, 0, err
	}

	if sa4, ok := sa.(*syscall.SockaddrInet4); ok {
		return s, sa4.Port, nil
	}

	closeWithErrno(s)
	return -1, 0, errors.New("failed to get socket port")
}

func closeAttachSocket(tmpPath string, s, pid int) error {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "replyInfo")
	var err error
	if unlinkErr := syscall.Unlink(path); unlinkErr != nil && !errors.Is(unlinkErr, syscall.ENOENT) {
		err = errors.Join(err, unlinkErr)
	}

	return errors.Join(err, syscall.Close(s))
}

func randomKey() uint64 {
	key := uint64(time.Now().Unix()) * 0xc6a4a7935bd1e995

	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return key
	}

	for i, b := range buf {
		key ^= uint64(b) << (uint(i) * 8)
	}

	return key
}

func writeReplyInfo(tmpPath string, pid, port int, key uint64) error {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "replyInfo")

	content := fmt.Sprintf("%016x\n%d\n", key, port)
	return os.WriteFile(path, []byte(content), 0o600)
}

func notifySemaphore(tmpPath string, value, notifyCount int) error {
	if notifyCount <= 0 {
		return nil
	}

	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", "_notifier")

	semKey, err := ftok(path, 0xa1)
	if err != nil {
		return err
	}

	semID, err := semget(semKey, 1, unix.IPC_CREAT|0o666)
	if err != nil {
		return err
	}

	flags := int16(0)
	if value < 0 {
		flags = unix.IPC_NOWAIT
	}

	sb := createSembuf(0, int16(value), flags)

	for range notifyCount {
		if err := semop(semID, []sembuf{sb}); err != nil {
			// The restore path decrements with IPC_NOWAIT. The JVMs we notified
			// consume the posts themselves as they wake up, so the semaphore is
			// frequently already at zero by the time we try to take our posts
			// back. EAGAIN ("resource temporarily unavailable") is the kernel
			// signaling there is nothing left to decrement. The original C code
			// was handling this, but it was missed in translation.
			if value < 0 && errors.Is(err, unix.EAGAIN) {
				return nil
			}
			return fmt.Errorf("semop failed: %w", err)
		}
	}

	return nil
}

func acceptClient(ctx context.Context, s int, key uint64) (net.Conn, error) {
	acceptCtx, cancel := context.WithTimeout(ctx, openJ9AcceptTimeout)
	defer cancel()

	var fd int
	for {
		if err := acceptCtx.Err(); err != nil {
			return nil, err
		}

		acceptedFD, _, err := syscall.Accept4(s, syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK)
		if err == nil {
			fd = acceptedFD
			break
		}
		if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("jvm did not respond: %w", err)
		}
		if err := sleepContext(acceptCtx, openJ9PollInterval); err != nil {
			return nil, err
		}
	}

	conn, err := connectionFromFD(fd)
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = conn.Close()
		}
	}()

	buf := make([]byte, 35)
	if _, err := readFullContext(acceptCtx, conn, buf); err != nil {
		return nil, fmt.Errorf("the JVM connection was prematurely closed: %w", err)
	}

	expected := fmt.Sprintf("ATTACH_CONNECTED %016x ", key)
	if !bytes.Equal(buf[:len(expected)], []byte(expected)) {
		return nil, fmt.Errorf("unexpected JVM response %s", buf[:len(expected)])
	}

	cleanup = false
	return conn, nil
}

func connectionFromFD(fd int) (net.Conn, error) {
	file := os.NewFile(uintptr(fd), "openj9-attach")
	if file == nil {
		return nil, errors.Join(errors.New("could not own JVM connection"), syscall.Close(fd))
	}

	conn, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil {
		return nil, errors.Join(err, closeErr)
	}
	if closeErr != nil {
		return nil, errors.Join(closeErr, conn.Close())
	}
	return conn, nil
}

func (j *j9Attacher) lockNotificationFiles(ctx context.Context, tmpPath string) (int, error) {
	count := 0
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach")

	dir, err := os.Open(path)
	if err != nil {
		return 0, nil
	}
	defer dir.Close()

	entries, err := dir.Readdir(-1) // all files
	if err != nil {
		return 0, nil
	}

	for _, entry := range entries {
		if count >= MaxNotifyFiles {
			break
		}
		name := entry.Name()
		if len(name) > 0 && name[0] >= '1' && name[0] <= '9' && entry.IsDir() {
			fd, err := acquireLock(ctx, tmpPath, name, "attachNotificationSync")
			if err != nil {
				return count, err
			}
			j.notifyLock[count] = fd
			count++
		}
	}

	return count, nil
}

func (j *j9Attacher) unlockNotificationFiles(count int) error {
	var err error

	for i := range count {
		if j.notifyLock[i] >= 0 {
			err = errors.Join(err, releaseLock(j.notifyLock[i]))
			j.notifyLock[i] = -1
		}
	}

	return err
}

func (j *j9Attacher) releaseNotificationFiles(tmpPath string, count int) error {
	return errors.Join(
		j.unlockNotificationFiles(count),
		notifySemaphore(tmpPath, -1, count),
	)
}

func isOpenJ9Process(tmpPath string, pid int) bool {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "attachInfo")
	_, err := os.Stat(path)
	return err == nil
}

type j9Reader struct {
	connection *j9Connection
}

func (r *j9Reader) Read(p []byte) (int, error) {
	if r == nil || r.connection == nil {
		return 0, os.ErrClosed
	}
	return r.connection.read(p)
}

func (r *j9Reader) Close() error {
	if r == nil || r.connection == nil {
		return nil
	}
	return r.connection.closeGracefully()
}

func (r *j9Reader) Abort() error {
	if r == nil || r.connection == nil {
		return nil
	}
	return r.connection.abort()
}

func (*j9Reader) HandlesContextCancellation() {}

type j9Connection struct {
	ctx              context.Context
	conn             net.Conn
	closeOnce        sync.Once
	closeErr         error
	cancellationDone chan struct{}
	stopCancellation func() bool
}

func newJ9Connection(ctx context.Context, conn net.Conn) *j9Connection {
	connection := &j9Connection{
		ctx:              ctx,
		conn:             conn,
		cancellationDone: make(chan struct{}),
	}
	connection.stopCancellation = context.AfterFunc(ctx, func() {
		defer close(connection.cancellationDone)
		_ = conn.SetDeadline(time.Now())
	})
	return connection
}

func (c *j9Connection) read(p []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, os.ErrClosed
	}

	n, err := readConnectionContext(c.ctx, c.conn, p)
	if ctxErr := c.ctx.Err(); ctxErr != nil && n == 0 {
		return 0, errors.Join(ctxErr, c.abort())
	}
	return n, err
}

func (c *j9Connection) abort() error {
	if c == nil || c.conn == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closeErr = c.conn.Close()
		c.waitForCancellationCallback()
	})
	return c.closeErr
}

func (c *j9Connection) closeGracefully() error {
	if c == nil || c.conn == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		defer c.waitForCancellationCallback()
		if c.ctx.Err() != nil {
			c.closeErr = c.conn.Close()
			return
		}

		detachCtx, cancel := context.WithTimeout(c.ctx, openJ9DetachTimeout)
		defer cancel()

		var detachErr error
		if err := writeCommandContext(detachCtx, c.conn, "ATTACH_DETACHED"); err != nil {
			detachErr = err
		}

		buf := make([]byte, 256)
		if detachErr == nil {
			for {
				n, err := readConnectionContext(detachCtx, c.conn, buf)
				if err != nil || n <= 0 || buf[n-1] == 0 {
					if detachCtx.Err() != nil {
						detachErr = detachCtx.Err()
					} else if c.ctx.Err() != nil {
						detachErr = c.ctx.Err()
					}
					break
				}
			}
		}

		c.closeErr = errors.Join(detachErr, c.conn.Close())
	})
	return c.closeErr
}

func (c *j9Connection) waitForCancellationCallback() {
	if c.stopCancellation != nil && !c.stopCancellation() {
		<-c.cancellationDone
	}
}

func (j *j9Attacher) setConnection(connection *j9Connection) {
	j.mu.Lock()
	previous := j.connection
	j.connection = connection
	j.mu.Unlock()

	if previous != nil && previous != connection {
		_ = previous.abort()
	}
}

func (j *j9Attacher) clearConnection(connection *j9Connection) {
	j.mu.Lock()
	if j.connection == connection {
		j.connection = nil
	}
	j.mu.Unlock()
}

func (j *j9Attacher) abortConnection(connection *j9Connection) error {
	j.clearConnection(connection)
	return connection.abort()
}

func (j *j9Attacher) detach() error {
	j.mu.Lock()
	connection := j.connection
	j.connection = nil
	j.mu.Unlock()
	if connection == nil {
		return nil
	}
	return connection.closeGracefully()
}

func (j *j9Attacher) jattachOpenJ9(
	ctx context.Context,
	tmpPath string,
	nspid int,
	argv []string,
) (reader io.ReadCloser, err error) {
	attachLock, err := acquireLock(ctx, tmpPath, "", "_attachlock")
	if err != nil {
		return nil, fmt.Errorf("could not acquire attach lock: %w", err)
	}

	notifyCount := 0
	notificationPosted := false
	s := -1
	var port int
	var connection *j9Connection

	defer func() {
		var cleanupErr error
		if s >= 0 {
			cleanupErr = errors.Join(cleanupErr, closeAttachSocket(tmpPath, s, nspid))
		}
		if notifyCount > 0 {
			if notificationPosted {
				cleanupErr = errors.Join(cleanupErr, j.releaseNotificationFiles(tmpPath, notifyCount))
			} else {
				cleanupErr = errors.Join(cleanupErr, j.unlockNotificationFiles(notifyCount))
			}
		}
		if attachLock >= 0 {
			cleanupErr = errors.Join(cleanupErr, releaseLock(attachLock))
		}
		if err != nil && connection != nil {
			cleanupErr = errors.Join(cleanupErr, j.abortConnection(connection))
		}
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()

	s, port, err = createAttachSocket()
	if err != nil {
		return nil, fmt.Errorf("failed to listen to attach socket: %w", err)
	}

	key := randomKey()
	if err := writeReplyInfo(tmpPath, nspid, port, key); err != nil {
		return nil, fmt.Errorf("could not write replyInfo: %w", err)
	}

	notifyCount, err = j.lockNotificationFiles(ctx, tmpPath)
	if err != nil {
		return nil, fmt.Errorf("could not lock OpenJ9 notification files: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	notificationPosted = notifyCount > 0
	if err := notifySemaphore(tmpPath, 1, notifyCount); err != nil {
		return nil, fmt.Errorf("could not notify semaphore: %w", err)
	}

	conn, err := acceptClient(ctx, s, key)
	if err != nil {
		return nil, err
	}
	connection = newJ9Connection(ctx, conn)
	j.setConnection(connection)

	closeErr := closeAttachSocket(tmpPath, s, nspid)
	s = -1
	if closeErr != nil {
		return nil, fmt.Errorf("could not close attach socket: %w", closeErr)
	}

	notifyErr := j.releaseNotificationFiles(tmpPath, notifyCount)
	notifyCount = 0
	notificationPosted = false
	if notifyErr != nil {
		return nil, fmt.Errorf("could not release OpenJ9 notification files: %w", notifyErr)
	}

	releaseErr := releaseLock(attachLock)
	attachLock = -1
	if releaseErr != nil {
		return nil, fmt.Errorf("could not release OpenJ9 attach lock: %w", releaseErr)
	}

	j.logger.Info("connected to remote JVM")

	cmd := translateCommand(argv)

	if writeErr := writeCommandContext(ctx, conn, cmd); writeErr != nil {
		return nil, fmt.Errorf("error writing to socket: %w", writeErr)
	}

	return &j9Reader{connection: connection}, nil
}
