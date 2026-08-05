// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type nativeGoAutoSDKProcessAccess struct{}

type nativeGoAutoSDKProcessSession struct {
	memory *os.File
	stat   *os.File
}

func newGoAutoSDKProcessAccess() goAutoSDKProcessAccess {
	return nativeGoAutoSDKProcessAccess{}
}

func (nativeGoAutoSDKProcessAccess) Open(
	processRoot *os.File,
	fileInfo *exec.FileInfo,
) (goAutoSDKProcessSession, error) {
	if processRoot == nil || fileInfo == nil {
		return nil, errors.New("exact process root is unavailable")
	}
	memory, err := openGoAutoSDKProcessFile(processRoot, "mem", unix.O_RDWR)
	if err != nil {
		return nil, err
	}
	stat, err := openGoAutoSDKProcessFile(processRoot, "stat", unix.O_RDONLY)
	if err != nil {
		_ = memory.Close()
		return nil, err
	}
	executable, err := openGoAutoSDKProcessFile(
		processRoot,
		"exe",
		unix.O_RDONLY,
	)
	if err != nil {
		return nil, errors.Join(err, stat.Close(), memory.Close())
	}
	info, err := executable.Stat()
	closeErr := executable.Close()
	if err != nil {
		return nil, errors.Join(err, closeErr, stat.Close(), memory.Close())
	}
	statInfo, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.Join(
			errors.New("reading exact process executable identity failed"),
			closeErr,
			stat.Close(),
			memory.Close(),
		)
	}
	if statInfo.Dev != fileInfo.Dev() ||
		statInfo.Ino != fileInfo.Ino() {
		return nil, errors.Join(
			errors.New("exact process executable changed before admission"),
			closeErr,
			stat.Close(),
			memory.Close(),
		)
	}
	if closeErr != nil {
		return nil, errors.Join(closeErr, stat.Close(), memory.Close())
	}

	return &nativeGoAutoSDKProcessSession{
		memory: memory,
		stat:   stat,
	}, nil
}

func openGoAutoSDKProcessFile(
	processRoot *os.File,
	name string,
	flags int,
) (*os.File, error) {
	fd, err := unix.Openat(
		int(processRoot.Fd()),
		name,
		flags|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("creating exact process file handle failed")
	}
	return file, nil
}

func (s *nativeGoAutoSDKProcessSession) Read(addr uint64) (byte, error) {
	if addr > math.MaxInt64 {
		return 0, errors.New("process memory address exceeds signed file offset")
	}
	value := []byte{0}
	n, err := s.memory.ReadAt(value, int64(addr))
	if err := goAutoSDKProcessReadResult(n, len(value), err); err != nil {
		return 0, err
	}
	return value[0], nil
}

func (s *nativeGoAutoSDKProcessSession) Write(addr uint64, value byte) error {
	if addr > math.MaxInt64 {
		return errors.New("process memory address exceeds signed file offset")
	}
	buf := []byte{value}
	n, err := s.memory.WriteAt(buf, int64(addr))
	return goAutoSDKProcessWriteResult(n, len(buf), err)
}

func (s *nativeGoAutoSDKProcessSession) StartTime() (uint64, error) {
	var buf [4096]byte
	n, err := s.stat.ReadAt(buf[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	if n == 0 {
		return 0, errors.New("process stat is empty")
	}
	if n == len(buf) {
		return 0, errors.New("process stat exceeds buffer")
	}
	return goAutoSDKStartTimeFromStat(buf[:n])
}

func (s *nativeGoAutoSDKProcessSession) Close() error {
	return errors.Join(s.stat.Close(), s.memory.Close())
}

func goAutoSDKProcessReadResult(n, expected int, err error) error {
	if n == expected && (err == nil || errors.Is(err, io.EOF)) {
		return nil
	}
	if n == 0 && errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %w", errGoAutoSDKProcessMemoryGone, err)
	}
	if err != nil {
		return err
	}
	return fmt.Errorf(
		"%w: read %d bytes, expected %d",
		errGoAutoSDKProcessMemoryGone,
		n,
		expected,
	)
}

func goAutoSDKProcessWriteResult(n, expected int, err error) error {
	if n == expected && err == nil {
		return nil
	}
	if n == 0 && errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", errGoAutoSDKProcessMemoryGone, err)
	}
	if err != nil {
		return err
	}
	return fmt.Errorf(
		"%w: wrote %d bytes, expected %d",
		errGoAutoSDKProcessMemoryGone,
		n,
		expected,
	)
}

func goAutoSDKStartTimeFromStat(data []byte) (uint64, error) {
	commEnd := strings.LastIndexByte(string(data), ')')
	if commEnd < 0 {
		return 0, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(data[commEnd+1:]))
	const startTimeIndex = 22 - 3
	if len(fields) <= startTimeIndex {
		return 0, errors.New("process stat has no start time")
	}
	ticks, err := strconv.ParseUint(fields[startTimeIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing process start time: %w", err)
	}
	const nanosecondsPerClockTick = uint64(time.Second) / 100
	if ticks == 0 || ticks > math.MaxUint64/nanosecondsPerClockTick {
		return 0, errors.New("invalid process start time")
	}
	return ticks * nanosecondsPerClockTick, nil
}

func goAutoSDKProcessGone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH)
}
