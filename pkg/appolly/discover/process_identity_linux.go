// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type identityStableProcessHandle struct {
	mu sync.Mutex
	fd int
}

func openIdentityStableProcessHandle(pid int) (*identityStableProcessHandle, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	return &identityStableProcessHandle{fd: fd}, nil
}

func (h *identityStableProcessHandle) Signal(signal syscall.Signal) error {
	if h == nil {
		return errors.New("process handle is closed")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fd < 0 {
		return errors.New("process handle is closed")
	}
	return unix.PidfdSendSignal(h.fd, signal, nil, 0)
}

func (h *identityStableProcessHandle) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fd < 0 {
		return nil
	}
	err := unix.Close(h.fd)
	h.fd = -1
	return err
}

func processRootIdentity(
	processRoot *os.File,
) (startTime, dev, ino uint64, err error) {
	if processRoot == nil {
		return 0, 0, 0, errors.New("process root is unavailable")
	}

	statFD, err := unix.Openat(
		int(processRoot.Fd()),
		"stat",
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, 0, 0, err
	}
	statFile := os.NewFile(uintptr(statFD), "stat")
	if statFile == nil {
		_ = unix.Close(statFD)
		return 0, 0, 0, errors.New("can't create process stat file")
	}
	statContents, readErr := io.ReadAll(io.LimitReader(statFile, procStatBufSize))
	closeErr := statFile.Close()
	if readErr != nil {
		return 0, 0, 0, readErr
	}
	if closeErr != nil {
		return 0, 0, 0, closeErr
	}
	startTimeTicks, err := strconv.ParseUint(
		parseProcStatField(string(statContents), 22),
		10,
		64,
	)
	if err != nil {
		return 0, 0, 0, err
	}

	var executableStat unix.Stat_t
	if err := unix.Fstatat(
		int(processRoot.Fd()),
		"exe",
		&executableStat,
		0,
	); err != nil {
		return 0, 0, 0, err
	}
	return ticksToNanosecond(startTimeTicks),
		executableStat.Dev,
		executableStat.Ino,
		nil
}

func livePendingProcessIdentityMatches(
	fileInfo *exec.FileInfo,
	processRoot *os.File,
) bool {
	if fileInfo == nil {
		return false
	}
	startTime, dev, ino, err := processRootIdentity(processRoot)
	return err == nil &&
		startTime == fileInfo.StartTime() &&
		dev == fileInfo.Dev() &&
		ino == fileInfo.Ino()
}

func executablePathThroughProcessRoot(processRoot *os.File) (string, error) {
	if processRoot == nil {
		return "", errors.New("process root is unavailable")
	}
	return fmt.Sprintf("/proc/self/fd/%d/exe", processRoot.Fd()), nil
}

func filesystemRootPathThroughProcessRoot(processRoot *os.File) (string, error) {
	if processRoot == nil {
		return "", errors.New("process root is unavailable")
	}
	return fmt.Sprintf("/proc/self/fd/%d/root", processRoot.Fd()), nil
}
