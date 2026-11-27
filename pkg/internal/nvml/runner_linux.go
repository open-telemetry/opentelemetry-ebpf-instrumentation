// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nvml // import "go.opentelemetry.io/obi/pkg/internal/nvml"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
)

const (
	helperName = "obi-nvml-helper"

	// The child process receives the helper as its first inherited file, which is descriptor 3.
	helperPath = "/proc/self/fd/3"

	// Covers hosts where the NVIDIA driver is installed after OBI starts.
	restartDelay = time.Minute
)

// Run executes the embedded NVML helper and passes each sample it reports to
// handle, until ctx is done. The helper is started again when it exits, after
// handle receives an empty sample.
func Run(ctx context.Context, cfg RunnerConfig, handle func(sample.Sample)) {
	log := slog.With("component", "nvml.Runner")

	if len(embeddedHelper) == 0 {
		log.Error("this OBI build does not embed the NVML helper, GPU device metrics are disabled")
		return
	}

	reportedNoLibrary := false
	for {
		err := runOnce(ctx, cfg, handle)
		if ctx.Err() != nil {
			return
		}

		// The previous sample is no longer current.
		handle(sample.Sample{})

		switch {
		case !noLibrary(err):
			log.Warn("NVML helper stopped, it will be restarted", "error", err, "delay", restartDelay)
		case !reportedNoLibrary:
			// Expected on the hosts of a cluster that have no NVIDIA GPU.
			log.Info("no NVIDIA driver found, GPU device metrics wait for one", "error", err)
			reportedNoLibrary = true
		default:
			log.Debug("still no NVIDIA driver", "error", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(restartDelay):
		}
	}
}

func runOnce(ctx context.Context, cfg RunnerConfig, handle func(sample.Sample)) error {
	helper, err := helperFile()
	if err != nil {
		return err
	}
	defer helper.Close()

	cmd := exec.CommandContext(ctx, helperPath, "-interval", cfg.Interval.String())
	cmd.Args[0] = helperName
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{helper}
	// The helper needs the loader, the C library and the NVIDIA library of the host.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot:    cfg.HostRoot,
		Pdeathsig: syscall.SIGKILL,
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating the NVML helper output pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting the NVML helper in %s: %w", cfg.HostRoot, err)
	}

	readErr := readSamples(stdout, handle)

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}

	return readErr
}

func noLibrary(err error) bool {
	var exitErr *exec.ExitError

	return errors.As(err, &exitErr) && exitErr.ExitCode() == sample.ExitNoLibrary
}

// helperFile copies the embedded helper to an anonymous in-memory file, so
// that it can be executed without writing it to the host filesystem.
func helperFile() (*os.File, error) {
	fd, err := unix.MemfdCreate(helperName, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("creating the NVML helper file: %w", err)
	}

	file := os.NewFile(uintptr(fd), helperName)
	if _, err := file.Write(embeddedHelper); err != nil {
		return nil, errors.Join(fmt.Errorf("writing the NVML helper file: %w", err), file.Close())
	}

	return file, nil
}
