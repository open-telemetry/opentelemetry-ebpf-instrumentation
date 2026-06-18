// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"errors"
	"log/slog"
	"os"
	"sync"

	v2 "github.com/containers/common/pkg/cgroupv2"
	"golang.org/x/sys/unix"
)

const (
	// selfMountPath is where OBI mounts its own cgroupv2 hierarchy when
	// the host has no unified or hybrid mount available.
	selfMountPath = "/run/obi-cgroupv2"
	selfMountPerm = 0o700

	cgroupFSRoot   = "/sys/fs/cgroup"
	cgroupV2Hybrid = "/sys/fs/cgroup/unified"
	cgroup2Magic   = 0x63677270
)

var errNoCgroupV2 = errors.New("no cgroupv2 hierarchy found")

type cgroupV2Result struct {
	path string
	err  error
}

var cgroupV2Once = sync.OnceValue(func() cgroupV2Result {
	log := slog.With("component", "ebpf.cgroupv2")
	if enabled, err := v2.Enabled(); err == nil && enabled {
		return cgroupV2Result{path: cgroupFSRoot}
	}
	if _, err := os.Stat(cgroupV2Hybrid); err == nil {
		return cgroupV2Result{path: cgroupV2Hybrid}
	}
	if p, err := selfMountCgroupV2(log); err == nil {
		return cgroupV2Result{path: p}
	} else {
		log.Warn("could not self-mount cgroupv2", "path", selfMountPath, "error", err)
	}
	return cgroupV2Result{err: errNoCgroupV2}
})

func selfMountCgroupV2(log *slog.Logger) (string, error) {
	if isCgroup2Mount(selfMountPath) {
		return selfMountPath, nil
	}
	if err := os.MkdirAll(selfMountPath, selfMountPerm); err != nil {
		return "", err
	}
	if err := unix.Mount("none", selfMountPath, "cgroup2", 0, ""); err != nil {
		return "", err
	}
	log.Info("self-mounted cgroup2 hierarchy", "path", selfMountPath)
	return selfMountPath, nil
}

func isCgroup2Mount(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return st.Type == cgroup2Magic
}

func CgroupV2Path() (string, error) {
	r := cgroupV2Once()
	return r.path, r.err
}
