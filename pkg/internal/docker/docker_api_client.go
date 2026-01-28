// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker // import "go.opentelemetry.io/obi/pkg/internal/docker"

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/docker/docker/client"

	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
)

func cmlog() *slog.Logger {
	return slog.With("component", "docker.ContainerStore")
}

type PID int32

var osInfoForPID = container.InfoForPID

type ContainerMeta struct {
	// TODO: add other fields https://opentelemetry.io/docs/specs/semconv/resource/container/
	Name string
}

// ContainerStore caches access to the Docker container API.
type ContainerStore struct {
	initMutex sync.Mutex
	docker    client.ContainerAPIClient
	log       *slog.Logger
}

func NewStore() *ContainerStore {
	return &ContainerStore{
		log: cmlog(),
	}
}

func (s *ContainerStore) IsEnabled(ctx context.Context) bool {
	if s == nil {
		return false
	}
	s.initMutex.Lock()
	defer s.initMutex.Unlock()
	s.initialize(ctx)
	return s.docker != nil
}

func (s *ContainerStore) initialize(ctx context.Context) {
	if s.docker != nil {
		return
	}
	docker, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		s.log.Debug("trying to instantiate docker client", "error", err)
		return
	}
	if info, err := docker.Info(ctx); err != nil {
		s.log.Debug("trying to get get docker info", "error", err)
		return
	} else {
		s.log.Info("Docker info",
			"driver", info.Driver,
			"version", info.ServerVersion,
			"cgroupDriver", info.CgroupDriver,
			"cgroupVersion", info.CgroupVersion)
	}
	s.docker = docker
}

func (s *ContainerStore) ContainerInfo(ctx context.Context, pid PID) (ContainerMeta, bool) {
	osCntInfo, err := osInfoForPID(uint32(pid))
	if err != nil {
		s.log.Debug("failed to get OS container info for pid", "pid", pid, "error", err)
		return ContainerMeta{}, false
	}
	inspectInfo, err := s.docker.ContainerInspect(ctx, osCntInfo.ContainerID)
	if err != nil {
		s.log.Debug("failed to inspect docker container",
			"pid", pid,
			"id", osCntInfo.ContainerID,
			"error", err)
		return ContainerMeta{}, false
	}
	cntInfo := ContainerMeta{
		// some containers start with '/'. Removing it
		Name: strings.Trim(inspectInfo.Name, "/"),
	}
	return cntInfo, true
}
