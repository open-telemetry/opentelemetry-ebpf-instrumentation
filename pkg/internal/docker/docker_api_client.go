package docker

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/docker/docker/client"

	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
)

func cmlog() *slog.Logger {
	return slog.With("component", "docker.APIClient")
}

type PID int32

var osInfoForPID = container.InfoForPID

type ContainerMeta struct {
	// TODO: add other fields https://opentelemetry.io/docs/specs/semconv/resource/container/
	Name string
}

type APIClient struct {
	initMutex sync.Mutex
	docker    client.ContainerAPIClient
	log       *slog.Logger
}

func NewStore() *APIClient {
	return &APIClient{
		log: cmlog(),
	}
}

func (s *APIClient) IsEnabled(ctx context.Context) bool {
	s.initMutex.Lock()
	defer s.initMutex.Unlock()
	s.initialize(ctx)
	return s.docker != nil
}

func (s *APIClient) initialize(ctx context.Context) error {
	if s.docker != nil {
		return nil
	}
	docker, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("instantiating docker client: %w", err)
	}
	if info, err := docker.Info(ctx); err != nil {
		return err
	} else {
		s.log.Info("Docker info",
			"driver", info.Driver,
			"version", info.ServerVersion,
			"cgroupDriver", info.CgroupDriver,
			"cgroupVersion", info.CgroupVersion)
	}
	s.docker = docker
	return nil
}

func (s *APIClient) ContainerInfo(ctx context.Context, pid PID) (ContainerMeta, bool) {
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
		Name: inspectInfo.Name,
	}
	return cntInfo, true
}
