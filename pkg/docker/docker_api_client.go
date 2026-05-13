// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker // import "go.opentelemetry.io/obi/pkg/docker"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
)

const composeServiceLabelKey = "com.docker.compose.service"

func cmlog() *slog.Logger {
	return slog.With("component", "docker.ContainerStore")
}

var osInfoForPID = container.InfoForPID

type ContainerMeta struct {
	// TODO: add other fields https://opentelemetry.io/docs/specs/semconv/resource/container/
	ID             string
	Name           string
	ComposeService string
}

// dockerClient defines the Docker API methods needed by ContainerStore.
type dockerClient interface {
	ContainerInspect(ctx context.Context, container string, options client.ContainerInspectOptions) (client.ContainerInspectResult, error)
	Events(ctx context.Context, options client.EventsListOptions) client.EventsResult
}

// ContainerStore caches access to the Docker container API.
// The behavior can be overridden via environment variables:
//   - DOCKER_HOST to set the URL to the docker server.
//   - DOCKER_API_VERSION to set the version of the
//     API to use, leave empty for negotiation.
//   - DOCKER_CERT_PATH to specify the directory from
//     which to load the TLS certificates ("ca.pem", "cert.pem", "key.pem').
//   - DOCKER_TLS_VERIFY to enable or disable TLS verification
//     (off by default).
type ContainerStore struct {
	initMutex      sync.Mutex
	docker         dockerClient
	log            *slog.Logger
	watcherStarted sync.Once

	cacheMu sync.RWMutex
	byPID   map[app.PID]ContainerMeta
	byID    map[string][]app.PID
}

func NewStore() *ContainerStore {
	return &ContainerStore{
		log:   cmlog(),
		byPID: make(map[app.PID]ContainerMeta),
		byID:  make(map[string][]app.PID),
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

	docker, err := client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
		client.FromEnv,
	)
	if err != nil {
		s.log.Debug("trying to instantiate docker client", "error", err)
		return
	}
	if result, err := docker.Info(ctx, client.InfoOptions{}); err != nil {
		s.log.Debug("failed to get docker info", "error", err)
		return
	} else {
		s.log.Info("Docker info",
			"driver", result.Info.Driver,
			"version", result.Info.ServerVersion,
			"cgroupDriver", result.Info.CgroupDriver,
			"cgroupVersion", result.Info.CgroupVersion)
		s.docker = docker
	}
}

// ContainerInfo returns the ContainerMeta that is associated to the provided PID.
// It also returns true if the ContainerMeta was found for the provided PID. False otherwise
func (s *ContainerStore) ContainerInfo(ctx context.Context, pid app.PID) (ContainerMeta, bool) {
	s.cacheMu.RLock()
	if ci, ok := s.byPID[pid]; ok {
		s.cacheMu.RUnlock()
		return ci, true
	}
	s.cacheMu.RUnlock()

	osCntInfo, err := osInfoForPID(pid)
	if err != nil {
		s.log.Debug("failed to get OS container info for pid", "pid", pid, "error", err)
		return ContainerMeta{}, false
	}
	inspectResult, err := s.docker.ContainerInspect(ctx, osCntInfo.ContainerID, client.ContainerInspectOptions{})
	if err != nil {
		s.log.Debug("failed to inspect docker container",
			"pid", pid,
			"id", osCntInfo.ContainerID,
			"error", err)
		return ContainerMeta{}, false
	}

	inspectInfo := inspectResult.Container
	const abbreviationLength = 12
	containerID := inspectInfo.ID
	if len(containerID) > abbreviationLength {
		containerID = containerID[:abbreviationLength]
	}

	composeSvcName := ""
	if inspectInfo.Config != nil && len(inspectInfo.Config.Labels) > 0 {
		composeSvcName = inspectInfo.Config.Labels[composeServiceLabelKey]
	}

	meta := ContainerMeta{
		// some containers start with '/'. Removing it
		Name:           strings.Trim(inspectInfo.Name, "/"),
		ID:             containerID,
		ComposeService: composeSvcName,
	}

	s.cacheMu.Lock()
	s.byPID[pid] = meta
	s.byID[inspectInfo.ID] = append(s.byID[inspectInfo.ID], pid)
	s.cacheMu.Unlock()

	return meta, true
}

func (ci *ContainerMeta) DecorateService(s *svc.Attrs) {
	s.Metadata = ContainerMetadata(s.Metadata, ci, func(n attr.Name) attr.Name {
		return n
	})

	if s.AutoName() {
		// populate service name from container metadata
		if ci.ComposeService != "" {
			s.UID.Name = ci.ComposeService
		} else {
			s.UID.Name = ci.Name
		}
	}
	// overriding the Instance here will avoid reusing the OTEL resource reporter
	// if the application/process was discovered and reported information
	// before the docker metadata was available
	// Service Instance ID is set according to OTEL collector conventions.
	if s.UID.Namespace == "" {
		if ci.ComposeService == "" {
			s.UID.Instance = ci.Name
		} else {
			s.UID.Instance = ci.ComposeService + "." + ci.Name
		}
	} else {
		s.UID.Instance = s.UID.Namespace + "." + s.UID.Name + "." + ci.Name
	}
}

func ContainerMetadata[T ~string](dst map[T]string, ci *ContainerMeta, stringer func(attr.Name) T) map[T]string {
	// Copy map to avoid concurrent read/write on shared Metadata
	var out map[T]string
	if dst == nil {
		out = map[T]string{}
	} else {
		out = maps.Clone(dst)
	}
	out[stringer(attr.ContainerName)] = ci.Name
	out[stringer(attr.ContainerID)] = ci.ID
	return out
}

// Start begins the event watcher goroutine to invalidate and remove
// metadata of destroyed containers.
func (s *ContainerStore) Start(ctx context.Context) {
	s.watcherStarted.Do(func() {
		s.initMutex.Lock()
		s.initialize(ctx)
		s.initMutex.Unlock()
		go s.watchContainerEvents(ctx)
	})
}

func (s *ContainerStore) watchContainerEvents(ctx context.Context) {
	s.initMutex.Lock()
	if s.docker == nil {
		s.initMutex.Unlock()
		return
	}
	s.initMutex.Unlock()

	fltrs := make(client.Filters).
		Add("type", string(events.ContainerEventType)).
		Add("event", string(events.ActionDie), string(events.ActionDestroy))

	for {
		if err := s.eventsLoop(ctx, fltrs); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Debug("docker event stream error", "error", err)
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *ContainerStore) eventsLoop(ctx context.Context, fltrs client.Filters) error {
	result := s.docker.Events(ctx, client.EventsListOptions{Filters: fltrs})
	for {
		select {
		case msg, ok := <-result.Messages:
			if !ok {
				return nil
			}
			if msg.Actor.ID != "" {
				s.invalidateContainer(msg.Actor.ID)
			}
		case err, ok := <-result.Err:
			if !ok || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-ctx.Done():
			return context.Canceled
		}
	}
}

func (s *ContainerStore) invalidatePID(pid app.PID) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	meta, ok := s.byPID[pid]
	if !ok {
		return
	}
	delete(s.byPID, pid)

	pids := s.byID[meta.ID][:0]
	for _, cachedPID := range s.byID[meta.ID] {
		if cachedPID != pid {
			pids = append(pids, cachedPID)
		}
	}

	if len(pids) == 0 {
		delete(s.byID, meta.ID)
		return
	}
	s.byID[meta.ID] = pids
}

func (s *ContainerStore) invalidateContainer(containerID string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	for _, pid := range s.byID[containerID] {
		delete(s.byPID, pid)
	}
	delete(s.byID, containerID)
}
