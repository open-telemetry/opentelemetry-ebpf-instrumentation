// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/docker"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
)

// DockerProvider wraps docker.ContainerStore to implement the Provider interface.
type DockerProvider struct {
	store *docker.ContainerStore
	ctx   context.Context
	log   *slog.Logger

	// Internal caches for reverse lookups
	mu             sync.RWMutex
	pidToPidNs     map[app.PID]uint32
	pidNsToMeta    map[uint32]docker.ContainerMeta
	containerByPID map[app.PID]docker.ContainerMeta
}

var _ Provider = (*DockerProvider)(nil)

// injectable function for testing
var containerInfoForPID = container.InfoForPID

// NewDockerProvider creates a new Docker metadata provider.
func NewDockerProvider(ctx context.Context, store *docker.ContainerStore) *DockerProvider {
	return &DockerProvider{
		store:          store,
		ctx:            ctx,
		log:            slog.With("component", "metadata.DockerProvider"),
		pidToPidNs:     make(map[app.PID]uint32),
		pidNsToMeta:    make(map[uint32]docker.ContainerMeta),
		containerByPID: make(map[app.PID]docker.ContainerMeta),
	}
}

func (d *DockerProvider) AddProcess(pid app.PID) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get container info from Docker
	containerMeta, ok := d.store.ContainerInfo(d.ctx, pid)
	if !ok {
		d.log.Debug("no container info for PID", "pid", pid)
		return
	}

	// Get PID namespace for reverse lookup
	cntInfo, err := containerInfoForPID(pid)
	if err != nil {
		d.log.Debug("failed to get container namespace info", "pid", pid, "error", err)
		return
	}

	d.log.Debug("adding process to Docker provider",
		"pid", pid,
		"pidns", cntInfo.PIDNamespace,
		"containerID", cntInfo.ContainerID)

	d.pidToPidNs[pid] = cntInfo.PIDNamespace
	d.pidNsToMeta[cntInfo.PIDNamespace] = containerMeta
	d.containerByPID[pid] = containerMeta
}

func (d *DockerProvider) DeleteProcess(pid app.PID) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if pidns, ok := d.pidToPidNs[pid]; ok {
		delete(d.pidNsToMeta, pidns)
		delete(d.pidToPidNs, pid)
	}
	delete(d.containerByPID, pid)

	d.log.Debug("deleted process from Docker provider", "pid", pid)
}

func (d *DockerProvider) GetMetadataEntries(pidns uint32) []MetadataEntry {
	d.mu.RLock()
	containerMeta, ok := d.pidNsToMeta[pidns]
	d.mu.RUnlock()

	if !ok {
		return nil
	}

	return buildDockerMetadataEntries(&containerMeta)
}

func (d *DockerProvider) GetMetadataEntriesByIP(_ string) []MetadataEntry {
	// Docker provider does not support IP-based lookups
	return nil
}

func (d *DockerProvider) GetServiceName(_ string) ServiceInfo {
	// Docker provider does not support service name resolution by IP
	return ServiceInfo{}
}

// DecorateService provides backward compatibility by applying metadata and service identity.
func (d *DockerProvider) DecorateService(svc *svc.Attrs, pidns uint32) {
	d.mu.RLock()
	containerMeta, ok := d.pidNsToMeta[pidns]
	d.mu.RUnlock()

	if ok {
		containerMeta.DecorateService(svc)
	}
}

// buildDockerMetadataEntries constructs Docker metadata entries from container metadata.
func buildDockerMetadataEntries(containerMeta *docker.ContainerMeta) []MetadataEntry {
	return []MetadataEntry{
		{Key: attr.ContainerName, Value: containerMeta.Name},
		{Key: attr.ContainerID, Value: containerMeta.ID},
	}
}
