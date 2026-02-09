// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/docker"
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

func (d *DockerProvider) MetadataByPIDNs(pidns uint32) *Metadata {
	d.mu.RLock()
	defer d.mu.RUnlock()

	containerMeta, ok := d.pidNsToMeta[pidns]
	if !ok {
		return nil
	}

	return d.convertToMetadata(&containerMeta)
}

func (d *DockerProvider) MetadataByIP(_ string) *Metadata {
	// Docker provider does not YET support IP-based lookups
	return nil
}

func (d *DockerProvider) ServiceNameForIP(_ string) (string, string, string) {
	// Docker provider does not YET support service name resolution by IP
	return "", "", ""
}

func (d *DockerProvider) DecorateService(svc *svc.Attrs, pidns uint32) {
	d.mu.RLock()
	containerMeta, ok := d.pidNsToMeta[pidns]
	d.mu.RUnlock()

	if ok {
		containerMeta.DecorateService(svc)
	} else if svc.Metadata == nil {
		// Ensure metadata map is not nil
		svc.Metadata = map[attr.Name]string{}
	}
}

// convertToMetadata converts docker.ContainerMeta to unified Metadata structure.
func (d *DockerProvider) convertToMetadata(containerMeta *docker.ContainerMeta) *Metadata {
	otelAttrs := map[attr.Name]string{
		attr.ContainerName: containerMeta.Name,
		attr.ContainerID:   containerMeta.ID,
	}

	return &Metadata{
		Name:           containerMeta.Name,
		Namespace:      "",
		ContainerID:    containerMeta.ID,
		ContainerName:  containerMeta.Name,
		K8sMetadata:    nil, // Docker provider does not have Kubernetes metadata
		OTELAttributes: otelAttrs,
	}
}
