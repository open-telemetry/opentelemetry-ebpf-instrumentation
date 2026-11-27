// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/internal/gpuolly/agent"

import (
	"bytes"
	"context"
	"os"
	"strconv"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/gpuolly"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/transform"
)

// processResolver finds the name and the Kubernetes pod of the processes that use a GPU.
type processResolver struct {
	// store is nil when OBI does not run in Kubernetes.
	store       *kube.Store
	clusterName string
}

func newProcessResolver(ctx context.Context, ctxInfo *global.ContextInfo, cfg *obi.Config) *processResolver {
	if ctxInfo.K8sInformer == nil || !ctxInfo.K8sInformer.IsKubeEnabled() {
		return &processResolver{}
	}

	store, err := ctxInfo.K8sInformer.Get(ctx)
	if err != nil {
		alog().Warn("GPU process metrics will not have Kubernetes attributes", "error", err)
		return &processResolver{}
	}

	return &processResolver{
		store: store,
		clusterName: transform.KubeClusterNameWithMetadataProvider(ctx, &cfg.Attributes.Kubernetes,
			&metadata.MetadataProvider{K8sInformer: ctxInfo.K8sInformer, CloudMetadata: cfg.CloudMetadata}),
	}
}

func (r *processResolver) resolve(pid uint32) *gpuolly.Process {
	process := &gpuolly.Process{PID: pid}
	if comm, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/comm"); err == nil {
		process.ExecutableName = string(bytes.TrimSpace(comm))
	}

	if r.store == nil {
		return process
	}

	info, err := container.InfoForPID(app.PID(pid))
	if err != nil {
		return process
	}

	pod := r.store.PodByContainerID(info.ContainerID)
	if pod == nil || pod.Meta == nil || pod.Meta.Pod == nil {
		return process
	}

	var containerName string
	for _, c := range pod.Meta.Pod.Containers {
		if c.Id == info.ContainerID {
			containerName = c.Name
		}
	}

	// The same Kubernetes attributes as the application metrics.
	fi := &exec.FileInfo{}
	transform.AppendKubeMetadata(r.store, fi, pod, r.clusterName, containerName)
	process.Metadata = fi.ServiceAttrs().Metadata

	return process
}
