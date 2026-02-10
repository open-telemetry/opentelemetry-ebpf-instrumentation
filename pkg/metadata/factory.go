// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/docker"
	"go.opentelemetry.io/obi/pkg/kube"
)

func mlog() *slog.Logger {
	return slog.With("component", "metadata.Factory")
}

// kubeMetadataProvider abstracts kube.MetadataProvider for easier dependency injection
type kubeMetadataProvider interface {
	IsKubeEnabled() bool
	Get(context.Context) (*kube.Store, error)
}

// NewProvider creates a composite metadata provider from available sources.
// It combines multiple metadata providers into a single provider that can decorate
// with metadata from multiple sources (e.g., Kubernetes + Cloud provider in the future).
//
// Container/Pod providers (Kubernetes, Docker) are mutually exclusive:
//   - If Kubernetes is available, it is used for container/pod metadata
//   - Otherwise, Docker is used if available
//
// Additional providers (e.g., Cloud provider metadata) can be added alongside
// the container provider in the future.
//
// Returns a CompositeProvider that may contain multiple providers or be empty (no-op).
func NewProvider(
	ctx context.Context,
	kubeProvider kubeMetadataProvider,
	dockerStore *docker.ContainerStore,
	clusterName string,
) Provider {
	log := mlog()
	var providers []Provider

	// Container/Pod metadata provider (mutually exclusive: Kubernetes OR Docker)
	if kubeProvider != nil && kubeProvider.IsKubeEnabled() {
		store, err := kubeProvider.Get(ctx)
		if err != nil {
			log.Warn("failed to get Kubernetes store", "error", err)
		} else {
			log.Info("adding Kubernetes metadata provider")
			providers = append(providers, NewKubernetesProvider(store, clusterName))
		}
	} else if dockerStore != nil && dockerStore.IsEnabled(ctx) {
		// Only use Docker if Kubernetes is not available
		log.Info("adding Docker metadata provider")
		providers = append(providers, NewDockerProvider(ctx, dockerStore))
	}

	// Future providers (e.g., Cloud metadata) would be added here:
	// if cloudProvider != nil {
	//     log.Info("adding Cloud metadata provider")
	//     providers = append(providers, NewCloudProvider(cloudProvider))
	// }

	if len(providers) == 0 {
		log.Info("no metadata providers available (will operate as no-op)")
	} else {
		log.Info("initialized composite metadata provider", "count", len(providers))
	}

	return NewCompositeProvider(providers...)
}
