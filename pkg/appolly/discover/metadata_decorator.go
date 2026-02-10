// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// MetadataDecoratorProvider creates a metadata decorator based on the available environment.
// It automatically selects between Kubernetes and Docker decorators:
// - If Kubernetes is available and enabled, uses KubernetesMetadataDecorator
// - Otherwise, if Docker is available, uses DockerMetadataDecorator
// - If neither is available, bypasses the decoration stage
//
// This provides a unified interface so callers don't need to know about the specific
// implementation details of Kubernetes vs Docker metadata handling.
func MetadataDecoratorProvider(
	provider metadata.Provider,
	kubeInformer kubeMetadataProvider,
	dockerClient dockerAPIClient,
	input, output *msg.Queue[[]Event[ProcessAttrs]],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		// Try Kubernetes first (takes precedence)
		if kubeInformer != nil && kubeInformer.IsKubeEnabled() {
			if store, err := kubeInformer.Get(ctx); err == nil {
				// Use Kubernetes decorator with pod event handling
				// store is *kube.Store which implements meta.Notifier
				return KubernetesMetadataDecoratorProvider(
					provider,
					store, // *kube.Store implements meta.Notifier
					input,
					output,
				)(ctx)
			}
		}

		// Fall back to Docker if Kubernetes is not available
		if dockerClient != nil && dockerClient.IsEnabled(ctx) {
			// Use Docker decorator with synchronous metadata fetch
			return DockerMetadataDecoratorProvider(
				kubeInformer,
				dockerClient,
				input,
				output,
			)(ctx)
		}

		// No metadata source available, bypass
		return swarm.Bypass(input, output)
	}
}
