// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/appolly/meta"

import (
	"context"
	"slices"

	"go.opentelemetry.io/contrib/detectors/aws/ecs"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

func ecsNodeFetcher(ctx context.Context) (NodeMeta, error) {
	metadata, err := otelNodeFetcher(ecs.NewResourceDetector())(ctx)
	// OBI's task, container and log attributes do not describe every service on the node.
	metadata.Metadata = slices.DeleteFunc(metadata.Metadata, func(entry Entry) bool {
		switch entry.Key.OTEL() {
		case semconv.CloudProviderKey, semconv.CloudPlatformKey, semconv.CloudAccountIDKey,
			semconv.CloudRegionKey, semconv.CloudAvailabilityZoneKey, semconv.AWSECSClusterARNKey:
			return false
		default:
			return true
		}
	})
	return metadata, err
}
