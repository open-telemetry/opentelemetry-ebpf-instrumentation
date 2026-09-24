// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ecs // import "go.opentelemetry.io/obi/pkg/internal/ecs"

import (
	"context"
	"time"

	awsecs "go.opentelemetry.io/contrib/detectors/aws/ecs"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

const taskMetadataTimeout = 2 * time.Second

// TaskMetadata describes the ECS task running OBI and supplies resolver defaults.
type TaskMetadata struct {
	Cluster string
	Region  string
}

func DetectTaskMetadata(ctx context.Context) (TaskMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, taskMetadataTimeout)
	defer cancel()

	res, err := awsecs.NewResourceDetector().Detect(ctx)
	if err != nil || res == nil {
		return TaskMetadata{}, err
	}

	var metadata TaskMetadata
	for _, attr := range res.Attributes() {
		switch attr.Key {
		case semconv.AWSECSClusterARNKey:
			metadata.Cluster = attr.Value.AsString()
		case semconv.CloudRegionKey:
			metadata.Region = attr.Value.AsString()
		}
	}
	return metadata, nil
}
