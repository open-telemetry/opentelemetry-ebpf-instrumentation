// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

func TestOtelNodeFetcher(t *testing.T) {
	detected := resource.NewWithAttributes(semconv.SchemaURL,
		semconv.HostIDKey.String("host-123"),
		semconv.AWSECSClusterARNKey.String("arn:aws:ecs:us-east-1:123456789012:cluster/test"),
		semconv.CloudRegionKey.String("us-east-1"),
		semconv.CloudProviderKey.String("aws"),
	)
	want := NodeMeta{
		Features: ClusterECS,
		HostID:   "host-123",
		Cluster:  "arn:aws:ecs:us-east-1:123456789012:cluster/test",
		Region:   "us-east-1",
		Metadata: []Entry{
			{Key: "aws.ecs.cluster.arn", Value: "arn:aws:ecs:us-east-1:123456789012:cluster/test"},
			{Key: "cloud.provider", Value: "aws"},
			{Key: "cloud.region", Value: "us-east-1"},
		},
	}
	for _, tc := range []struct {
		name     string
		resource *resource.Resource
		attempts int
		want     NodeMeta
	}{
		{name: "first attempt succeeds", resource: detected, attempts: 1, want: want},
		{name: "second attempt succeeds", resource: detected, attempts: 2, want: want},
		{name: "nil resource", attempts: 1},
		{name: "empty resource", resource: resource.Empty(), attempts: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			detector := mockNodeDetector(func(context.Context) (*resource.Resource, error) {
				attempts++
				if attempts < tc.attempts {
					return resource.Empty(), fmt.Errorf("metadata unavailable: %w", resource.ErrPartialResource)
				}
				return tc.resource, nil
			})

			got, err := otelNodeFetcher(ClusterECS, detector)(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.attempts, attempts)
		})
	}

	t.Run("detector does not return before timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			detector := mockNodeDetector(func(context.Context) (*resource.Resource, error) {
				<-release
				return detected, nil
			})

			start := time.Now()
			got, err := otelNodeFetcher(ClusterECS, detector)(t.Context())
			require.NoError(t, err)
			assert.Equal(t, NodeMeta{}, got)
			assert.Equal(t, connectionTimeout, time.Since(start))
		})
	})
}

type mockNodeDetector func(context.Context) (*resource.Resource, error)

func (d mockNodeDetector) Detect(ctx context.Context) (*resource.Resource, error) {
	return d(ctx)
}
