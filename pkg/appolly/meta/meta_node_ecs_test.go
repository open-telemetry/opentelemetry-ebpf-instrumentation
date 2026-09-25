// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

func TestECSNodeFetcher(t *testing.T) {
	for _, tc := range []struct {
		name      string
		container string
		task      string
		wantEmpty bool
	}{
		{
			name:      "shared metadata",
			container: `{"ContainerARN":"arn:aws:ecs:us-east-1:123456789012:container/test/obi","LogDriver":"awslogs","LogOptions":{"awslogs-group":"obi","awslogs-stream":"obi/task","awslogs-region":"us-east-1"}}`,
			task:      `{"Cluster":"test","TaskARN":"arn:aws:ecs:us-east-1:123456789012:task/test/task-1","AvailabilityZone":"us-east-1a","Family":"obi","Revision":"1","LaunchType":"EC2"}`,
		},
		{name: "invalid JSON", container: "{}", task: "{", wantEmpty: true},
		{name: "invalid ARN", container: "{}", task: `{"TaskARN":"invalid"}`, wantEmpty: true},
		{name: "incomplete log metadata", container: `{"LogDriver":"awslogs"}`, task: `{"Cluster":"test","TaskARN":"arn:aws:ecs:us-east-1:123456789012:task/test/task-1"}`, wantEmpty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/task" {
					fmt.Fprint(w, tc.task)
					return
				}
				fmt.Fprint(w, tc.container)
			}))
			defer server.Close()
			t.Setenv("ECS_CONTAINER_METADATA_URI_V4", server.URL)
			t.Setenv("ECS_CONTAINER_METADATA_URI", "")
			got, err := ecsNodeFetcher(t.Context())
			require.NoError(t, err)
			if tc.wantEmpty {
				require.Empty(t, got.Cluster)
				require.Empty(t, got.Region)
				require.Empty(t, got.Metadata)
				return
			}
			assert.Equal(t, "arn:aws:ecs:us-east-1:123456789012:cluster/test", got.Cluster)
			assert.Equal(t, "us-east-1", got.Region)
			// Exact matching excludes the detector's OBI-specific task, container and log attributes.
			assert.ElementsMatch(t, []Entry{
				{Key: "cloud.provider", Value: "aws"},
				{Key: "cloud.platform", Value: "aws_ecs"},
				{Key: "cloud.account.id", Value: "123456789012"},
				{Key: "cloud.region", Value: "us-east-1"},
				{Key: "cloud.availability_zone", Value: "us-east-1a"},
				{Key: "aws.ecs.cluster.arn", Value: "arn:aws:ecs:us-east-1:123456789012:cluster/test"},
			}, got.Metadata)
		})
	}
}

func TestECSNodeFetcherWithoutV4(t *testing.T) {
	for _, endpoint := range []string{"", "http://127.0.0.1:1"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Setenv("ECS_CONTAINER_METADATA_URI_V4", "")
			t.Setenv("ECS_CONTAINER_METADATA_URI", endpoint)
			got, err := ecsNodeFetcher(t.Context())
			require.NoError(t, err)
			assert.Empty(t, got.Cluster)
			assert.Empty(t, got.Region)
			if endpoint == "" {
				assert.Empty(t, got.Metadata)
			} else {
				assert.ElementsMatch(t, []Entry{{Key: "cloud.provider", Value: "aws"}, {Key: "cloud.platform", Value: "aws_ecs"}}, got.Metadata)
			}
		})
	}
}

func TestECSNodeFetcherCancellation(t *testing.T) {
	t.Setenv("ECS_CONTAINER_METADATA_URI_V4", "http://127.0.0.1:1")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := ecsNodeFetcher(ctx)
	require.NoError(t, err)
	assert.Empty(t, got.Cluster)
	assert.Empty(t, got.Region)
	assert.Empty(t, got.Metadata)
}

func TestNodeMetaCloudDefaults(t *testing.T) {
	first := otelNodeFetcher(resource.StringDetector(semconv.SchemaURL, semconv.CloudRegionKey, func() (string, error) { return "ec2-region", nil }))
	second := otelNodeFetcher(resource.StringDetector(semconv.SchemaURL, semconv.AWSECSClusterARNKey, func() (string, error) { return "ecs-cluster", nil }))
	third := otelNodeFetcher(resource.StringDetector(semconv.SchemaURL, semconv.CloudRegionKey, func() (string, error) { return "ecs-region", nil }))
	got := fetchEntries(t.Context(), DefaultRetryConfig, first, second, third, func(context.Context) (NodeMeta, error) { return NodeMeta{HostID: "override"}, nil })
	assert.Equal(t, "ecs-cluster", got.Cluster)
	assert.Equal(t, "ecs-region", got.Region)
	assert.Equal(t, "override", got.HostID)
	assert.ElementsMatch(t, []Entry{{Key: "cloud.region", Value: "ecs-region"}, {Key: "aws.ecs.cluster.arn", Value: "ecs-cluster"}}, got.Metadata)
}

func TestNewNodeMetaECS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/task" {
			fmt.Fprint(w, `{"Cluster":"test","TaskARN":"arn:aws:ecs:us-east-1:123456789012:task/test/task-1"}`)
			return
		}
		fmt.Fprint(w, "{}")
	}))
	defer server.Close()
	t.Setenv("ECS_CONTAINER_METADATA_URI_V4", server.URL)
	t.Setenv("ECS_CONTAINER_METADATA_URI", "")
	got := NewNodeMeta(t.Context(), "host-override", nil, DefaultRetryConfig)
	assert.Equal(t, "host-override", got.HostID)
	assert.Equal(t, "arn:aws:ecs:us-east-1:123456789012:cluster/test", got.Cluster)
	assert.Equal(t, "us-east-1", got.Region)
	assert.Contains(t, got.Metadata, Entry{Key: "aws.ecs.cluster.arn", Value: got.Cluster})
	assert.Contains(t, got.Metadata, Entry{Key: "cloud.region", Value: got.Region})
	assert.Contains(t, got.Metadata, Entry{Key: "cloud.platform", Value: "aws_ecs"})
}
