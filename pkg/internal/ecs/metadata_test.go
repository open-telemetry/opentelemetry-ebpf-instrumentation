// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ecs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectTaskMetadata(t *testing.T) {
	for _, tc := range []struct {
		name      string
		container string
		task      string
		wantError bool
	}{
		{name: "valid", container: "{}", task: `{"Cluster":"test","TaskARN":"arn:aws:ecs:us-east-1:123456789012:task/test/task-1"}`},
		{name: "invalid JSON", container: "{}", task: "{", wantError: true},
		{name: "invalid ARN", container: "{}", task: `{"TaskARN":"invalid"}`, wantError: true},
		{name: "incomplete log metadata", container: `{"LogDriver":"awslogs"}`, task: `{"Cluster":"test","TaskARN":"arn:aws:ecs:us-east-1:123456789012:task/test/task-1"}`, wantError: true},
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
			got, err := DetectTaskMetadata(t.Context())
			if tc.wantError {
				require.Error(t, err)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, TaskMetadata{Cluster: "arn:aws:ecs:us-east-1:123456789012:cluster/test", Region: "us-east-1"}, got)
		})
	}
}

func TestDetectTaskMetadataWithoutV4(t *testing.T) {
	for _, endpoint := range []string{"", "http://127.0.0.1:1"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Setenv("ECS_CONTAINER_METADATA_URI_V4", "")
			t.Setenv("ECS_CONTAINER_METADATA_URI", endpoint)
			got, err := DetectTaskMetadata(t.Context())
			require.NoError(t, err)
			require.Empty(t, got)
		})
	}
}

func TestDetectTaskMetadataCancellation(t *testing.T) {
	t.Setenv("ECS_CONTAINER_METADATA_URI_V4", "http://127.0.0.1:1")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := DetectTaskMetadata(ctx)
	require.ErrorIs(t, err, context.Canceled)
}
