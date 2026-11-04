// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/metadata"
)

func TestGCEResolverConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cfg       GCENameResolverConfig
		interval  time.Duration
		wantError string
	}{
		{name: "zero refresh interval", wantError: "positive refresh interval"},
		{name: "negative refresh interval", interval: -time.Second, wantError: "positive refresh interval"},
		{name: "invalid endpoint", interval: time.Second, cfg: GCENameResolverConfig{Endpoint: "file:///tmp/mock"}, wantError: "HTTP(S) base URL"},
		{name: "endpoint credentials", interval: time.Second, cfg: GCENameResolverConfig{Endpoint: "https://user:password@example.com/"}, wantError: "HTTP(S) base URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := metadata.NodeMeta{Metadata: []metadata.Entry{
				{Key: attr.Name(semconv.CloudPlatformKey), Value: semconv.CloudPlatformGCPComputeEngine.Value.AsString()},
				{Key: attr.Name(semconv.CloudAccountIDKey), Value: "project"},
				{Key: attr.Name(semconv.CloudAvailabilityZoneKey), Value: "us-central1-a"},
			}}
			refresher, err := gceInventoryRefresher(t.Context(), &node, tc.cfg, CloudMetadataConfig{RefreshInterval: tc.interval})
			require.ErrorContains(t, err, tc.wantError)
			assert.Nil(t, refresher)
		})
	}
}

func TestGCEResolverSkipsOtherPlatforms(t *testing.T) {
	for _, platform := range []string{"", semconv.CloudPlatformGCPKubernetesEngine.Value.AsString()} {
		t.Run(platform, func(t *testing.T) {
			node := metadata.NodeMeta{Metadata: []metadata.Entry{
				{Key: attr.Name(semconv.CloudPlatformKey), Value: platform},
			}}
			refresher, err := gceInventoryRefresher(t.Context(), &node, GCENameResolverConfig{}, CloudMetadataConfig{})
			require.NoError(t, err)
			assert.Nil(t, refresher)
		})
	}
}

func TestGCELocalInstanceID(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cfg         GCENameResolverConfig
		kubernetes  bool
		missingID   bool
		missingMeta bool
		want        string
	}{
		{name: "detected scope", want: "123"},
		{name: "matching explicit scope", cfg: GCENameResolverConfig{ProjectID: "project", Zone: "us-central1-a"}, want: "123"},
		{name: "different project", cfg: GCENameResolverConfig{ProjectID: "other-project"}},
		{name: "different zone", cfg: GCENameResolverConfig{Zone: "us-central1-b"}},
		{name: "Kubernetes identity", kubernetes: true},
		{name: "missing VM ID", missingID: true},
		{name: "missing cloud scope", missingMeta: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := metadata.NodeMeta{
				Features: metadata.ClusterGCP,
				HostID:   "custom-exported-host", GCEInstanceID: "123",
				Metadata: []metadata.Entry{
					{Key: attr.Name(semconv.CloudAccountIDKey), Value: "project"},
					{Key: attr.Name(semconv.CloudAvailabilityZoneKey), Value: "us-central1-a"},
				},
			}
			if tc.kubernetes {
				node.Features |= metadata.ClusterK8s
			}
			if tc.missingID {
				node.GCEInstanceID = ""
			}
			if tc.missingMeta {
				node.Metadata = nil
			}
			assert.Equal(t, tc.want, gceLocalInstanceID(node, tc.cfg))
		})
	}
}
