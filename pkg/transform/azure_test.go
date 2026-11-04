// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/metadata"
)

func azureTestNode() metadata.NodeMeta {
	return metadata.NodeMeta{Features: metadata.ClusterAzureVM, AzureInstanceID: "vm-uuid", HostID: "custom-host", Metadata: []metadata.Entry{{Key: attr.Name(semconv.CloudResourceIDKey), Value: "/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/virtualMachineScaleSets/set/virtualMachines/0"}}}
}

func TestAzureScope(t *testing.T) {
	node := azureTestNode()
	require.Equal(t, AzureNameResolverConfig{"sub", "group"}, azureScope(&node, AzureNameResolverConfig{}))
	require.Equal(t, AzureNameResolverConfig{"other", "group"}, azureScope(&node, AzureNameResolverConfig{SubscriptionID: "other"}))
	require.Equal(t, AzureNameResolverConfig{"sub", "other"}, azureScope(&node, AzureNameResolverConfig{ResourceGroup: "other"}))
	require.Equal(t, AzureNameResolverConfig{"other", "group"}, azureScope(&node, AzureNameResolverConfig{SubscriptionID: " other\n", ResourceGroup: "  "}))
	node.Metadata[0].Value = "/not/an/arm/id"
	require.Empty(t, detectedAzureScope(&node))
}

func TestAzureMetadataRefreshersConfiguration(t *testing.T) {
	node := azureTestNode()
	cfg := &NameResolverConfig{Sources: []Source{SourceAzure}}
	cloudCfg := CloudMetadataConfig{RefreshInterval: time.Minute}
	require.Len(t, CloudMetadataRefreshers(t.Context(), &node, cfg, cloudCfg), 1)
	require.Empty(t, CloudMetadataRefreshers(t.Context(), &node, nil, cloudCfg))
	require.Empty(t, CloudMetadataRefreshers(t.Context(), &node, &NameResolverConfig{}, cloudCfg))
	require.Empty(t, CloudMetadataRefreshers(t.Context(), &node, cfg, CloudMetadataConfig{}))
	node.Metadata = nil
	require.Empty(t, CloudMetadataRefreshers(t.Context(), &node, cfg, cloudCfg))
	cfg.Azure = AzureNameResolverConfig{"explicit-sub", "explicit-group"}
	require.Len(t, CloudMetadataRefreshers(t.Context(), &node, cfg, cloudCfg), 1)
	node.Features |= metadata.ClusterK8s
	require.Empty(t, CloudMetadataRefreshers(t.Context(), &node, cfg, cloudCfg))
	node.Features = metadata.ClusterEC2
	require.Empty(t, CloudMetadataRefreshers(t.Context(), &node, cfg, cloudCfg))
}

func TestLocalAzureInstanceID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*metadata.NodeMeta, *NameResolverConfig)
		want   string
	}{
		{"detected UUID survives host override", func(*metadata.NodeMeta, *NameResolverConfig) {}, "azure:sub:vm-uuid"},
		{"case insensitive scope", func(_ *metadata.NodeMeta, c *NameResolverConfig) { c.Azure = AzureNameResolverConfig{"SUB", "GROUP"} }, "azure:sub:vm-uuid"},
		{"different subscription", func(_ *metadata.NodeMeta, c *NameResolverConfig) { c.Azure.SubscriptionID = "remote" }, ""},
		{"different group", func(_ *metadata.NodeMeta, c *NameResolverConfig) { c.Azure.ResourceGroup = "remote" }, ""},
		{"Kubernetes", func(n *metadata.NodeMeta, _ *NameResolverConfig) { n.Features |= metadata.ClusterK8s }, ""},
		{"missing UUID", func(n *metadata.NodeMeta, _ *NameResolverConfig) { n.AzureInstanceID = "" }, ""},
		{"missing detected scope", func(n *metadata.NodeMeta, c *NameResolverConfig) {
			n.Metadata = nil
			c.Azure = AzureNameResolverConfig{"sub", "group"}
		}, ""},
		{"disabled source", func(_ *metadata.NodeMeta, c *NameResolverConfig) { c.Sources = nil }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := azureTestNode()
			cfg := &NameResolverConfig{Sources: []Source{SourceAzure}}
			tc.change(&node, cfg)
			require.Equal(t, tc.want, localAzureInstanceID(&node, cfg))
		})
	}
	require.Empty(t, localAzureInstanceID(new(metadata.NodeMeta), nil))
}

func TestLocalCloudInstanceIDWithBothSources(t *testing.T) {
	cfg := &NameResolverConfig{Sources: []Source{SourceGCE, SourceAzure}}
	node := azureTestNode()
	require.Equal(t, "azure:sub:vm-uuid", localCloudInstanceID(&node, cfg))
	node = metadata.NodeMeta{
		Features: metadata.ClusterGCP, GCEInstanceID: "gce-vm",
		Metadata: []metadata.Entry{
			{Key: attr.Name(semconv.CloudAccountIDKey), Value: "project"},
			{Key: attr.Name(semconv.CloudAvailabilityZoneKey), Value: "zone"},
		},
	}
	require.Equal(t, "gce-vm", localCloudInstanceID(&node, cfg))
	node.Features |= metadata.ClusterK8s
	require.Empty(t, localCloudInstanceID(&node, cfg))
}
