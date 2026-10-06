// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/cloud"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestECSResolverRecoversFromInitialFailure(t *testing.T) {
	var available atomic.Bool
	var failures atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if !available.Load() {
			failures.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"__type":"AccessDeniedException","message":"denied"}`)
			return
		}
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonEC2ContainerServiceV20141113.ListTasks":
			fmt.Fprint(w, `{"taskArns":["task-1"]}`)
		case "AmazonEC2ContainerServiceV20141113.DescribeTasks":
			fmt.Fprint(w, `{"tasks":[{"group":"service:checkout","attachments":[{"details":[{"name":"privateIPv4Address","value":"10.0.0.2"}]}]}]}`)
		default:
			t.Errorf("unexpected ECS operation: %s", r.Header.Get("X-Amz-Target"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWS_ENDPOINT_URL_ECS", server.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	input := msg.NewQueue[[]request.Span]()
	output := msg.NewQueue[[]request.Span]()
	resolved := output.Subscribe(msg.SubscriberName("test"))
	cfg := &NameResolverConfig{
		Sources: []Source{SourceECS}, CacheLen: 10, CacheTTL: time.Minute,
	}
	ctxInfo := &global.ContextInfo{NodeMeta: metadata.NodeMeta{Features: metadata.ClusterECS}}
	cloudCfg := CloudMetadataConfig{ClusterName: "cluster", Region: "us-east-1", RefreshInterval: 10 * time.Millisecond}
	refreshers := CloudMetadataRefreshers(ctx, &ctxInfo.NodeMeta, cfg.Sources, cloudCfg)
	require.Len(t, refreshers, 1)
	ctxInfo.CloudMetaInventory = cloud.NewInventory(refreshers)
	startCloudInventory(t, ctxInfo.CloudMetaInventory, cloudCfg.RefreshInterval)
	require.Eventually(t, func() bool { return failures.Load() > 0 }, 5*time.Second, 10*time.Millisecond)
	run, err := nameResolver(ctx, ctxInfo, cfg, input, output)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		run(ctx)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("resolver did not stop")
		}
	}()

	resolve := func() request.Span {
		t.Helper()
		input.SendCtx(ctx, []request.Span{{Type: request.EventTypeHTTPClient, Host: "10.0.0.2"}})
		select {
		case spans := <-resolved:
			require.Len(t, spans, 1)
			return spans[0]
		case <-time.After(5 * time.Second):
			t.Fatal("resolver did not forward span")
			return request.Span{}
		}
	}
	assert.Equal(t, "10.0.0.2", resolve().HostName)
	available.Store(true)
	require.Eventually(t, func() bool {
		return resolve().HostName == "checkout"
	}, 5*time.Second, 10*time.Millisecond)
	name, ok := ctxInfo.CloudMetaInventory.ServiceNameForIP("10.0.0.2")
	assert.True(t, ok)
	assert.Equal(t, "checkout", name)
}

func TestECSMetadataRefreshersConfiguration(t *testing.T) {
	t.Setenv("ECS_CONTAINER_METADATA_URI_V4", "")
	t.Setenv("ECS_CONTAINER_METADATA_URI", "")
	ctxInfo := &global.ContextInfo{NodeMeta: metadata.NodeMeta{Features: metadata.ClusterECS}}
	for _, sources := range [][]Source{nil, {SourceDNS}} {
		refreshers := CloudMetadataRefreshers(t.Context(), &ctxInfo.NodeMeta, sources, CloudMetadataConfig{})
		assert.Empty(t, refreshers)
	}
	for _, tc := range []struct {
		cloud    CloudMetadataConfig
		interval time.Duration
	}{
		{CloudMetadataConfig{Region: "us-east-1"}, time.Second},
		{CloudMetadataConfig{ClusterName: "cluster"}, time.Second},
		{CloudMetadataConfig{ClusterName: "cluster", Region: "us-east-1"}, 0},
		{CloudMetadataConfig{ClusterName: "cluster", Region: "us-east-1"}, -time.Second},
	} {
		t.Run(fmt.Sprintf("%s_%s_%v", tc.cloud.Region, tc.cloud.ClusterName, tc.interval), func(t *testing.T) {
			tc.cloud.RefreshInterval = tc.interval
			refreshers := CloudMetadataRefreshers(t.Context(), &ctxInfo.NodeMeta,
				[]Source{SourceECS}, tc.cloud)
			assert.Empty(t, refreshers)
		})
	}
}

func TestECSMetadataRefreshersMetadataDefaults(t *testing.T) {
	const detectedCluster = "arn:aws:ecs:us-east-1:123456789012:cluster/test"
	for _, tc := range []struct {
		name        string
		cluster     string
		region      string
		wantCluster string
		wantRegion  string
	}{
		{"discovered", "", "", detectedCluster, "us-east-1"},
		{"explicit cluster", "configured", "", "configured", "us-east-1"},
		{"explicit region", "", "eu-west-1", detectedCluster, "eu-west-1"},
		{"fully configured", "configured", "eu-west-1", "configured", "eu-west-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var apiRequests atomic.Int32
			metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("resolver must use shared node metadata")
				fmt.Fprint(w, "{}")
			}))
			t.Cleanup(metadataServer.Close)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				apiRequests.Add(1)
				var input struct{ Cluster string }
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&input))
				assert.Equal(t, tc.wantCluster, input.Cluster)
				assert.Contains(t, r.Header.Get("Authorization"), "/"+tc.wantRegion+"/ecs/aws4_request")
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				fmt.Fprint(w, `{"taskArns":[]}`)
			}))
			t.Cleanup(api.Close)
			t.Setenv("ECS_CONTAINER_METADATA_URI_V4", metadataServer.URL)
			t.Setenv("ECS_CONTAINER_METADATA_URI", "")
			t.Setenv("AWS_ENDPOINT_URL_ECS", api.URL)
			t.Setenv("AWS_ACCESS_KEY_ID", "test")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
			t.Setenv("AWS_SESSION_TOKEN", "")
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
			t.Setenv("AWS_MAX_ATTEMPTS", "1")
			cfg := &NameResolverConfig{
				Sources: []Source{SourceECS},
			}
			cloudCfg := CloudMetadataConfig{ClusterName: tc.cluster, Region: tc.region, RefreshInterval: time.Second}
			original := cloudCfg
			info := &global.ContextInfo{NodeMeta: metadata.NodeMeta{Features: metadata.ClusterECS, Cluster: detectedCluster, Region: "us-east-1"}}
			refreshers := CloudMetadataRefreshers(t.Context(), &info.NodeMeta, cfg.Sources, cloudCfg)
			require.Len(t, refreshers, 1)
			inventory := cloud.NewInventory(refreshers)
			startCloudInventory(t, inventory, 10*time.Millisecond)
			assert.Equal(t, original, cloudCfg)
			require.Eventually(t, func() bool { return apiRequests.Load() > 0 }, 5*time.Second, 10*time.Millisecond)
		})
	}
}

type fakeECSResolver map[string]string

func (fakeECSResolver) Name() string { return "ecs" }
func (f fakeECSResolver) Refresh(_ context.Context, snapshot *cloud.MetadataSnapshot) error {
	for id, name := range f {
		snapshot.ServiceByIP[id] = name
		snapshot.ServiceByContainerID[id] = name
	}
	return nil
}

func TestResolveNamesFromECS(t *testing.T) {
	inventory := cloud.NewInventory([]cloud.MetadataRefresher{fakeECSResolver{
		"10.0.0.1":             "storefront",
		"10.0.0.2":             "checkout",
		"storefront-container": "storefront",
		"checkout-container":   "checkout",
	}})
	startCloudInventory(t, inventory, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		name, ok := inventory.ServiceNameForContainerID("checkout-container")
		return ok && name == "checkout"
	}, 5*time.Second, 10*time.Millisecond)
	resolver := NameResolver{
		cloudInventory: inventory,
		sources:        ResolverECS,
		logger:         nrlog(),
	}

	t.Run("client", func(t *testing.T) {
		span := request.Span{
			Type: request.EventTypeHTTPClient,
			Peer: "10.0.0.1",
			Host: "10.0.0.2",
			Service: svc.Attrs{UID: svc.UID{
				Name: "generated-container-name",
			}},
		}
		span.Service.SetAutoName()
		span.Service.RuntimeContainerID = "storefront-container"

		resolver.resolveNames(&span)

		assert.Equal(t, "storefront", span.Service.UID.Name)
		assert.Equal(t, "storefront", span.PeerName)
		assert.Equal(t, "checkout", span.HostName)
	})

	t.Run("server", func(t *testing.T) {
		span := request.Span{
			Type: request.EventTypeHTTP,
			Peer: "10.0.0.1",
			Host: "10.0.0.2",
			Service: svc.Attrs{UID: svc.UID{
				Name: "generated-container-name",
			}},
		}
		span.Service.SetAutoName()
		span.Service.RuntimeContainerID = "checkout-container"

		resolver.resolveNames(&span)

		assert.Equal(t, "checkout", span.Service.UID.Name)
		assert.Equal(t, "storefront", span.PeerName)
		assert.Equal(t, "checkout", span.HostName)
	})

	t.Run("explicit service name", func(t *testing.T) {
		span := request.Span{
			Type: request.EventTypeHTTPClient,
			Peer: "10.0.0.1",
			Host: "10.0.0.2",
			Service: svc.Attrs{UID: svc.UID{
				Name: "configured-name",
			}},
		}

		span.Service.RuntimeContainerID = "storefront-container"
		resolver.resolveNames(&span)

		assert.Equal(t, "configured-name", span.Service.UID.Name)
		assert.Equal(t, "storefront", span.PeerName)
		assert.Equal(t, "checkout", span.HostName)
	})

	t.Run("loopback uses container identity", func(t *testing.T) {
		span := request.Span{
			Type: request.EventTypeHTTP, Host: "127.0.0.1", Peer: "127.0.0.1",
			Service: svc.Attrs{UID: svc.UID{Name: "container-name"}, RuntimeContainerID: "checkout-container"},
		}
		span.Service.SetAutoName()
		resolver.resolveNames(&span)
		assert.Equal(t, "checkout", span.Service.UID.Name)
		assert.Equal(t, "checkout", span.HostName)
	})

	t.Run("missing container identity keeps local name", func(t *testing.T) {
		span := request.Span{
			Type: request.EventTypeHTTP, Host: "10.0.0.2",
			Service: svc.Attrs{UID: svc.UID{Name: "container-name"}},
		}
		span.Service.SetAutoName()
		resolver.resolveNames(&span)
		assert.Equal(t, "container-name", span.Service.UID.Name)
	})
}

func startCloudInventory(t *testing.T, inventory *cloud.Inventory, interval time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	run, err := cloud.InventoryRefresherNode(inventory, interval)(ctx)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("inventory refresh did not stop")
		}
	})
}
