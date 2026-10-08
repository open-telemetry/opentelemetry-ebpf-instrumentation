// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/cloud"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestRoute53ResolverRecoversFromInitialFailure(t *testing.T) {
	var available atomic.Bool
	var failures atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/2013-04-01/hostedzone/test-zone/rrset", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "/route53/aws4_request")
		w.Header().Set("Content-Type", "text/xml")
		if !available.Load() {
			failures.Add(1)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>denied</Message></Error></ErrorResponse>`)
			return
		}
		fmt.Fprint(w, `<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets><ResourceRecordSet><Name>Payments.Internal.Example.com.</Name><Type>A</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>10.0.0.2</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>300</MaxItems></ListResourceRecordSetsResponse>`)
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWS_ENDPOINT_URL_ROUTE_53", server.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cfg := &NameResolverConfig{
		Sources: []Source{SourceRoute53}, CacheLen: 10, CacheTTL: time.Minute,
	}
	cloudCfg := CloudMetadataConfig{
		RefreshInterval: 10 * time.Millisecond,
		Route53:         Route53MetadataConfig{RefreshInterval: 10 * time.Millisecond, HostedZoneIDs: []string{"test-zone"}},
	}
	info := &global.ContextInfo{NodeMeta: metadata.NodeMeta{Features: metadata.ClusterEC2}}
	refreshers := CloudMetadataRefreshers(ctx, &info.NodeMeta, cfg.Sources, cloudCfg)
	require.Len(t, refreshers, 1)
	info.CloudMetaInventory = cloud.NewInventory(refreshers)
	startCloudInventory(t, info.CloudMetaInventory, cloudCfg.RefreshInterval)
	require.Eventually(t, func() bool { return failures.Load() > 0 }, 5*time.Second, 10*time.Millisecond)
	input, output := msg.NewQueue[[]request.Span](), msg.NewQueue[[]request.Span]()
	resolved := output.Subscribe(msg.SubscriberName("test"))
	run, err := nameResolver(ctx, info, cfg, input, output)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { defer close(done); run(ctx) }()
	defer func() {
		cancel()
		for _, ch := range []chan struct{}{done} {
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
				t.Error("pipeline did not stop")
			}
		}
	}()
	resolve := func() string {
		t.Helper()
		input.SendCtx(ctx, []request.Span{{Type: request.EventTypeHTTPClient, Host: "10.0.0.2"}})
		select {
		case spans := <-resolved:
			return spans[0].HostName
		case <-time.After(5 * time.Second):
			t.Fatal("resolver did not forward span")
			return ""
		}
	}
	assert.Equal(t, "10.0.0.2", resolve())
	available.Store(true)
	require.Eventually(t, func() bool { return resolve() == "payments.internal.example.com" }, 5*time.Second, 10*time.Millisecond)
}

func TestRoute53InventoryConfiguration(t *testing.T) {
	nodeMeta := &metadata.NodeMeta{Features: metadata.ClusterEC2}
	for _, sources := range [][]Source{nil, {SourceDNS}} {
		refreshers := CloudMetadataRefreshers(t.Context(), nodeMeta, sources, CloudMetadataConfig{})
		assert.Empty(t, refreshers)
	}
	for _, cfg := range []CloudMetadataConfig{
		{},
		{Route53: Route53MetadataConfig{RefreshInterval: time.Second}},
		{Route53: Route53MetadataConfig{RefreshInterval: time.Second, HostedZoneIDs: []string{""}}},
		{Route53: Route53MetadataConfig{RefreshInterval: -time.Second, HostedZoneIDs: []string{"zone"}}},
	} {
		refreshers := CloudMetadataRefreshers(t.Context(), nodeMeta, []Source{SourceRoute53}, cfg)
		assert.Empty(t, refreshers)
	}
}

func TestRoute53InventoryRegion(t *testing.T) {
	for _, tc := range []struct {
		name           string
		configRegion   string
		detectedRegion string
		wantRegion     string
	}{
		{"configured region", "us-gov-west-1", "us-east-2", "us-gov-west-1"},
		{"detected region", "", "us-gov-east-1", "us-gov-east-1"},
		{"default region", "", "", route53DefaultRegion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var authorization atomic.Value
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authorization.Store(r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "text/xml")
				fmt.Fprint(w, `<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>300</MaxItems></ListResourceRecordSetsResponse>`)
			}))
			t.Cleanup(server.Close)
			t.Setenv("AWS_ENDPOINT_URL_ROUTE_53", server.URL)
			t.Setenv("AWS_ACCESS_KEY_ID", "test")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
			t.Setenv("AWS_SESSION_TOKEN", "")
			t.Setenv("AWS_REGION", "")
			t.Setenv("AWS_DEFAULT_REGION", "")
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
			t.Setenv("AWS_MAX_ATTEMPTS", "1")

			refresher, err := route53InventoryRefresher(t.Context(),
				&metadata.NodeMeta{Region: tc.detectedRegion},
				CloudMetadataConfig{
					Region:          tc.configRegion,
					RefreshInterval: time.Second,
					Route53:         Route53MetadataConfig{RefreshInterval: 10 * time.Millisecond, HostedZoneIDs: []string{"test-zone"}},
				})
			require.NoError(t, err)

			snapshot := &cloud.MetadataSnapshot{ServiceByIP: map[string]string{}}
			require.NoError(t, refresher.Refresh(t.Context(), snapshot))
			assert.Contains(t, authorization.Load(), "/"+tc.wantRegion+"/route53/aws4_request")
		})
	}
}

func TestRoute53ResolverPrecedence(t *testing.T) {
	route53 := fakeECSResolver{"10.0.0.1": "dns.example.com", "10.0.0.2": "other.example.com"}
	ecs := fakeECSResolver{"10.0.0.1": "ecs-service"}
	for _, tc := range []struct {
		name       string
		refreshers []cloud.MetadataRefresher
		wantHost   string
	}{
		{"ecs takes precedence", []cloud.MetadataRefresher{route53, ecs}, "ecs-service"},
		{"route53 only", []cloud.MetadataRefresher{route53}, "dns.example.com"},
		{"disabled", nil, "10.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inventory := cloud.NewInventory(tc.refreshers)
			if len(tc.refreshers) > 0 {
				startCloudInventory(t, inventory, 10*time.Millisecond)
				require.Eventually(t, func() bool {
					name, ok := inventory.ServiceNameForIP("10.0.0.1")
					return ok && name == tc.wantHost
				}, 5*time.Second, 10*time.Millisecond)
			}
			resolver := NameResolver{cloudInventory: inventory, logger: nrlog()}
			span := request.Span{Type: request.EventTypeHTTPClient, Host: "10.0.0.1", Peer: "10.0.0.2"}
			resolver.resolveNames(&span)
			assert.Equal(t, tc.wantHost, span.HostName)
			if len(tc.refreshers) > 0 {
				assert.Equal(t, "other.example.com", span.PeerName)
			}
		})
	}
}
