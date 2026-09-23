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
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestECSResolverRecoversFromInitialFailure(t *testing.T) {
	var available atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if !available.Load() {
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
	defer server.Close()
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
		ECS: ECSNameResolverConfig{Cluster: "cluster", Region: "us-east-1", RefreshInterval: 10 * time.Millisecond},
	}
	ctxInfo := &global.ContextInfo{}
	refresh, err := ECSInventoryProvider(ctxInfo, cfg)(ctx)
	require.NoError(t, err)
	require.NotNil(t, ctxInfo.AppO11y.ECSInventory)
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		refresh(ctx)
	}()
	defer func() {
		cancel()
		select {
		case <-refreshDone:
		case <-time.After(5 * time.Second):
			t.Error("inventory refresh did not stop")
		}
	}()
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
	name, ok := ctxInfo.AppO11y.ECSInventory.ServiceNameForIP("10.0.0.2")
	assert.True(t, ok)
	assert.Equal(t, "checkout", name)
}

func TestECSInventoryProviderConfiguration(t *testing.T) {
	for _, cfg := range []*NameResolverConfig{nil, {Sources: []Source{SourceDNS}}} {
		ctxInfo := &global.ContextInfo{}
		run, err := ECSInventoryProvider(ctxInfo, cfg)(t.Context())
		require.NoError(t, err)
		run(t.Context())
		assert.Nil(t, ctxInfo.AppO11y.ECSInventory)
	}
	for _, ecsCfg := range []ECSNameResolverConfig{
		{Region: "us-east-1", RefreshInterval: time.Second},
		{Cluster: "cluster", RefreshInterval: time.Second},
		{Cluster: "cluster", Region: "us-east-1"},
		{Cluster: "cluster", Region: "us-east-1", RefreshInterval: -time.Second},
	} {
		ctxInfo := &global.ContextInfo{}
		_, err := ECSInventoryProvider(ctxInfo, &NameResolverConfig{
			Sources: []Source{SourceECS}, ECS: ecsCfg,
		})(t.Context())
		require.ErrorContains(t, err, "cluster, region, and a positive refresh interval are required")
		assert.Nil(t, ctxInfo.AppO11y.ECSInventory)
	}
}

type fakeECSResolver map[string]string

func (f fakeECSResolver) ServiceNameForIP(ip string) (string, bool) {
	name, ok := f[ip]
	return name, ok
}

func TestResolveNamesFromECS(t *testing.T) {
	resolver := NameResolver{
		ecs: fakeECSResolver{
			"10.0.0.1": "storefront",
			"10.0.0.2": "checkout",
		},
		sources: ResolverECS,
		logger:  nrlog(),
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

		resolver.resolveNames(&span)

		assert.Equal(t, "configured-name", span.Service.UID.Name)
		assert.Equal(t, "storefront", span.PeerName)
		assert.Equal(t, "checkout", span.HostName)
	})
}
