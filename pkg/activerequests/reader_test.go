// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package activerequests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
)

func TestExpiredActiveRequest(t *testing.T) {
	assert.Equal(t, 5*time.Minute, NewReader(nil, Config{}).config.MaxAge)
	assert.Equal(t, 10*time.Minute, NewReader(nil, Config{MaxAge: 10 * time.Minute}).config.MaxAge)
	now := 10 * time.Minute
	ttl := 5 * time.Minute
	for _, tt := range []struct {
		name    string
		start   uint64
		ttl     time.Duration
		expired bool
	}{
		{name: "missing timestamp", start: 0, ttl: ttl, expired: true},
		{name: "within TTL", start: uint64(now - ttl + time.Nanosecond), ttl: ttl},
		{name: "at TTL", start: uint64(now - ttl), ttl: ttl, expired: true},
		{name: "beyond TTL", start: uint64(now - ttl - time.Nanosecond), ttl: ttl, expired: true},
		{name: "future timestamp", start: uint64(now + time.Second), ttl: ttl},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expired, expired(tt.start, now, tt.ttl))
		})
	}
}

func TestActiveRequestCarriesAvailableHTTPAttributes(t *testing.T) {
	active := ebpfcommon.BpfActiveRequestT{
		StartMonotimeNs: uint64(2 * time.Second),
		IsTls:           1,
	}
	copy(active.Method[:], "GET")
	copy(active.Path[:], "/orders/123")
	active.Conn.S_addr[15] = 1
	active.Conn.S_port = 8443
	service := svc.Attrs{UID: svc.UID{Name: "shop", Instance: "instance-1"}}

	entry := activeRequest(active, service)
	assert.Equal(t, "GET", entry.Method)
	assert.Equal(t, "/orders/123", entry.Path)
	assert.Equal(t, "https", entry.Scheme)
	assert.Equal(t, "::1", entry.ServerAddress)
	assert.Equal(t, 8443, entry.ServerPort)
	assert.Equal(t, service.UID, entry.Service.UID)
	assert.Equal(t, uint64(2*time.Second), entry.StartMonotimeNs)
}

func TestActiveRequestFilteringUsesMetricFiltersAndRoutePolicy(t *testing.T) {
	c := NewReader(nil, Config{
		ApplicationFilter: filter.AttributeFamilyConfig{
			"url.path": {Match: "/api/*"},
		},
		InstrumentationFilter: filter.InstrumentationAttributeFamilyConfig{
			instrumentations.InstrumentationHTTP: {
				Metrics: filter.AttributeFamilyConfig{
					"http.request.method": {Match: "GET"},
				},
				Traces: filter.AttributeFamilyConfig{
					"http.request.method": {Match: "POST"},
				},
			},
		},
		GlobalRoutePolicy: svc.NewRoutePolicy(services.RoutePolicy{
			IgnorePatterns: []string{"/api/health"},
			IgnoredEvents:  services.IgnoreMetrics,
		}),
	})
	c.initMatchers()
	require.NoError(t, c.initErr)
	entry := Request{Method: "GET", Path: "/api/orders"}
	assert.True(t, c.include(&entry))

	entry.Method = "POST"
	assert.False(t, c.include(&entry), "metrics filter excludes POST even when trace filter allows it")
	entry.Method = "GET"
	entry.Path = "/api/health"
	assert.False(t, c.include(&entry), "ignored route excludes active metrics")
	entry.Path = "/other"
	assert.False(t, c.include(&entry), "application filter excludes unrelated paths")

	entry.Path = "/api/health"
	entry.Service.IncomingRoutePolicy = svc.NewRoutePolicy(services.RoutePolicy{
		IgnorePatterns: []string{"/api/health"},
		IgnoredEvents:  services.IgnoreTraces,
	})
	assert.True(t, c.include(&entry), "trace-only route ignores must not suppress metrics")
}

func TestCountRequestsByServiceAndSelectedAttributes(t *testing.T) {
	firstService := svc.Attrs{UID: svc.UID{Name: "orders", Instance: "one"}}
	secondService := svc.Attrs{UID: svc.UID{Name: "orders", Instance: "two"}}
	requests := []Request{
		{Service: firstService, Method: "GET", Scheme: "http", ServerAddress: "first"},
		{Service: firstService, Method: "GET", Scheme: "http", ServerAddress: "second"},
		{Service: firstService, Method: "POST", Scheme: "https"},
		{Service: secondService, Method: "GET", Scheme: "http"},
	}

	counts := countRequests(requests, []attr.Name{attr.HTTPRequestMethod, attr.HTTPURLScheme})
	require.Len(t, counts, 3)
	got := map[string]int64{}
	for _, count := range counts {
		method, _ := count.Attributes.Value(attribute.Key(attr.HTTPRequestMethod))
		scheme, _ := count.Attributes.Value(attribute.Key(attr.HTTPURLScheme))
		key := count.Service.UID.Instance + "/" + method.AsString() + "/" + scheme.AsString()
		got[key] = count.Value
	}
	assert.Equal(t, map[string]int64{"one/GET/http": 2, "one/POST/https": 1, "two/GET/http": 1}, got)
}

func TestCountRequestsOmitsMissingAttributesAndSanitizesValues(t *testing.T) {
	counts := countRequests([]Request{{
		Service: svc.Attrs{UID: svc.UID{Name: "orders"}},
		Method:  "GET",
		Scheme:  "http",
		Path:    "/bad\xffpath",
	}}, []attr.Name{attr.HTTPUrlPath, attr.ServerAddr, attr.ServerPort})
	require.Len(t, counts, 1)
	path, ok := counts[0].Attributes.Value(attribute.Key(attr.HTTPUrlPath))
	assert.True(t, ok)
	assert.Equal(t, "/badpath", path.AsString())
	_, ok = counts[0].Attributes.Value(attribute.Key(attr.ServerAddr))
	assert.False(t, ok)
	_, ok = counts[0].Attributes.Value(attribute.Key(attr.ServerPort))
	assert.False(t, ok)
}
