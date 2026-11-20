// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestActiveHTTPServerRequestRoutePolicy(t *testing.T) {
	rule := services.RoutePolicy{IgnorePatterns: []string{"/health"}, IgnoredEvents: services.IgnoreMetrics}
	global := svc.NewRoutePolicy(rule)
	traceRule := rule
	traceRule.IgnoredEvents = services.IgnoreTraces

	for _, tc := range []struct {
		name    string
		service *svc.RoutePolicy
		path    string
		want    bool
	}{
		{"global ignores health", nil, "/health", false},
		{"global allows work", nil, "/work", true},
		{"empty service override allows health", svc.NewRoutePolicy(services.RoutePolicy{}), "/health", true},
		{"service ignores only traces", svc.NewRoutePolicy(traceRule), "/health", true},
		{"service ignores metrics", svc.NewRoutePolicy(rule), "/health", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			span := request.Span{Path: tc.path, Service: svc.Attrs{
				Features: export.FeatureHTTPServerActiveRequests, IncomingRoutePolicy: tc.service,
			}}
			assert.Equal(t, tc.want, matchesActiveHTTPServerRequest(&span, global, nil))
		})
	}
}

func TestActiveHTTPServerStartMatchers(t *testing.T) {
	serverError := 500
	cfg := &obi.Config{}
	cfg.Filters.Application = filter.AttributeFamilyConfig{
		"url.path": {Match: "/orders"},
	}
	cfg.Filters.ApplicationByInstrumentation = filter.InstrumentationAttributeFamilyConfig{
		instrumentations.InstrumentationHTTP: {
			Metrics: filter.AttributeFamilyConfig{
				"http.request.method":       {Match: "POST"},
				"http.response.status_code": {Equals: &serverError},
				"url.scheme":                {Match: "https"},
			},
		},
	}

	matchers, err := activeHTTPServerStartMatchers(cfg)
	require.NoError(t, err)

	for _, tt := range []struct {
		method string
		path   string
		scheme string
		want   bool
	}{
		{"POST", "/orders", "https", true},
		{"POST", "/orders", "http", false},
		{"GET", "/orders", "https", false},
		{"POST", "/health", "https", false},
	} {
		t.Run(tt.method+" "+tt.scheme+tt.path, func(t *testing.T) {
			span := request.Span{
				Type:      request.EventTypeHTTP,
				Method:    tt.method,
				Path:      tt.path,
				Statement: tt.scheme + request.SchemeHostSeparator,
			}
			assert.Equal(t, tt.want, matchers.Matches(span))
		})
	}
}

func TestActiveHTTPServerStartMatchers_ServerAddressAndPort(t *testing.T) {
	port := 8443
	cfg := &obi.Config{}
	cfg.Filters.Application = filter.AttributeFamilyConfig{
		"server.address": {Match: "shop.example.com"},
		"server.port":    {Equals: &port},
	}

	matchers, err := activeHTTPServerStartMatchers(cfg)
	require.NoError(t, err)

	for _, tt := range []struct {
		authority string
		hostPort  int
		want      bool
	}{
		{"shop.example.com:8443", 8443, true},
		{"shop.example.com", 8443, true},
		{"admin.example.com", 8443, false},
		{"shop.example.com", 8080, false},
		{"shop.example.com", 0, false},
	} {
		span := request.Span{
			Type:             request.EventTypeHTTP,
			RequestAuthority: tt.authority,
			HostPort:         tt.hostPort,
		}
		assert.Equal(t, tt.want, matchers.Matches(span), "authority=%q port=%d", tt.authority, tt.hostPort)
	}
}
