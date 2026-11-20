// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly // import "go.opentelemetry.io/obi/pkg/appolly"

import (
	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

func activeHTTPServerGlobalRoutePolicy(routes *transform.RoutesConfig) *svc.RoutePolicy {
	if routes == nil || routes.DirectionalRuleOnly || !routes.HasIncomingPolicy() {
		return nil
	}

	return svc.NewRoutePolicy(routes.DirectionalPolicies().Incoming)
}

func activeHTTPServerStartMatchers(cfg *obi.Config) (filter.MatcherSet[request.Span], error) {
	httpFilters := cfg.Filters.ApplicationByInstrumentation[instrumentations.InstrumentationHTTP]
	var matchers filter.MatcherSet[request.Span]

	for _, configured := range []filter.AttributeFamilyConfig{cfg.Filters.Application, httpFilters.Metrics} {
		startFilters := filter.AttributeFamilyConfig{}
		for name, definition := range configured {
			switch attr.Name(name).Prom() {
			case attr.HTTPRequestMethod.Prom(), attr.HTTPUrlPath.Prom(),
				attr.HTTPURLScheme.Prom(), attr.ServerAddr.Prom(), attr.ServerPort.Prom():
				startFilters[name] = definition
			}
		}
		if len(startFilters) == 0 {
			continue
		}

		compiled, err := filter.NewMatcherSet(
			startFilters, nil, cfg.Attributes.ExtraGroupAttributes, spanPtrPromGetters(cfg),
		)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, compiled...)
	}
	return matchers, nil
}

func matchesActiveHTTPServerRequest(
	span *request.Span,
	globalIncoming *svc.RoutePolicy,
	startMatchers filter.MatcherSet[request.Span],
) bool {
	if !span.Service.Features.HTTPServerActiveRequests() ||
		!span.Service.ExportModes.CanExportMetrics() {
		return false
	}

	policy := span.Service.IncomingRoutePolicy
	if policy == nil {
		policy = globalIncoming
	}
	if policy != nil && policy.IgnoreMatcher != nil {
		switch policy.Config.IgnoredEvents {
		case "", services.IgnoreAll, services.IgnoreMetrics:
			if policy.IgnoreMatcher.Find(span.Path) != "" {
				return false
			}
		}
	}

	return startMatchers.Matches(*span)
}

func visitActiveHTTPServerRequests(
	eventCtx *ebpfcommon.EBPFEventContext,
	globalIncoming *svc.RoutePolicy,
	startMatchers filter.MatcherSet[request.Span],
	visit func(*request.Span),
) error {
	const mapName = "ongoing_http_server_requests"

	if eventCtx == nil {
		return nil
	}

	var connections *ebpf.Map

	eventCtx.MapsLock.Lock()
	requests, err := eventCtx.EBPFMaps[mapName].Clone()
	if err == nil && requests != nil {
		connections, err = eventCtx.EBPFMaps["ongoing_server_connections"].Clone()
	}
	eventCtx.MapsLock.Unlock()

	if requests != nil {
		defer requests.Close()
	}
	if err != nil {
		return err
	}
	if requests == nil {
		return nil
	}
	if connections != nil {
		defer connections.Close()
	}

	pids := eventCtx.CommonPIDsFilter
	if pids == nil {
		return nil
	}

	return ebpfcommon.VisitOngoingHTTPServerRequests(requests, pids,
		func(key ebpfcommon.BpfGoAddrKeyT, span *request.Span) {
			if span.HostPort == 0 && connections != nil {
				var conn gotracer.BpfHttpServerConnectionT
				if err := connections.Lookup(&key, &conn); err == nil {
					span.HostPort = int(conn.Conn.S_port)
				}
			}

			if matchesActiveHTTPServerRequest(span, globalIncoming, startMatchers) {
				visit(span)
			}
		})
}

func newActiveHTTPServerRequestReader(
	cfg *obi.Config,
	eventCtx *ebpfcommon.EBPFEventContext,
) (func(visit func(*request.Span)) error, error) {
	startMatchers, err := activeHTTPServerStartMatchers(cfg)
	if err != nil {
		return nil, err
	}
	globalIncoming := activeHTTPServerGlobalRoutePolicy(cfg.Routes)

	return func(visit func(*request.Span)) error {
		return visitActiveHTTPServerRequests(eventCtx, globalIncoming, startMatchers, visit)
	}, nil
}
