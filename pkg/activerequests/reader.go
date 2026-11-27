// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package activerequests reads active HTTP server requests from the shared eBPF map.
package activerequests // import "go.opentelemetry.io/obi/pkg/activerequests"

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/selection"
)

const (
	activeRequestsMapName = "active_requests"
	defaultMaxAge         = 5 * time.Minute
)

type Config struct {
	MaxAge                time.Duration
	ApplicationFilter     filter.AttributeFamilyConfig
	InstrumentationFilter filter.InstrumentationAttributeFamilyConfig
	ExtraGroupAttributes  map[string][]attr.Name
	GlobalRoutePolicy     *svc.RoutePolicy
	DynamicSelector       selection.MultiSignalPIDSelector
}

// Request holds the HTTP server information needed to count an active request.
type Request struct {
	Service         svc.Attrs
	Method          string
	Path            string
	Route           string
	Scheme          string
	ServerAddress   string
	ServerPort      int
	StartMonotimeNs uint64
}

// Count is the number of active requests for a service and metric attribute set.
type Count struct {
	Service    svc.Attrs
	Attributes attribute.Set
	Value      int64
}

type Reader struct {
	eventCtx     *ebpfcommon.EBPFEventContext
	config       Config
	initOnce     sync.Once
	initErr      error
	appMatchers  filter.MatcherSet[*Request]
	httpMatchers filter.MatcherSet[*Request]
}

func NewReader(eventCtx *ebpfcommon.EBPFEventContext, cfg Config) *Reader {
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = defaultMaxAge
	}
	return &Reader{eventCtx: eventCtx, config: cfg}
}

// Collect reads and counts the currently active requests by service and selected attributes.
func (r *Reader) Collect(names []attr.Name) ([]Count, error) {
	requests, err := r.Snapshot()
	if err != nil {
		return nil, err
	}
	return countRequests(requests, names), nil
}

// Snapshot reads the map without clearing live records and excludes expired records.
func (r *Reader) Snapshot() ([]Request, error) {
	if r == nil || r.eventCtx == nil || r.eventCtx.CommonPIDsFilter == nil {
		return nil, nil
	}
	r.initOnce.Do(r.initMatchers)
	if r.initErr != nil {
		return nil, fmt.Errorf("active request filters: %w", r.initErr)
	}
	now := timing.MonoTimeNow()
	if now == 0 {
		return nil, errors.New("read monotonic time for active requests")
	}
	r.eventCtx.MapsLock.Lock()
	requestsMap := r.eventCtx.EBPFMaps[activeRequestsMapName]
	if requestsMap == nil {
		r.eventCtx.MapsLock.Unlock()
		return nil, nil
	}
	mapHandle, err := requestsMap.Clone()
	r.eventCtx.MapsLock.Unlock()
	if err != nil {
		return nil, fmt.Errorf("clone active requests map: %w", err)
	}
	defer mapHandle.Close()

	currentPIDs := r.eventCtx.CommonPIDsFilter.CurrentPIDs(ebpfcommon.PIDTypeGo | ebpfcommon.PIDTypeKProbes)
	result := []Request{}
	seen := map[ebpfcommon.BpfActiveRequestKeyT]struct{}{}
	iterator := mapHandle.Iterate()
	var key ebpfcommon.BpfActiveRequestKeyT
	var active ebpfcommon.BpfActiveRequestT
	for iterator.Next(&key, &active) {
		if expired(active.StartMonotimeNs, now, r.config.MaxAge) {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		service, ok := currentPIDs[active.Pid.Ns][app.PID(active.Pid.UserPid)]
		if !ok || !service.Features.HTTPServerActiveRequests() || !service.ExportModes.CanExportMetrics() {
			continue
		}
		if r.config.DynamicSelector != nil {
			pid := service.DynamicSelectorPID
			if pid == 0 {
				pid = service.ProcPID
			}
			if !r.config.DynamicSelector.AppMetrics().IncludesPID(pid) {
				continue
			}
		}
		entry := activeRequest(active, service)
		if !r.include(&entry) {
			continue
		}
		result = append(result, entry)
	}
	if err := iterator.Err(); err != nil {
		return nil, fmt.Errorf("iterate active requests map: %w", err)
	}

	return result, nil
}

func (r *Reader) initMatchers() {
	r.appMatchers, r.initErr = filter.NewMatcherSet(
		r.config.ApplicationFilter, nil, r.config.ExtraGroupAttributes, PromGetters())
	if r.initErr != nil {
		return
	}
	r.httpMatchers, r.initErr = filter.NewMatcherSet(
		r.config.InstrumentationFilter[instrumentations.InstrumentationHTTP].Metrics,
		nil, r.config.ExtraGroupAttributes, PromGetters())
}

func expired(start uint64, now, ttl time.Duration) bool {
	return start == 0 || ttl > 0 && now >= time.Duration(start) && now-time.Duration(start) >= ttl
}

func activeRequest(active ebpfcommon.BpfActiveRequestT, service svc.Attrs) Request {
	scheme := "http"
	if active.IsTls != 0 {
		scheme = "https"
	}
	host := ""
	address := net.IP(active.Conn.S_addr[:])
	if !address.IsUnspecified() {
		host = address.String()
	}
	return Request{
		Method:          unix.ByteSliceToString(active.Method[:]),
		Path:            unix.ByteSliceToString(active.Path[:]),
		Scheme:          scheme,
		ServerAddress:   host,
		ServerPort:      int(active.Conn.S_port),
		StartMonotimeNs: active.StartMonotimeNs,
		Service:         service,
	}
}

func (r *Reader) include(entry *Request) bool {
	policy := entry.Service.IncomingRoutePolicy
	if policy == nil {
		policy = r.config.GlobalRoutePolicy
	}
	if policy != nil && policy.IgnoreMatcher != nil && policy.IgnoreMatcher.Find(entry.Path) != "" {
		mode := policy.Config.IgnoredEvents
		if mode == "" {
			mode = services.IgnoreDefault
		}
		if mode == services.IgnoreMetrics || mode == services.IgnoreAll {
			return false
		}
	}
	if policy != nil && policy.Matcher != nil {
		entry.Route = policy.Matcher.Find(entry.Path)
	}
	if entry.Route == "" && entry.Service.CustomInRouteMatcher != nil {
		entry.Route = entry.Service.CustomInRouteMatcher.Find(entry.Path)
	}
	if entry.Route == "" && entry.Service.HarvestedRouteMatcher != nil {
		entry.Route = entry.Service.HarvestedRouteMatcher.Find(entry.Path)
	}
	return r.appMatchers.Matches(entry) && r.httpMatchers.Matches(entry)
}

func countRequests(requests []Request, names []attr.Name) []Count {
	fields := attributes.OpenTelemetryGetters(OTELGetters(), names)
	type countKey struct {
		service svc.UID
		attrs   attribute.Distinct
	}
	counts := make(map[countKey]Count, len(requests))
	for i := range requests {
		active := &requests[i]
		values := make([]attribute.KeyValue, 0, len(fields))
		for _, field := range fields {
			kv := field.Get(active)
			if !kv.Valid() {
				continue
			}
			if kv.Value.Type() == attribute.STRING {
				kv = kv.Key.String(attributes.SanitizeUTF8(kv.Value.AsString()))
			}
			values = append(values, kv)
		}

		set := attribute.NewSet(values...)
		key := countKey{service: active.Service.UID, attrs: set.Equivalent()}
		count := counts[key]
		count.Service = active.Service
		count.Attributes = set
		count.Value++
		counts[key] = count
	}

	result := make([]Count, 0, len(counts))
	for _, count := range counts {
		result = append(result, count)
	}
	return result
}
