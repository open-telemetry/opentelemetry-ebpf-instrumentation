// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly // import "go.opentelemetry.io/obi/pkg/appolly"

import (
	"context"
	"errors"
	"maps"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/selection"
)

const (
	httpServerRequestIDsMap            = "http_server_request_ids"
	httpServerRequestReconcileInterval = 3 * time.Second
)

type httpServerRequestKey struct {
	hostPID         uint32
	goroutineAddr   uint64
	startMonotimeNs uint64
}

type httpServerRequestTracker struct {
	active map[httpServerRequestKey]request.Span
}

func (t *httpServerRequestTracker) observe(
	event ebpfcommon.HTTPServerRequestEvent,
	service svc.Attrs,
) (request.Span, int64) {
	key := httpServerRequestKey{
		hostPID:         event.Pid.HostPid,
		goroutineAddr:   event.GoroutineAddr,
		startMonotimeNs: event.StartMonotimeNs,
	}

	switch event.Type {
	case ebpfcommon.EventTypeHTTPServerRequestStart:
		if _, exists := t.active[key]; exists {
			return request.Span{}, 0
		}

		if t.active == nil {
			t.active = make(map[httpServerRequestKey]request.Span)
		}

		span := ebpfcommon.HTTPServerRequestEventToSpan(&event)
		span.Service = service

		// Keep the start attributes stable until the request ends.
		span.Service.Metadata = maps.Clone(service.Metadata)
		span.Service.EnvVars = maps.Clone(service.EnvVars)

		t.active[key] = span
		return span, 1

	case ebpfcommon.EventTypeHTTPServerRequestEnd:
		span, exists := t.active[key]
		if !exists {
			return request.Span{}, 0
		}

		delete(t.active, key)
		return span, -1
	}

	return request.Span{}, 0
}

func (t *httpServerRequestTracker) removePID(
	procPID app.PID,
) []request.Span {
	var removed []request.Span

	for key, start := range t.active {
		if start.Service.ProcPID != procPID {
			continue
		}

		removed = append(removed, start)
		delete(t.active, key)
	}

	return removed
}

func (c *httpServerRequestCollector) service(
	pid ebpfcommon.BpfPidInfoT,
) (svc.Attrs, bool) {
	pids, ok := c.currentPIDs[pid.Ns]
	if !ok {
		return svc.Attrs{}, false
	}

	service, ok := pids[app.PID(pid.UserPid)]
	if !ok {
		return svc.Attrs{}, false
	}

	// FileInfo updates remain visible even when the gate suppresses duplicate create events.
	if file := c.processFiles[service.ProcPID]; file != nil {
		service = file.UnsafeServiceAttrs()
	}
	if !service.Features.HTTPServerActiveRequests() {
		return svc.Attrs{}, false
	}

	return service, true
}

type httpServerRequestCollector struct {
	currentPIDs     map[uint32]map[app.PID]svc.Attrs
	processFiles    map[app.PID]*exec.FileInfo
	metricsSelector selection.PIDSelector
	tracker         httpServerRequestTracker
	output          *msg.Queue[[]request.HTTPServerRequestDelta]
}

func httpServerRequestsNode(
	selector selection.MultiSignalPIDSelector,
	eventContext *ebpfcommon.EBPFEventContext,
	bufferLen int,
	processEvents *msg.Queue[exec.ProcessEvent],
	output *msg.Queue[[]request.HTTPServerRequestDelta],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		requests := make(chan ebpfcommon.HTTPServerRequestEvent, bufferLen)
		processInput := processEvents.Subscribe(
			msg.SubscriberName("appolly.HTTPServerRequests"),
		)

		requestsCtx, stopRequests := context.WithCancel(ctx)
		eventContext.HTTPServerRequests = func(event ebpfcommon.HTTPServerRequestEvent) {
			select {
			case <-requestsCtx.Done():
				return
			case requests <- event:
			}
		}

		collector := &httpServerRequestCollector{
			output: output,
		}
		if selector != nil {
			collector.metricsSelector = selector.AppMetrics()
		}

		run := collector.run(eventContext, requests, processInput)

		return func(ctx context.Context) {
			defer stopRequests()
			run(ctx)
		}, nil
	}
}

func (c *httpServerRequestCollector) handleRequest(
	ctx context.Context,
	event ebpfcommon.HTTPServerRequestEvent,
) {
	var service svc.Attrs

	if event.Type == ebpfcommon.EventTypeHTTPServerRequestStart {
		var ok bool
		service, ok = c.service(event.Pid)
		if !ok {
			return
		}

		if c.metricsSelector != nil {
			pid := dynamicSignalPID(&request.Span{Service: service})
			if !c.metricsSelector.IncludesPID(pid) {
				return
			}
		}
	}

	span, delta := c.tracker.observe(event, service)
	if delta == 0 {
		return
	}

	c.output.SendCtx(ctx, []request.HTTPServerRequestDelta{{
		Span:  span,
		Delta: delta,
	}})
}

func (c *httpServerRequestCollector) removeProcess(
	ctx context.Context,
	procPID app.PID,
) {
	delete(c.processFiles, procPID)
	for _, pids := range c.currentPIDs {
		for pid, service := range pids {
			if service.ProcPID == procPID {
				delete(pids, pid)
			}
		}
	}

	removed := c.tracker.removePID(procPID)
	if len(removed) == 0 {
		return
	}

	deltas := make([]request.HTTPServerRequestDelta, len(removed))
	for i, span := range removed {
		deltas[i] = request.HTTPServerRequestDelta{
			Span:  span,
			Delta: -1,
		}
	}

	c.output.SendCtx(ctx, deltas)
}

func (c *httpServerRequestCollector) run(
	eventContext *ebpfcommon.EBPFEventContext,
	requests <-chan ebpfcommon.HTTPServerRequestEvent,
	processEvents <-chan exec.ProcessEvent,
) swarm.RunFunc {
	return func(ctx context.Context) {
		defer c.output.Close()
		ticker := time.NewTicker(httpServerRequestReconcileInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case <-ticker.C:
				c.reconcile(ctx, eventContext)

			case event, ok := <-requests:
				if !ok {
					return
				}

				if event.Type == ebpfcommon.EventTypeHTTPServerRequestStart {
					_, known := c.currentPIDs[event.Pid.Ns][app.PID(event.Pid.UserPid)]
					if !known && eventContext.CommonPIDsFilter != nil {
						c.currentPIDs = eventContext.CommonPIDsFilter.CurrentPIDs(
							ebpfcommon.PIDTypeGo,
						)
					}
				}

				c.handleRequest(ctx, event)

			case event, ok := <-processEvents:
				if !ok {
					return
				}
				if event.File == nil {
					continue
				}

				switch event.Type {
				case exec.ProcessEventCreated:
					if c.processFiles == nil {
						c.processFiles = make(map[app.PID]*exec.FileInfo)
					}
					c.processFiles[event.File.Pid()] = event.File
					if eventContext.CommonPIDsFilter != nil {
						c.currentPIDs = eventContext.CommonPIDsFilter.CurrentPIDs(
							ebpfcommon.PIDTypeGo,
						)
					}

				case exec.ProcessEventTerminated:
					c.removeProcess(ctx, event.File.Pid())
				}
			}
		}
	}
}

// Reconcile missed end events without expiring requests that are still running.
func (c *httpServerRequestCollector) reconcile(ctx context.Context, eventContext *ebpfcommon.EBPFEventContext) {
	var deltas []request.HTTPServerRequestDelta
	eventContext.MapsLock.Lock()
	if ids := eventContext.EBPFMaps[httpServerRequestIDsMap]; ids != nil {
		for key, span := range c.tracker.active {
			var pid ebpfcommon.BpfPidInfoT
			err := ids.Lookup(ebpfcommon.BpfHttpServerRequestKeyT{
				Pid:             uint64(key.hostPID),
				GoroutineAddr:   key.goroutineAddr,
				StartMonotimeNs: key.startMonotimeNs,
			}, &pid)
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				delete(c.tracker.active, key)
				deltas = append(deltas, request.HTTPServerRequestDelta{Span: span, Delta: -1})
			}
		}
	}
	eventContext.MapsLock.Unlock()

	if len(deltas) != 0 {
		c.output.SendCtx(ctx, deltas)
	}
}
