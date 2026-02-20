// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package agent // import "go.opentelemetry.io/obi/pkg/netolly/agent"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tcmanager"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/netolly/flow"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const (
	listenPoll       = "poll"
	listenWatch      = "watch"
	directionIngress = "ingress"
	directionEgress  = "egress"
	directionBoth    = "both"

	ipTypeAny  = "any"
	ipTypeIPV4 = "ipv4"
	ipTypeIPV6 = "ipv6"

	ipIfaceExternal    = "external"
	ipIfaceLocal       = "local"
	ipIfaceNamedPrefix = "name:"
)

func alog() *slog.Logger {
	return slog.With("component", "agent.Flows")
}

// Status of the agent service. Helps on the health report as well as making some asynchronous
// tests waiting for the agent to accept flows.
type Status int

const (
	StatusNotStarted Status = iota
	StatusStarting
	StatusStarted
	StatusStopping
	StatusStopped
)

func (s Status) String() string {
	switch s {
	case StatusNotStarted:
		return "StatusNotStarted"
	case StatusStarting:
		return "StatusStarting"
	case StatusStarted:
		return "StatusStarted"
	case StatusStopping:
		return "StatusStopping"
	case StatusStopped:
		return "StatusStopped"
	default:
		return "invalid"
	}
}

var errShutdownTimeout = errors.New("graceful shutdown has timed out while waiting for eBPF network infrastructure to finish")

// Flows reporting agent
// pino 4
// posso creare un mio flows e usare come ringbuffer qualcosa di mio?
type Flows struct {
	cfg     *obi.Config
	ctxInfo *global.ContextInfo
	graph   *swarm.Runner

	// input data providers
	ifaceManager *tcmanager.InterfaceManager
	// focuses on L3/L4 traffic (tc/sock)
	flowFetcher ebpfFlowFetcher

	// processing nodes to be wired in the buildPipeline method
	mapTracer *flow.MapTracer
	rbTracer  *flow.RingBufTracer

	// elements used to decorate flows with extra information
	interfaceNamer flow.InterfaceNamer
	agentIP        net.IP

	// stats metrics
	rbStatsTracer *flow.RingBufStatsTracer

	// focuses on TCP/UDP stack internals (kprobes/tracepoints)
	statsFetcher ebpfStatsFetcher

	status Status
}

// ebpfFlowFetcher abstracts the interface of ebpf.FlowFetcher to allow dependency injection in tests
// pino 7
// occhio
type ebpfFlowFetcher interface {
	io.Closer

	LookupAndDeleteMap() map[ebpf.NetFlowId][]ebpf.NetFlowMetrics
	ReadRingBuf() (ringbuf.Record, error)
}

type ebpfStatsFetcher interface {
	io.Closer

	//LookupAndDeleteMap() map[ebpf.NetFlowId][]ebpf.NetFlowMetrics
	ReadRingBuf() (ringbuf.Record, error)
}

// FlowsAgent instantiates a new agent, given a configuration.
func FlowsAgent(ctxInfo *global.ContextInfo, cfg *obi.Config) (*Flows, error) {
	alog := alog()
	alog.Info("initializing Flows agent")

	var (
		ifaceManager *tcmanager.InterfaceManager
		flowFetcher  ebpfFlowFetcher
		statsFetcher ebpfStatsFetcher
		err          error
	)

	// 1. Common Logic: Acquire Agent IP
	alog.Debug("acquiring Agent IP")
	agentIP, err := fetchAgentIP(&cfg.NetworkFlows)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}
	alog.Debug("agent IP: " + agentIP.String())

	// 2. Conditional Initialization based on Metrics mode
	// Assuming Metrics is a field in your config (e.g., cfg.Metrics)
	mode := cfg.NetworkFlows.Metrics

	// Setup Stats if mode is "stats" or "all"
	if mode == "stats" || mode == "all" {
		statsFetcher, err = newStatsFetcher(cfg, alog)
		if err != nil {
			return nil, err
		}
	}

	// Setup Flows if mode is "flows" or "all"
	if mode == "flows" || mode == "all" {
		// TODO pino rafael check if ifaceManager is used for stats
		ifaceManager = tcmanager.NewInterfaceManager()
		ifaceManager.SetChannelBufferLen(cfg.ChannelBufferLen)
		ifaceManager.SetPollPeriod(cfg.NetworkFlows.ListenPollPeriod)
		ifaceManager.SetMonitorMode(monitorMode(cfg, alog))

		flowFetcher, err = newFlowFetcher(cfg, alog, ifaceManager)
		if err != nil {
			return nil, err
		}
	}

	// 3. Return the agent with whatever was (or wasn't) initialized
	// If a component wasn't initialized, its variable remains 'nil'

	// pino 6
	// forse posso togliere return e modificare ebpfFlowFetcher aggiungendo la parte del tracer
	// se non c'e' ne tc ne sock devo comunque aggiungere la mia parte
	return flowsAgent(ctxInfo, cfg, flowFetcher, statsFetcher, agentIP, ifaceManager)
}

func newFlowFetcher(cfg *obi.Config, alog *slog.Logger, ifaceManager *tcmanager.InterfaceManager) (ebpfFlowFetcher, error) {
	// pino 3
	// non so se e' il posto giusto, sicuro non devo dipendere da tc o sock pero' se sono abilitati devo trovare il modo di abilitare tutti e due
	// Check if application network metrics are enabled
	switch cfg.NetworkFlows.Source {
	case obi.EbpfSourceSock:
		alog.Info("using socket filter for collecting network events")

		return ebpf.NewSockFlowFetcher(cfg.NetworkFlows.Sampling, cfg.NetworkFlows.CacheMaxFlows)
	case obi.EbpfSourceTC:
		alog.Info("using kernel Traffic Control for collecting network events")
		ingress, egress := flowDirections(&cfg.NetworkFlows)

		return ebpf.NewFlowFetcher(cfg.NetworkFlows.Sampling, cfg.NetworkFlows.CacheMaxFlows,
			ingress, egress, ifaceManager, cfg.EBPF.TCBackend)
	}

	return nil, errors.New("unknown network configuration eBPF source specified, allowed options are [tc, socket_filter]")
}

func newStatsFetcher(cfg *obi.Config, alog *slog.Logger) (ebpfStatsFetcher, error) {
	return ebpf.NewStatsFetcher()

	//return nil, errors.New("unknown network configuration eBPF source specified, allowed options are [tc, socket_filter]")
}

func monitorMode(cfg *obi.Config, alog *slog.Logger) tcmanager.MonitorMode {
	switch cfg.NetworkFlows.ListenInterfaces {
	case listenPoll:
		alog.Debug("listening for new interfaces: use polling",
			"period", cfg.NetworkFlows.ListenPollPeriod)

		return tcmanager.MonitorPoll
	case listenWatch:
		alog.Debug("listening for new interfaces: use watching")

		return tcmanager.MonitorWatch
	}

	alog.Warn("wrong interface listen method. Using file watcher as default",
		"providedValue", cfg.NetworkFlows.ListenInterfaces)

	return tcmanager.MonitorWatch
}

// flowsAgent is a private constructor with injectable dependencies, usable for tests
func flowsAgent(
	ctxInfo *global.ContextInfo,
	cfg *obi.Config,
	flowFetcher ebpfFlowFetcher,
	statsFetcher ebpfStatsFetcher,
	agentIP net.IP,
	ifaceManager *tcmanager.InterfaceManager,
) (*Flows, error) {
	var (
		interfaceNamer func(ifIndex int) string
		mapTracer      *flow.MapTracer
		rbTracer       *flow.RingBufTracer
		rbStatsTracer  *flow.RingBufStatsTracer
	)
	mode := cfg.NetworkFlows.Metrics
	if mode == "flows" || mode == "all" {
		// configure allow/deny interfaces filter
		filter, err := tcmanager.NewInterfaceFilter(cfg.NetworkFlows.Interfaces, cfg.NetworkFlows.ExcludeInterfaces)
		if err != nil {
			return nil, fmt.Errorf("configuring interface filters: %w", err)
		}

		ifaceManager.SetInterfaceFilter(filter)

		interfaceNamer = func(ifIndex int) string {
			iface, ok := ifaceManager.InterfaceName(ifIndex)
			if !ok {
				return "unknown"
			}
			return iface
		}

		mapTracer = flow.NewMapTracer(flowFetcher, cfg.NetworkFlows.CacheActiveTimeout)
		rbTracer = flow.NewRingBufTracer(flowFetcher, mapTracer, cfg.NetworkFlows.CacheActiveTimeout)
	}
	if mode == "stats" || mode == "all" {
		rbStatsTracer = flow.NewRingBufStatsTracer(statsFetcher)
	}

	return &Flows{
		ctxInfo:        ctxInfo,
		flowFetcher:    flowFetcher,
		ifaceManager:   ifaceManager,
		cfg:            cfg,
		mapTracer:      mapTracer,
		rbTracer:       rbTracer,
		rbStatsTracer:  rbStatsTracer,
		agentIP:        agentIP,
		interfaceNamer: interfaceNamer,
	}, nil
}

func flowDirections(cfg *obi.NetworkConfig) (ingress, egress bool) {
	switch cfg.Direction {
	case directionIngress:
		return true, false
	case directionEgress:
		return false, true
	case directionBoth:
		return true, true
	default:
		alog().Warn("unknown DIRECTION. Tracing both ingress and egress traffic",
			"direction", cfg.Direction)
		return true, true
	}
}

// Run a Flows agent
func (f *Flows) Run(ctx context.Context) error {
	alog := alog()

	f.status = StatusStarting
	alog.Info("starting Flows agent")

	graph, err := f.buildPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	f.graph = graph

	if f.cfg.NetworkFlows.Metrics != "stats" {
		f.ifaceManager.Start(ctx)
	}

	f.graph.Start(ctx, swarm.WithCancelTimeout(f.cfg.ShutdownTimeout))
	f.status = StatusStarted

	alog.Info("Flows agent successfully started")

	<-ctx.Done()

	if err := f.stop(); err != nil {
		return fmt.Errorf("failed to stop Flows agent: %w", err)
	}

	return nil
}

func (f *Flows) stop() error {
	alog := alog()

	stopped := make(chan error)
	go func() {
		f.status = StatusStopping
		alog.Info("stopping Flows agent")
		if err := f.flowFetcher.Close(); err != nil {
			alog.Warn("eBPF resources not correctly closed", "error", err)
		}

		alog.Debug("waiting for all nodes to finish their pending work")

		f.ifaceManager.Wait()
		<-f.graph.Done()
		f.status = StatusStopped

		if err := <-f.graph.Done(); err != nil {
			stopped <- err
		}
		close(stopped)

		alog.Info("Flows agent stopped")
	}()

	select {
	case <-time.After(f.cfg.ShutdownTimeout):
		return errShutdownTimeout
	case err := <-stopped:
		// err might be nil
		return err
	}
}

func (f *Flows) Status() Status {
	return f.status
}
