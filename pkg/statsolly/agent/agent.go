// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

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
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	stats "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const (
	listenPoll  = "poll"
	listenWatch = "watch"

	ipTypeAny  = "any"
	ipTypeIPV4 = "ipv4"
	ipTypeIPV6 = "ipv6"

	ipIfaceExternal    = "external"
	ipIfaceLocal       = "local"
	ipIfaceNamedPrefix = "name:"
)

func alog() *slog.Logger {
	return slog.With("component", "agent.StatsO11y")
}

// Status of the agent service. Helps on the health report as well as making some asynchronous
// tests waiting for the agent to accept stats.
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

// Stats reporting agent
type Stats struct {
	cfg     *obi.Config
	ctxInfo *global.ContextInfo
	graph   *swarm.Runner

	// input data providers
	// TODO pinoOgni is this needed?
	ifaceManager *tcmanager.InterfaceManager

	// elements used to decorate stats with extra information
	agentIP net.IP

	// stats metrics
	rbTracer *stats.RingBufTracer

	// focuses on TCP/UDP stack internals (kprobes/tracepoints)
	fetcher ebpFetcher

	status Status
}

type ebpFetcher interface {
	io.Closer
	ReadRingBuf() (ringbuf.Record, error)
}

// StatsAgent instantiates a new agent, given a configuration.
func StatsAgent(ctxInfo *global.ContextInfo, cfg *obi.Config) (*Stats, error) {
	alog := alog()
	alog.Info("initializing Stats agent")

	var (
		ifaceManager *tcmanager.InterfaceManager
		statsFetcher ebpFetcher
		err          error
	)

	alog.Debug("acquiring Agent IP")
	agentIP, err := fetchAgentIP(&cfg.Stats)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}
	alog.Debug("agent IP: " + agentIP.String())

	statsFetcher, err = newFetcher(cfg, alog)
	if err != nil {
		return nil, err
	}

	ifaceManager = tcmanager.NewInterfaceManager()
	ifaceManager.SetChannelBufferLen(cfg.ChannelBufferLen)
	ifaceManager.SetPollPeriod(cfg.Stats.ListenPollPeriod)
	ifaceManager.SetMonitorMode(monitorMode(cfg, alog))

	return statsAgent(ctxInfo, cfg, statsFetcher, agentIP, ifaceManager)
}

func newFetcher(cfg *obi.Config, alog *slog.Logger) (ebpFetcher, error) {
	// We may need to add some arguments in the future
	return ebpf.NewStatsFetcher()
}

// TODO pinoOgni check
func monitorMode(cfg *obi.Config, alog *slog.Logger) tcmanager.MonitorMode {
	switch cfg.Stats.ListenInterfaces {
	case listenPoll:
		alog.Debug("listening for new interfaces: use polling",
			"period", cfg.Stats.ListenPollPeriod)

		return tcmanager.MonitorPoll
	case listenWatch:
		alog.Debug("listening for new interfaces: use watching")

		return tcmanager.MonitorWatch
	}

	alog.Warn("wrong interface listen method. Using file watcher as default",
		"providedValue", cfg.Stats.ListenInterfaces)

	return tcmanager.MonitorWatch
}

// statsAgent is a private constructor with injectable dependencies, usable for tests
func statsAgent(
	ctxInfo *global.ContextInfo,
	cfg *obi.Config,
	statsFetcher ebpFetcher,
	agentIP net.IP,
	ifaceManager *tcmanager.InterfaceManager,
) (*Stats, error) {
	var rbTracer *stats.RingBufTracer

	rbTracer = stats.NewRingBufTracer(statsFetcher)

	return &Stats{
		ctxInfo:      ctxInfo,
		ifaceManager: ifaceManager,
		cfg:          cfg,
		rbTracer:     rbTracer,
		agentIP:      agentIP,
		fetcher:      statsFetcher,
	}, nil
}

// Run a Stats agent
func (s *Stats) Run(ctx context.Context) error {
	alog := alog()

	s.status = StatusStarting
	alog.Info("starting Stats agent")

	graph, err := s.buildPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	s.graph = graph

	s.ifaceManager.Start(ctx)

	s.graph.Start(ctx, swarm.WithCancelTimeout(s.cfg.ShutdownTimeout))
	s.status = StatusStarted

	alog.Info("Stats agent successfully started")

	<-ctx.Done()

	if err := s.stop(); err != nil {
		return fmt.Errorf("failed to stop Stats agent: %w", err)
	}

	return nil
}

func (s *Stats) stop() error {
	alog := alog()

	stopped := make(chan error)
	go func() {
		s.status = StatusStopping
		alog.Info("stopping Stats agent")
		if err := s.fetcher.Close(); err != nil {
			alog.Warn("eBPF resources not correctly closed", "error", err)
		}

		alog.Debug("waiting for all nodes to finish their pending work")

		s.ifaceManager.Wait()
		<-s.graph.Done()
		s.status = StatusStopped

		if err := <-s.graph.Done(); err != nil {
			stopped <- err
		}
		close(stopped)

		alog.Info("Stats agent stopped")
	}()

	select {
	case <-time.After(s.cfg.ShutdownTimeout):
		return errShutdownTimeout
	case err := <-stopped:
		// err might be nil
		return err
	}
}

func (s *Stats) Status() Status {
	return s.status
}
