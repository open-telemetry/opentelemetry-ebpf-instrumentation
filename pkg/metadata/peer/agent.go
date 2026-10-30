// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/selection"
)

type Agent struct {
	cfg       Config
	network   network
	store     *localStore
	cache     *peerCache
	client    *http.Client
	server    *http.Server
	listener  net.Listener
	closeOnce sync.Once
}

func New(ctx context.Context, cfg Config, hostname string, serviceGraphEnabled bool,
	metricsPIDs selection.PIDSelector, metricProtocols *instrumentations.InstrumentationSelection,
) (*Agent, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if !validName(hostname) {
		return nil, errors.New("peer metadata requires a valid hostname")
	}

	network, err := localNetwork(cfg.PeerCIDRs)
	if err != nil {
		return nil, err
	}

	serverTLS, clientTLS, err := tlsConfigs(cfg.TLS)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("listening for peer metadata: %w", err)
	}

	if serverTLS != nil {
		listener = tls.NewListener(listener, serverTLS)
	}

	agent := &Agent{
		cfg:      cfg,
		network:  network,
		store:    newStore(hostname, cfg),
		cache:    newPeerCache(cfg),
		client:   newHTTPClient(cfg, clientTLS),
		listener: listener,
	}

	agent.store.graphEnabled = serviceGraphEnabled
	agent.store.metricsPIDs = metricsPIDs
	if metricProtocols != nil {
		agent.store.metricProtocols = *metricProtocols
	}

	agent.server = &http.Server{
		Handler:           metadataHandler(agent.store, cfg, network, agent.cache),
		ReadHeaderTimeout: cfg.RequestTimeout,
		ReadTimeout:       cfg.RequestTimeout,
		WriteTimeout:      cfg.RequestTimeout,
		IdleTimeout:       3 * cfg.RefreshInterval,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	context.AfterFunc(ctx, agent.Close)
	return agent, nil
}

func (a *Agent) Close() {
	a.closeOnce.Do(func() {
		_ = a.server.Close()
		_ = a.listener.Close()
		a.client.CloseIdleConnections()
	})
}

// Run serves local metadata, tracks process inventory, and refreshes peers until cancellation.
func (a *Agent) Run(ctx context.Context, events <-chan exec.ProcessEvent) {
	defer a.Close()

	// We need another afterfunc here, since the context is a child of
	// the context we see in New().
	stopClose := context.AfterFunc(ctx, a.Close)
	defer stopClose()

	var workers sync.WaitGroup

	workers.Go(func() {
		runInventory(ctx, events, a.store, a.cfg.RefreshInterval)
	})

	workers.Go(func() {
		if err := a.server.Serve(a.listener); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
			slog.Error("peer metadata server stopped", "error", err)
		}
	})

	jobs := make(chan *cachedPeer, a.cfg.MaxConcurrent)
	for range a.cfg.MaxConcurrent {
		workers.Go(func() {
			a.fetchPeers(ctx, jobs)
		})
	}

	a.schedulePeers(ctx, jobs)
	workers.Wait()
}

// fetchPeers downloads queued peer snapshots and records each refresh result in the cache.
func (a *Agent) fetchPeers(ctx context.Context, jobs <-chan *cachedPeer) {
	for {
		select {
		case <-ctx.Done():
			return
		case peer := <-jobs:
			started := time.Now()
			snapshot, size, err := fetchSnapshot(ctx, a.client, a.cfg, peer.address)

			var indexed *cachedSnapshot
			if err == nil {
				indexed = indexSnapshot(snapshot)
			} else if ctx.Err() == nil {
				slog.Debug("peer metadata unavailable", "peer", peer.address, "error", err)
			}

			a.cache.complete(peer, indexed, size, started, time.Now())
		}
	}
}

// schedulePeers expires caller observations and queues peer refreshes as capacity allows.
func (a *Agent) schedulePeers(ctx context.Context, jobs chan<- *cachedPeer) {
	ticker := time.NewTicker(max(time.Millisecond, min(time.Second, a.cfg.RefreshInterval/4)))
	defer ticker.Stop()

	for {
		now := time.Now()
		a.store.expire(now)

		for _, peer := range a.cache.due(now, cap(jobs)-len(jobs)) {
			select {
			case jobs <- peer:
			case <-ctx.Done():
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-a.cache.wake:
		}
	}
}

// Decorate records outgoing callers and enriches spans from available peer metadata.
func (a *Agent) Decorate(span *request.Span, now time.Time) {
	if span.Service.ProcPID == app.PID(os.Getpid()) {
		return
	}

	endpoint := Endpoint{Port: span.HostPort}

	// Read the Host IP address, if we fail and it's a client span
	// there's nothing we can do.
	destination, err := netip.ParseAddr(span.Host)
	if err == nil {
		destination = destination.Unmap()
		endpoint.IP = destination.String()
	} else if span.IsClientSpan() {
		return
	}

	if span.IsClientSpan() {
		if !a.network.isLocal(destination) && !a.network.permits(destination) {
			return
		}

		a.decorateClient(span, endpoint, now)
		return
	}

	service := a.resolveCaller(span.Peer, endpoint, now)
	if service.Name == "" {
		return
	}

	span.PeerName = service.Name
	span.OtherNamespace = service.Namespace
}

// decorateClient records outgoing callers and enriches the destination.
func (a *Agent) decorateClient(span *request.Span, destination Endpoint, now time.Time) {
	caller := a.store.serviceFor(span.Service)
	a.store.observe(destination, caller, now)
	service, ignoreClientCount := a.resolveDestination(destination, caller, span.Type, now)
	if service.Name == "" {
		return
	}

	span.HostName = service.Name
	span.OtherNamespace = service.Namespace
	if ignoreClientCount && span.Type != request.EventTypeFailedConnect {
		request.SetIgnoreServiceGraphClientCount(span)
	}
}

// resolveDestination identifies the service and whether to suppress the client graph count.
func (a *Agent) resolveDestination(destination Endpoint, caller Service, event request.EventType, now time.Time) (Service, bool) {
	address, err := netip.ParseAddr(destination.IP)
	if err != nil {
		return Service{}, false
	}

	address = address.Unmap()
	if a.network.isLocal(address) {
		service, match := a.store.destinationService(destination)
		return service, protocolMetricsEnabled(&a.store.metricProtocols, event) &&
			(match == listenerAmbiguous || (match == listenerUnique && service.ServiceGraph))
	}

	if !a.network.permits(address) {
		return Service{}, false
	}

	snapshot, fetchedAt := a.cache.lookup(address, now)
	if snapshot == nil {
		return Service{}, false
	}

	service, match := snapshot.destinationService(destination)
	ignoreClientCount := protocolMetricsEnabled(snapshot.metricProtocols, event) &&
		(match == listenerAmbiguous || (match == listenerUnique && service.ServiceGraph && snapshot.knowsCaller(destination, caller, now.Sub(fetchedAt))))
	return service, ignoreClientCount
}

// resolveCaller identifies a caller from recent observations, using its hostname as a fallback.
func (a *Agent) resolveCaller(remoteIP string, destination Endpoint, now time.Time) Service {
	address, err := netip.ParseAddr(remoteIP)
	if err != nil {
		return Service{}
	}

	address = address.Unmap()
	if a.network.isLocal(address) {
		return a.store.callerService(destination, now)
	}

	if !a.network.permits(address) {
		return Service{}
	}

	snapshot, fetchedAt := a.cache.lookup(address, now)
	if snapshot == nil {
		return Service{}
	}

	return snapshot.callerService(destination, now.Sub(fetchedAt))
}
