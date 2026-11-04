// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/obi/pkg/metadata/peer/metadatapb"
)

// peerExchange serves the local store over gRPC and fetches snapshots directly from each remote agent.
type peerExchange struct {
	metadatapb.UnimplementedPeerMetadataServiceServer

	cfg       MetadataConfig
	store     *localStore
	network   network
	cache     *peerCache
	clients   *peerClients
	server    *grpc.Server
	listener  net.Listener
	closeOnce sync.Once
}

func newPeerExchange(cfg MetadataConfig, store *localStore, network network) (*peerExchange, error) {
	serverTLS, clientTLS, err := tlsConfigs(cfg.TLS)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("listening for peer metadata: %w", err)
	}

	p := &peerExchange{
		cfg:      cfg,
		store:    store,
		network:  network,
		cache:    newPeerCache(cfg),
		clients:  newPeerClients(&cfg, clientTLS),
		server:   grpc.NewServer(peerServerOptions(&cfg, serverTLS)...),
		listener: listener,
	}

	metadatapb.RegisterPeerMetadataServiceServer(p.server, p)
	return p, nil
}

func (p *peerExchange) close() {
	p.closeOnce.Do(func() {
		p.server.Stop()
		_ = p.listener.Close()
		p.clients.close()
	})
}

func (p *peerExchange) lookup(address netip.Addr, now time.Time) (*cachedSnapshot, time.Time) {
	return p.cache.lookup(address, now)
}

// GetSnapshot serves the local metadata, limiting caller observations to the requester's source address.
func (p *peerExchange) GetSnapshot(ctx context.Context, _ *metadatapb.GetSnapshotRequest) (*metadatapb.Snapshot, error) {
	requester, ok := requesterAddress(ctx)
	if !ok || !p.network.permits(requester) {
		return nil, status.Error(codes.PermissionDenied, "peer address is not permitted")
	}

	now := time.Now()
	snapshot := p.store.snapshot(map[string]struct{}{requester.String(): {}}, now)
	snapshot.KnownCallers = p.cache.knownCallers(requester, now)
	return snapshotToProto(&snapshot), nil
}

// run serves local metadata and refreshes peers until cancellation.
func (p *peerExchange) run(ctx context.Context) {
	var workers sync.WaitGroup

	workers.Go(func() {
		if err := p.server.Serve(p.listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) && ctx.Err() == nil {
			slog.Error("peer metadata server stopped", "error", err)
		}
	})

	jobs := make(chan *cachedPeer, p.cfg.MaxConcurrent)
	for range p.cfg.MaxConcurrent {
		workers.Go(func() {
			p.fetchPeers(ctx, jobs)
		})
	}

	p.schedulePeers(ctx, jobs)
	workers.Wait()
}

// fetchPeers downloads queued peer snapshots and records each refresh result in the cache.
func (p *peerExchange) fetchPeers(ctx context.Context, jobs <-chan *cachedPeer) {
	for {
		select {
		case <-ctx.Done():
			return
		case peer := <-jobs:
			started := time.Now()
			snapshot, size, err := p.fetch(ctx, peer.address)

			var indexed *cachedSnapshot
			if err == nil {
				indexed = indexSnapshot(snapshot)
			} else if ctx.Err() == nil {
				slog.Debug("peer metadata unavailable", "peer", peer.address, "error", err)
			}

			p.cache.complete(peer, indexed, size, started, time.Now())
		}
	}
}

func (p *peerExchange) fetch(ctx context.Context, address netip.Addr) (*Snapshot, int, error) {
	client, err := p.clients.get(address)
	if err != nil {
		return nil, 0, err
	}

	return fetchSnapshot(ctx, client, &p.cfg)
}

// schedulePeers queues peer refreshes as capacity allows, and closes the connections to evicted peers.
func (p *peerExchange) schedulePeers(ctx context.Context, jobs chan<- *cachedPeer) {
	ticker := time.NewTicker(pollInterval(&p.cfg))
	defer ticker.Stop()

	for {
		for _, peer := range p.cache.due(time.Now(), cap(jobs)-len(jobs)) {
			select {
			case jobs <- peer:
			case <-ctx.Done():
				return
			}
		}
		p.clients.retain(p.cache.contains)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-p.cache.wake:
		}
	}
}
