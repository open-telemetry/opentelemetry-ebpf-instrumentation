// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/detectors/aws/ec2/v2"
	"go.opentelemetry.io/contrib/detectors/azure/azurevm"
	"go.opentelemetry.io/contrib/detectors/gcp"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube"
)

func nslog() *slog.Logger {
	return slog.With("component", "meta.NodeStore")
}

// TODO: make configurable
const (
	retryTimeout       = 30 * time.Second
	retryStartInterval = 500 * time.Millisecond
	retryMaxInterval   = 5 * time.Second
)

// host metadata is common to all the instrumented applications within a single
// physical node, cloud instance or local virtual machine.
// This information only needs to be retrieved once at startup, and will be
// directly added in the metrics and traces export, since it has no sense
// configuring an OBI instance to filter by attributes that are static for it.

// each fetcher implementation will return error only when retrying has sense.
// For example, we must not retry if a cloud API endpoint does not exist or it returns 4xx errors,
// because this would mean that OBI is not being executed in that cloud provider.
// But we can retry if the cloud API endpoint returns 5xx errors, as this would indicate
// a temporary unavailability in the Cloud Metadata sevice.
type fetcher func(ctx context.Context) (NodeStore, error)

type NodeStore struct {
	// HostID is a special attribute that needs to be frequently accessed
	// so it's stored separately from the rest of metadata entries
	HostID   string
	Metadata []Entry
}

type Entry struct {
	Key   attr.Name
	Value string
}

func NewNodeStore(
	ctx context.Context,
	kubeInformer *kube.MetadataProvider,
) NodeStore {
	return fetchEntries(ctx,
		// some fetchers will only retrieve the host name while others
		// will retrieve also host attributes that will be merged
		// in order of the priority below (the later the highest)
		linuxLocalFetcher,
		kubeNodeFetcher(kubeInformer),
		otelNodeFetcher(azurevm.New()),
		otelNodeFetcher(gcp.NewDetector()),
		otelNodeFetcher(ec2.NewResourceDetector()),
	)
}

func fetchEntries(
	ctx context.Context,
	fetchers ...fetcher,
) NodeStore {
	log := nslog()
	wg := sync.WaitGroup{}
	// we run in parallel to avoid that timeouts/retries delay the startup too much
	// but we want to keep the priority of the fetchers, so later fetchers can override
	// some data from previous fetchers
	results := make([]NodeStore, len(fetchers))
	for i, fetch := range fetchers {
		wg.Go(func() {
			results[i] = backoffFetch(ctx, fetch, log.With("fetcher", i))
		})
	}
	wg.Wait()

	// Merge all results maintaining priority
	merged := NodeStore{}
	for _, store := range results {
		merged.merge(store)
	}

	// for consistency, sort alphabetically by attribute
	slices.SortFunc(merged.Metadata, func(l, r Entry) int {
		return strings.Compare(string(l.Key), string(r.Key))
	})

	return merged
}

func backoffFetch(ctx context.Context, fetch fetcher, log *slog.Logger) NodeStore {
	backoff := retryStartInterval
	start := time.Now()
	for {
		entries, err := fetch(ctx)
		if err == nil {
			return entries
		}
		// exponential backoff retry strategy
		if time.Since(start) > retryTimeout {
			log.Warn("timeout reached while looking for metadata. Giving up", "error", err)
			return NodeStore{}
		}
		log.Debug("can't fetch metadata. Will retry", "retryAfter", backoff, "error", err)
		select {
		case <-time.After(backoff):
		// continue loop!
		case <-ctx.Done():
			log.Debug("context canceled. Exiting")
			return NodeStore{}
		}
		backoff = min(backoff*2, retryMaxInterval)
	}
}

// merges the attributes. On collision, the src NodeStore will overwrite
// the target NodeStore
func (ns *NodeStore) merge(src NodeStore) {
	if src.HostID != "" {
		ns.HostID = src.HostID
	}
	keyPos := map[attr.Name]int{}
	for i, att := range ns.Metadata {
		keyPos[att.Key] = i
	}
	for _, entry := range src.Metadata {
		if pos, ok := keyPos[entry.Key]; ok {
			// Key is already in destination: overwrite
			ns.Metadata[pos] = entry
		} else {
			ns.Metadata = append(ns.Metadata, entry)
			// theoretically should not be necessary unless src has duplicate Keys
			keyPos[entry.Key] = len(ns.Metadata) - 1
		}
	}
}
