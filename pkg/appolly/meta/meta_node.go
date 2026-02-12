// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"log/slog"
	"sync"
	"time"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
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
type fetcher func(ctx context.Context) ([]Entry, error)

type NodeStore struct {
	Metadata []Entry
}

type Entry struct {
	Key   attr.Name
	Value string
}

func NewNodeStore(
	ctx context.Context,
) *NodeStore {
	return &NodeStore{
		Metadata: fetchEntries(ctx,
			awsNodeFetcher,
		),
	}
}

func fetchEntries(
	ctx context.Context,
	fetchers ...fetcher,
) []Entry {
	log := nslog()
	wg := sync.WaitGroup{}
	// we run in parallel to avoid that timeouts/retries delay the startup too much
	// but we want to keep the priority of the fetchers, so later fetchers can override
	// some data from previous fetchers
	results := make([][]Entry, len(fetchers))
	for i, fetch := range fetchers {
		wg.Go(func() {
			results[i] = backoffFetch(ctx, fetch, log.With("fetcher", i))
		})
	}
	wg.Wait()

	// Concatenate all results maintaining order
	var allEntries []Entry
	for _, entries := range results {
		allEntries = append(allEntries, entries...)
	}
	return dedupeKeys(allEntries)
}

func backoffFetch(ctx context.Context, fetch fetcher, log *slog.Logger) []Entry {
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
			return nil
		}
		log.Debug("can't fetch metadata. Will retry", "retryAfter", backoff, "error", err)
		select {
		case <-time.After(backoff):
		// continue loop!
		case <-ctx.Done():
			log.Debug("context canceled. Exiting")
			return nil
		}
		backoff = min(backoff*2, retryMaxInterval)
	}
}

func dedupeKeys(entries []Entry) []Entry {
	keyPos := map[attr.Name]int{}
	out := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if pos, ok := keyPos[entry.Key]; ok {
			out[pos] = entry
		} else {
			out = append(out, entry)
			keyPos[entry.Key] = len(out) - 1
		}
	}
	return out
}
