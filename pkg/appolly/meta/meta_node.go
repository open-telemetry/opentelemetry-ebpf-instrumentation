// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"iter"
	"log/slog"
	"slices"
	"sync"
	"time"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/helpers/iters"
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
type fetcher func(ctx context.Context) (iter.Seq2[attr.Name, string], error)

type NodeStore struct {
	entries []Entry
}

type Entry struct {
	Key   attr.Name
	Value string
}

func NewNodeStore(
	ctx context.Context,
	fetchers ...fetcher,
) *NodeStore {
	return &NodeStore{
		entries: fetchEntries(ctx, fetchers...),
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
	results := make([]iter.Seq2[attr.Name, string], len(fetchers))
	for i, fetch := range fetchers {
		wg.Go(func() {
			results[i] = backoffFetch(ctx, fetch, log.With("fetcher", i))
		})
	}
	wg.Wait()

	jointResults := iters.Concat2(results...)
	resultsAsEntry := iters.Map2Seq(jointResults,
		func(k attr.Name, v string) Entry { return Entry{Key: k, Value: v} })
	return slices.Collect(resultsAsEntry)
}

func backoffFetch(ctx context.Context, fetch fetcher, log *slog.Logger) iter.Seq2[attr.Name, string] {
	backoff := retryStartInterval
	start := time.Now()
	for {
		seq, err := fetch(ctx)
		if err == nil {
			return seq
		}
		// exponential backoff retry strategy
		if time.Since(start) > retryTimeout {
			log.Warn("timeout reached while looking for metadata. Giving up", "error", err)
			return iters.Empty2[attr.Name, string]()
		}
		log.Debug("can't fetch metadata. Will retry",
			"retryAfter", backoff, "error", err)
		select {
		case <-time.After(backoff):
		// continue loop!
		case <-ctx.Done():
			log.Debug("context canceled. Exiting")
			return iters.Empty2[attr.Name, string]()
		}
		backoff = min(backoff*2, retryMaxInterval)
	}
}

func (sg *NodeStore) Get() iter.Seq[Entry] {
	return slices.Values(sg.entries)
}
