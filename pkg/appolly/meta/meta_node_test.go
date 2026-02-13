// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestFetchEntries_RetryAndKeepOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Create fetchers that fail different numbers of times before succeeding
		failOnce := makeFetcherThatFailsNTimes(1, "fetcher1", "value1")
		alwaysFails := func(_ context.Context) (NodeStore, error) {
			return NodeStore{}, errors.New("permanent failure")
		}
		failTwice := makeFetcherThatFailsNTimes(2, "fetcher2", "value2")
		succeedImmediately := makeFetcherThatFailsNTimes(0, "fetcher3", "value3")

		entries := fetchEntries(t.Context(), failOnce, alwaysFails, failTwice, succeedImmediately)

		// All fetchers should eventually succeed and return their data
		require.Equal(t, NodeStore{
			HostID: "host_fetcher3",
			Metadata: []Entry{
				{Key: "fetcher1_1", Value: "value1_1"},
				{Key: "fetcher1_2", Value: "value1_2"},
				{Key: "fetcher2_1", Value: "value2_1"},
				{Key: "fetcher2_2", Value: "value2_2"},
				{Key: "fetcher3_1", Value: "value3_1"},
				{Key: "fetcher3_2", Value: "value3_2"},
			},
		}, entries)
		synctest.Wait()
	})
}

func TestFetchEntries_DeduplicateByPriority(t *testing.T) {
	entries := fetchEntries(t.Context(),
		// lowest-priority fetcher
		func(_ context.Context) (NodeStore, error) {
			return NodeStore{
				HostID: "should-be-overridden",
				Metadata: []Entry{
					{Key: "some.local.stuff", Value: "something"},
					{Key: "cloud.stuff", Value: "should-be-overridden"},
					{Key: "host.name", Value: "foo-hostname"},
				},
			}, nil
		},
		// highest-priority fetcher
		func(_ context.Context) (NodeStore, error) {
			return NodeStore{
				HostID: "vm-01234567",
				Metadata: []Entry{
					{Key: "foo", Value: "bar"},
					{Key: "cloud.stuff", Value: "the-cloud-stuff"},
					{Key: "baz", Value: "bae"},
				},
			}, nil
		},
	)
	assert.Equal(t, NodeStore{
		HostID: "vm-01234567",
		Metadata: []Entry{
			{Key: "baz", Value: "bae"},
			{Key: "cloud.stuff", Value: "the-cloud-stuff"},
			{Key: "foo", Value: "bar"},
			{Key: "host.name", Value: "foo-hostname"},
			{Key: "some.local.stuff", Value: "something"},
		},
	}, entries)
}

func makeFetcherThatFailsNTimes(failCount int, key, value string) fetcher {
	attempts := atomic.Int32{}
	return func(_ context.Context) (NodeStore, error) {
		attempt := attempts.Add(1)
		if attempt <= int32(failCount) {
			return NodeStore{}, errors.New("simulated failure")
		}
		return NodeStore{
			HostID: "host_" + key,
			Metadata: []Entry{
				{Key: attr.Name(key + "_1"), Value: value + "_1"},
				{Key: attr.Name(key + "_2"), Value: value + "_2"},
			},
		}, nil
	}
}
