// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

func TestMetadataProviderClosesBothNotifierLayers(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	upstream := meta.NewBaseNotifier(slog.Default())
	context.AfterFunc(ctx, upstream.Close)
	provider := NewMetadataProvider(MetadataConfig{}, imetrics.NoopReporter{})
	provider.informer = &upstream
	store, err := provider.Get(ctx)
	require.NoError(t, err)
	t.Cleanup(store.Close)

	observer := &dummySubscriber{}
	store.Subscribe(observer)
	event := &informer.Event{Type: informer.EventType_SYNC_FINISHED}
	require.True(t, upstream.NotifyObserver(store, event))
	require.True(t, store.NotifyObserver(observer, event))

	cancel()

	require.Eventually(t, func() bool {
		return !upstream.NotifyObserver(store, event) && !store.NotifyObserver(observer, event)
	}, time.Second, time.Millisecond)

	store.Subscribe(observer)
	require.False(t, store.NotifyObserver(observer, event))
}
