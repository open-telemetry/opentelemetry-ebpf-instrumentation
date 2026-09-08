// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const updaterTestTimeout, updaterTestPID = time.Second, app.PID(123)

func newUpdaterTestStore(t *testing.T, containerIDs ...string) *kube.Store {
	t.Helper()
	notifier := meta.NewBaseNotifier(slog.Default())
	store := kube.NewStore(&notifier, kube.DefaultResourceLabels, nil, imetrics.NoopReporter{})
	for _, containerID := range containerIDs {
		addUpdaterTestContainer(t, store, containerID)
	}
	return store
}

func addUpdaterTestContainer(t *testing.T, store *kube.Store, containerID string) {
	t.Helper()
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name: containerID,
			Pod:  &informer.PodInfo{Containers: []*informer.ContainerInfo{{Id: containerID}}},
		},
	}))
}

func updaterEvent(eventType WatchEventType, pid app.PID) []Event[ebpf.Instrumentable] {
	event := Event[ebpf.Instrumentable]{Type: eventType, Obj: ebpf.Instrumentable{FileInfo: exec.New(exec.Init{Pid: pid})}}
	return []Event[ebpf.Instrumentable]{event}
}

func hasPodForPID(store *kube.Store, namespace uint32) bool {
	pod, _ := store.PodContainerByPIDNs(namespace, updaterTestPID)
	return pod != nil
}

func receiveUpdater[T any](t *testing.T, ch <-chan T) (T, bool) {
	t.Helper()
	select {
	case value, ok := <-ch:
		return value, ok
	case <-time.After(updaterTestTimeout):
		t.Fatal("timed out waiting for container store updater")
		var zero T
		return zero, false
	}
}

func TestContainerStoreUpdaterOrdersStateAndOutput(t *testing.T) {
	bootstrapInfo := container.Info{ContainerID: "bootstrap-container", PIDNamespace: 5}
	oldInfo := container.Info{ContainerID: "old-container", PIDNamespace: 10}
	newInfo := container.Info{ContainerID: "new-container", PIDNamespace: 20}
	infos := make(chan container.Info, 4)
	originalInfoForPID := kube.InfoForPID
	kube.InfoForPID = func(app.PID) (container.Info, error) { return <-infos, nil }
	t.Cleanup(func() { kube.InfoForPID = originalInfoForPID })
	store := newUpdaterTestStore(t, bootstrapInfo.ContainerID, newInfo.ContainerID)
	assert.False(t, hasPodForPID(store, bootstrapInfo.PIDNamespace))

	in := make(chan []Event[ebpf.Instrumentable], 1)
	out := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(0))
	consumers := []<-chan []Event[ebpf.Instrumentable]{out.Subscribe(), out.Subscribe()}
	done := make(chan struct{})
	go func() {
		updateLoop(store, in, out)(t.Context())
		close(done)
	}()

	beginUpdate := func(info container.Info, eventType WatchEventType) {
		t.Helper()
		if eventType == EventCreated {
			infos <- info
		}
		in <- updaterEvent(eventType, updaterTestPID)
		receiveUpdater(t, consumers[0])
	}
	finishUpdate := func() {
		t.Helper()
		receiveUpdater(t, consumers[1])
	}

	beginUpdate(bootstrapInfo, EventCreated)
	assert.True(t, hasPodForPID(store, bootstrapInfo.PIDNamespace))
	finishUpdate()
	beginUpdate(oldInfo, EventCreated)
	assert.False(t, hasPodForPID(store, bootstrapInfo.PIDNamespace))
	finishUpdate()
	beginUpdate(newInfo, EventCreated)
	assert.True(t, hasPodForPID(store, newInfo.PIDNamespace))
	addUpdaterTestContainer(t, store, oldInfo.ContainerID)
	assert.False(t, hasPodForPID(store, oldInfo.PIDNamespace))
	finishUpdate()
	beginUpdate(newInfo, EventCreated)
	assert.True(t, hasPodForPID(store, newInfo.PIDNamespace))
	finishUpdate()
	beginUpdate(container.Info{}, EventDeleted)
	assert.False(t, hasPodForPID(store, newInfo.PIDNamespace))
	finishUpdate()
	close(in)
	receiveUpdater(t, done)
	for _, consumer := range consumers {
		_, ok := receiveUpdater(t, consumer)
		assert.False(t, ok, "output must close after all input is forwarded")
	}
}

func TestContainerStoreUpdaterShutdown(t *testing.T) {
	t.Run("without consumers", func(t *testing.T) {
		in := make(chan []Event[ebpf.Instrumentable], 1)
		out := msg.NewQueue[[]Event[ebpf.Instrumentable]]()
		in <- nil
		close(in)
		updateLoop(newUpdaterTestStore(t), in, out)(t.Context())
	})

	t.Run("cancellation releases slow consumer", func(t *testing.T) {
		const pid app.PID = 456
		infos := make(chan container.Info, 2)
		originalInfoForPID := kube.InfoForPID
		kube.InfoForPID = func(app.PID) (container.Info, error) { return <-infos, nil }
		t.Cleanup(func() { kube.InfoForPID = originalInfoForPID })

		in := make(chan []Event[ebpf.Instrumentable], 2)
		out := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(1))
		activeConsumer := out.Subscribe()
		slowConsumer := out.Subscribe()
		ctx, cancel := context.WithCancel(t.Context())
		store, done := newUpdaterTestStore(t), make(chan struct{})
		go func() {
			updateLoop(store, in, out)(ctx)
			close(done)
		}()

		for range 2 {
			infos <- container.Info{ContainerID: "container", PIDNamespace: 30}
			in <- updaterEvent(EventCreated, pid)
			receiveUpdater(t, activeConsumer)
		}
		cancel()
		receiveUpdater(t, done)
		receiveUpdater(t, slowConsumer)
		_, ok := receiveUpdater(t, slowConsumer)
		assert.False(t, ok, "blocked second delivery must be canceled")
	})
}
