// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/cloud"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type gceProcessRefresher struct {
	name string
}

func (*gceProcessRefresher) Name() string { return "gce-test" }
func (r *gceProcessRefresher) Refresh(_ context.Context, snapshot *cloud.MetadataSnapshot) error {
	if r.name != "" {
		snapshot.ServiceByInstanceID["123"] = r.name
	}
	return nil
}

func TestGCEProcessDecoratorUpdatesTargetInfo(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	refresher := &gceProcessRefresher{}
	inventory := cloud.NewInventory([]cloud.MetadataRefresher{refresher})
	input := make(chan exec.ProcessEvent)
	output := msg.NewQueue[exec.ProcessEvent]()
	events := output.Subscribe(msg.SubscriberName("test"))
	d := cloudProcessDecorator{
		inventory: inventory, instanceID: "123",
		changes: inventory.SubscribeContainerChanges(), input: input, output: output,
	}
	checkTargetInfo := ecsTargetInfoExporters(ctx, t, output)
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("GCE process decorator did not stop")
		}
	})
	read := func() exec.ProcessEvent {
		t.Helper()
		select {
		case event := <-events:
			return event
		case <-time.After(5 * time.Second):
			t.Fatal("GCE process decorator did not forward an event")
			return exec.ProcessEvent{}
		}
	}
	send := func(event exec.ProcessEvent) {
		t.Helper()
		select {
		case input <- event:
		case <-time.After(5 * time.Second):
			t.Fatal("GCE process decorator did not accept an event")
		}
		read()
	}
	refresh := func(name string) {
		t.Helper()
		refresher.name = name
		// The node's initialization refresh lets this test control each update.
		_, err := cloud.InventoryRefresherNode(inventory, time.Hour)(ctx)
		require.NoError(t, err)
	}
	service := svc.Attrs{UID: svc.UID{Name: "process-name", Instance: "process-1"}}
	service.Features = export.FeatureApplicationRED
	service.SetAutoName()
	file := exec.New(exec.Init{Pid: 1, Service: service})
	send(exec.ProcessEvent{File: file, Type: exec.ProcessEventCreated})
	checkTargetInfo("process-name", "storefront")

	refresh("storefront")
	assert.Same(t, file, read().File)
	assert.Equal(t, "storefront", file.ServiceAttrs().UID.Name)
	assert.Empty(t, file.ServiceAttrs().RuntimeContainerID, "VM identity must not become a container ID")
	checkTargetInfo("storefront", "process-name")

	explicitService := svc.Attrs{UID: svc.UID{Name: "configured", Instance: "process-2"}}
	explicitService.Features = export.FeatureApplicationRED
	explicit := exec.New(exec.Init{Pid: 2, Service: explicitService})
	send(exec.ProcessEvent{File: explicit, Type: exec.ProcessEventCreated})
	assert.Equal(t, "configured", explicit.ServiceAttrs().UID.Name)

	refresh("")
	assert.Same(t, file, read().File)
	assert.Equal(t, "process-name", file.ServiceAttrs().UID.Name)
	checkTargetInfo("process-name", "storefront")

	send(exec.ProcessEvent{File: file, Type: exec.ProcessEventTerminated})
	refresh("replacement")
	// This event is a barrier through the same decorator loop.
	send(exec.ProcessEvent{File: explicit, Type: exec.ProcessEventCreated})
	close(input)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("GCE process decorator did not stop after input closure")
	}
	assert.NotContains(t, d.processes, app.PID(1))
	assert.Equal(t, "process-name", file.ServiceAttrs().UID.Name)
	assert.Equal(t, "configured", explicit.ServiceAttrs().UID.Name)
}
