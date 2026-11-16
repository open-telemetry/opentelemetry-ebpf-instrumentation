// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/cloud"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type azureProcessInventory struct {
	mu              sync.Mutex
	name            string
	containerName   string
	err             error
	failedRefreshes int
}

func (*azureProcessInventory) Name() string { return "azure" }
func (r *azureProcessInventory) Refresh(_ context.Context, s *cloud.MetadataSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		r.failedRefreshes++
		return r.err
	}
	if r.name != "" {
		s.ServiceByInstanceID["azure:sub:vm-uuid"] = r.name
		s.ServiceByIP["10.0.0.2"] = r.name
	}
	if r.containerName != "" {
		s.ServiceByContainerID["container"] = r.containerName
	}
	return nil
}

func (r *azureProcessInventory) set(name, containerName string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.name = name
	r.containerName = containerName
	r.err = err
	r.failedRefreshes = 0
}

func TestAzureProcessIdentityLifecycle(t *testing.T) {
	refresher := &azureProcessInventory{err: errors.New("temporarily denied")}
	waitForFailedRefresh := func() {
		t.Helper()
		require.Eventually(t, func() bool {
			refresher.mu.Lock()
			defer refresher.mu.Unlock()
			// A second attempt means the inventory has handled the first failure.
			return refresher.failedRefreshes >= 2
		}, time.Second, time.Millisecond)
	}
	inventory := cloud.NewInventory([]cloud.MetadataRefresher{refresher})
	input := make(chan exec.ProcessEvent)
	output := msg.NewQueue[exec.ProcessEvent]()
	result := output.Subscribe(msg.SubscriberName("azure-test"))
	node := azureTestNode()
	instanceID := localAzureInstanceID(&node, &NameResolverConfig{Sources: []Source{SourceAzure}})
	d := cloudProcessDecorator{instanceID: instanceID, inventory: inventory, changes: inventory.SubscribeContainerChanges(), input: input, output: output, containerInfo: func(app.PID) (container.Info, error) { return container.Info{}, container.ErrContainerNotFound }}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	checkTargetInfo := ecsTargetInfoExporters(ctx, t, output, "azure-instance")
	done := make(chan struct{})
	go func() { defer close(done); d.run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("decorator did not stop")
		}
	})
	read := func() exec.ProcessEvent {
		t.Helper()
		select {
		case event := <-result:
			return event
		case <-time.After(5 * time.Second):
			t.Fatal("missing process update")
			return exec.ProcessEvent{}
		}
	}
	service := svc.Attrs{UID: svc.UID{Name: "executable", Namespace: "ns", Instance: "azure-instance"}, Features: export.FeatureApplicationRED}
	service.SetAutoName()
	file := exec.New(exec.Init{Pid: 1, Service: service})
	input <- exec.ProcessEvent{File: file, Type: exec.ProcessEventCreated}
	read()
	require.Equal(t, "executable", file.ServiceAttrs().UID.Name)
	startCloudInventory(t, inventory, 10*time.Millisecond)
	waitForFailedRefresh()
	refresher.set("checkout", "", nil)
	require.Same(t, file, read().File)
	require.Equal(t, "checkout", file.ServiceAttrs().UID.Name)
	checkTargetInfo("checkout", "executable")
	span := request.Span{Service: service}
	resolver := NameResolver{cloudInventory: inventory, instanceID: instanceID}
	resolver.resolveLocalCloudInventory(&span)
	require.Equal(t, "checkout", span.Service.UID.Name)

	// Explicit service identity remains authoritative while the VM mapping exists.
	span.Service = svc.Attrs{UID: svc.UID{Name: "configured"}}
	resolver.resolveLocalCloudInventory(&span)
	require.Equal(t, "configured", span.Service.UID.Name)

	// A container-specific mapping wins over the host's scale-set name.
	file.SetRuntimeContainerID("container")
	refresher.set("checkout", "container-service", nil)
	read()
	require.Equal(t, "container-service", file.ServiceAttrs().UID.Name)
	span.Service = service
	span.Service.RuntimeContainerID = "container"
	resolver.resolveLocalCloudInventory(&span)
	require.Equal(t, "container-service", span.Service.UID.Name)
	// Failed refreshes retain the last complete name; recovery publishes membership removal.
	refresher.set("", "", errors.New("denied"))
	waitForFailedRefresh()
	name, ok := inventory.ServiceNameForInstanceID(instanceID)
	require.True(t, ok)
	require.Equal(t, "checkout", name)
	require.Equal(t, "container-service", file.ServiceAttrs().UID.Name)
	refresher.set("", "", nil)
	read()
	require.Equal(t, "executable", file.ServiceAttrs().UID.Name)
	checkTargetInfo("executable", "checkout")
}
