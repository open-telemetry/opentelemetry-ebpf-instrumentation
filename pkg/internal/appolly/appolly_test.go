// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/docker"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestProcessEventsLoopDoesntBlock(t *testing.T) {
	instr, err := New(
		t.Context(),
		&global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		&obi.Config{
			ChannelBufferLen: 1,
			Traces: otelcfg.TracesConfig{
				TracesEndpoint: "http://something",
			},
		},
	)

	events := make(chan discover.Event[*ebpf.Instrumentable])

	go instr.instrumentedEventLoop(t.Context(), events)

	for i := range app.PID(100) {
		events <- discover.Event[*ebpf.Instrumentable]{
			Obj:  &ebpf.Instrumentable{FileInfo: exec.New(exec.Init{Pid: i})},
			Type: discover.EventCreated,
		}
	}

	assert.NoError(t, err)
}

func TestHandleProcessEventDrainsOnlyTerminatingWorkerFinal(t *testing.T) {
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(2))
	events := processEvents.Subscribe()
	instrumenter := &Instrumenter{processEventInput: processEvents}
	parent := exec.New(exec.Init{Pid: 100})
	first := exec.New(exec.Init{Pid: 101})
	first.SetRuntimeMetricServiceSource(parent)
	second := exec.New(exec.Init{Pid: 102})
	second.SetRuntimeMetricServiceSource(parent)
	parent.SetPythonRuntimeMetricFinal(appruntime.PythonRuntimeMetricFinal{PID: 101, Generation: 1})
	parent.SetPythonRuntimeMetricFinal(appruntime.PythonRuntimeMetricFinal{PID: 102, Generation: 2})

	instrumenter.handleAndDispatchProcessEvent(exec.ProcessEvent{
		Type: exec.ProcessEventTerminated,
		File: first,
	})

	event := <-events
	require.Len(t, event.FinalPythonRuntimeMetrics, 1)
	assert.Equal(t, app.PID(101), event.FinalPythonRuntimeMetrics[0].PID)
	remaining, ok := parent.TakePythonRuntimeMetricFinal(102)
	require.True(t, ok)
	assert.Equal(t, uint64(2), remaining.Generation)
}

// TestInstrumenter_WithDynamicPIDSelector verifies that when the caller passes a selector via
// ContextInfo.DynamicPIDSelector, New uses it and the caller can add/remove PIDs on it directly.
func TestInstrumenter_WithDynamicPIDSelector(t *testing.T) {
	sel := discover.NewDynamicPIDSelector()
	ctxInfo := &global.ContextInfo{
		Prometheus:         &connector.PrometheusManager{},
		DynamicPIDSelector: sel,
	}
	_, err := New(
		t.Context(),
		ctxInfo,
		&obi.Config{ChannelBufferLen: 1, Traces: otelcfg.TracesConfig{TracesEndpoint: "http://localhost"}},
	)
	require.NoError(t, err)

	sel.AddPIDs(1, 2, 3)
	sel.AddPIDs(2, 4)
	sel.RemovePIDs(2)
	sel.RemovePIDs(99)
	pids, ok := sel.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 3, 4}, pids)
}

// TestSetupKubernetes_DockerFallback verifies that when Kubernetes looks enabled but its
// informer cache can't be initialized, setupKubernetes force-disables Kubernetes AND starts
// the Docker event watcher, so container metadata isn't cached without die/destroy invalidation.
func TestSetupKubernetes_DockerFallback(t *testing.T) {
	ctxInfo := &global.ContextInfo{
		K8sInformer: kube.NewMetadataProvider(kube.MetadataConfig{
			Enable:         kubeflags.EnabledTrue,
			KubeConfigPath: filepath.Join(t.TempDir(), "does-not-exist"),
		}, imetrics.NoopReporter{}),
		DockerMetadata: docker.NewStore(),
	}
	require.True(t, ctxInfo.K8sInformer.IsKubeEnabled())
	require.False(t, ctxInfo.DockerMetadata.WatcherRunning())

	setupKubernetes(t.Context(), ctxInfo)

	assert.False(t, ctxInfo.K8sInformer.IsKubeEnabled(),
		"Kubernetes should be force-disabled once its informer cache fails to initialize")
	assert.True(t, ctxInfo.DockerMetadata.WatcherRunning(),
		"Docker event watcher should start as a fallback once Kubernetes setup fails")
}
