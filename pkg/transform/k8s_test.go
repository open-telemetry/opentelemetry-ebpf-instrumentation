// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	isync "go.opentelemetry.io/obi/pkg/internal/helpers/sync"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const timeout = 5 * time.Second

func TestDecoration(t *testing.T) {
	originalInfoForPID := kube.InfoForPID
	t.Cleanup(func() {
		kube.InfoForPID = originalInfoForPID
	})

	inf := &fakeInformer{}
	store := kube.NewStore(inf, kube.ResourceLabels{
		"service.name":      []string{"app.kubernetes.io/name"},
		"service.namespace": []string{"app.kubernetes.io/part-of"},
	}, nil, imetrics.NoopReporter{})
	// pre-populated kubernetes metadata database
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "pod-12", Namespace: "the-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:12:56",
			Uid:          "uid-12",
			Owners:       []*informer.Owner{{Kind: "Deployment", Name: "deployment-12"}},
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-12"}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "pod-34", Namespace: "the-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:34:56",
			Uid:          "uid-34",
			Owners:       []*informer.Owner{{Kind: "ReplicaSet", Name: "rs"}},
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-34"}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "the-pod", Namespace: "the-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-56",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-56"}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "overridden-meta", Namespace: "the-ns", Kind: "Pod",
		Labels: map[string]string{
			"app.kubernetes.io/name":    "a-cool-name",
			"app.kubernetes.io/part-of": "a-cool-namespace",
		},
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-78",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-78"}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "overridden-meta-annots", Namespace: "the-ns", Kind: "Pod",
		Annotations: map[string]string{
			"resource.opentelemetry.io/service.name":      "otel-override-name",
			"resource.opentelemetry.io/service.namespace": "otel-override-ns",
		},
		Labels: map[string]string{
			"app.kubernetes.io/name":    "a-cool-name",
			"app.kubernetes.io/part-of": "a-cool-namespace",
		},
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-33",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-33"}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "env-var-takes-precedence", Namespace: "the-ns", Kind: "Pod",
		Annotations: map[string]string{
			"resource.opentelemetry.io/service.name":      "otel-override-name",
			"resource.opentelemetry.io/service.namespace": "otel-override-ns",
		},
		Labels: map[string]string{
			"app.kubernetes.io/name":    "a-cool-name",
			"app.kubernetes.io/part-of": "a-cool-namespace",
		},
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-66",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers: []*informer.ContainerInfo{{
				Name: "a-container", Id: "container-66",
				Env: map[string]string{
					"OTEL_RESOURCE_ATTRIBUTES": "service.name=env-svc-name,service.namespace=env-svc-ns",
				},
			}},
		},
	}})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "env-var-takes-precedence-but-not-unresolved", Namespace: "the-ns", Kind: "Pod",
		Annotations: map[string]string{
			"resource.opentelemetry.io/service.name":      "otel-override-name",
			"resource.opentelemetry.io/service.namespace": "otel-override-ns",
		},
		Labels: map[string]string{
			"app.kubernetes.io/name":    "a-cool-name",
			"app.kubernetes.io/part-of": "a-cool-namespace",
		},
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-67",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers: []*informer.ContainerInfo{{
				Name: "a-container", Id: "container-67",
				Env: map[string]string{
					"OTEL_RESOURCE_ATTRIBUTES": "service.name=$(env-svc-name-second-time),service.namespace=env-svc-ns-second-time",
				},
			}},
		},
	}})
	// we need to add PID metadata for all the pod/containers above
	// by convention, the mocked pid namespace will be PID+1000
	kube.InfoForPID = func(pid app.PID) (container.Info, error) {
		return container.Info{
			ContainerID:  fmt.Sprintf("container-%d", pid),
			PIDNamespace: 1000 + uint32(pid),
		}, nil
	}
	for _, pid := range []app.PID{12, 34, 56, 78, 33, 66, 67} {
		store.AddProcess(pid)
	}
	inputQueue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	dec := metadataDecorator{
		store: store, clusterName: "the-cluster",
		input:  inputQueue.Subscribe(),
		output: msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10)),
	}
	outputCh := dec.output.Subscribe()
	defer inputQueue.Close()
	go dec.nodeLoop(t.Context())

	autoNameSvc := svc.Attrs{}
	autoNameSvc.SetAutoName()

	t.Run("complete pod info should set deployment as name", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1012}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "the-ns", deco[0].Service.UID.Namespace)
		assert.Equal(t, "deployment-12", deco[0].Service.UID.Name)
		assert.Equal(t, "the-ns.pod-12.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.pod.name":        "pod-12",
			"k8s.container.name":  "a-container",
			"k8s.pod.uid":         "uid-12",
			"k8s.deployment.name": "deployment-12",
			"k8s.owner.name":      "deployment-12",
			"k8s.pod.start_time":  "2020-01-02 12:12:56",
			"k8s.cluster.name":    "the-cluster",
			"k8s.kind":            "Deployment",
		}, deco[0].Service.Metadata)
	})
	t.Run("pod info whose replicaset did not have an Owner should set the replicaSet name", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1034}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "the-ns", deco[0].Service.UID.Namespace)
		assert.Equal(t, "rs", deco[0].Service.UID.Name)
		assert.Equal(t, "the-ns.pod-34.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.replicaset.name": "rs",
			"k8s.owner.name":      "rs",
			"k8s.pod.name":        "pod-34",
			"k8s.container.name":  "a-container",
			"k8s.pod.uid":         "uid-34",
			"k8s.pod.start_time":  "2020-01-02 12:34:56",
			"k8s.cluster.name":    "the-cluster",
			"k8s.kind":            "ReplicaSet",
		}, deco[0].Service.Metadata)
	})
	t.Run("pod info with only pod name should set pod name as name", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1056}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "the-ns", deco[0].Service.UID.Namespace)
		assert.Equal(t, "the-pod", deco[0].Service.UID.Name)
		assert.Equal(t, "the-ns.the-pod.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "the-pod",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-56",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
		}, deco[0].Service.Metadata)
	})
	t.Run("user can override service name and ns via labels", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1078}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "a-cool-namespace", deco[0].Service.UID.Namespace)
		assert.Equal(t, "a-cool-name", deco[0].Service.UID.Name)
		assert.Equal(t, "the-ns.overridden-meta.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "overridden-meta",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-78",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
			"service.name":       "a-cool-name",
			"service.namespace":  "a-cool-namespace",
		}, deco[0].Service.Metadata)
	})
	t.Run("user can override service name and ns via annotations", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1033}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "otel-override-ns", deco[0].Service.UID.Namespace)
		assert.Equal(t, "otel-override-name", deco[0].Service.UID.Name)
		assert.Equal(t, "the-ns.overridden-meta-annots.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "overridden-meta-annots",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-33",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
			"service.name":       "otel-override-name",
			"service.namespace":  "otel-override-ns",
		}, deco[0].Service.Metadata)
	})
	t.Run("user can override service name and ns via env vars, taking precedence over any other criteria", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1066}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "env-svc-ns", deco[0].Service.UID.Namespace)
		assert.Equal(t, "env-svc-name", deco[0].Service.UID.Name)
		assert.Equal(t, "the-ns.env-var-takes-precedence.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "env-var-takes-precedence",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-66",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
			"service.name":       "env-svc-name",
			"service.namespace":  "env-svc-ns",
		}, deco[0].Service.Metadata)
	})
	t.Run("user can override service name and ns via env vars, taking precedence over any other criteria, but not if the vars are unresolved", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1067}, Service: autoNameSvc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "env-svc-ns-second-time", deco[0].Service.UID.Namespace)
		assert.Equal(t, "otel-override-name", deco[0].Service.UID.Name)
		assert.Equal(t, "the-ns.env-var-takes-precedence-but-not-unresolved.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "env-var-takes-precedence-but-not-unresolved",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-67",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
			"service.name":       "otel-override-name",
			"service.namespace":  "env-svc-ns-second-time",
		}, deco[0].Service.Metadata)
	})
	t.Run("process without pod Info won't be decorated", func(t *testing.T) {
		svc := svc.Attrs{UID: svc.UID{Name: "exec"}}
		svc.SetAutoName()
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1099}, Service: svc,
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Empty(t, deco[0].Service.UID.Namespace)
		assert.Equal(t, "exec", deco[0].Service.UID.Name)
		assert.Empty(t, deco[0].Service.Metadata)
	})
	t.Run("if service name or namespace are manually specified, don't override them", func(t *testing.T) {
		inputQueue.Send([]request.Span{{
			Pid: request.PidInfo{Namespace: 1012}, Service: svc.Attrs{UID: svc.UID{Name: "tralari", Namespace: "tralara"}},
		}})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		require.Len(t, deco, 1)
		assert.Equal(t, "tralara", deco[0].Service.UID.Namespace)
		assert.Equal(t, "tralari", deco[0].Service.UID.Name)
		assert.Equal(t, "the-ns.pod-12.a-container", deco[0].Service.UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.pod.name":        "pod-12",
			"k8s.container.name":  "a-container",
			"k8s.pod.uid":         "uid-12",
			"k8s.deployment.name": "deployment-12",
			"k8s.owner.name":      "deployment-12",
			"k8s.pod.start_time":  "2020-01-02 12:12:56",
			"k8s.cluster.name":    "the-cluster",
			"k8s.kind":            "Deployment",
		}, deco[0].Service.Metadata)
	})
}

func TestDecorationProcessEvents(t *testing.T) {
	originalInfoForPID := kube.InfoForPID
	originalContainerInfoForPID := containerInfoForPID
	t.Cleanup(func() {
		kube.InfoForPID = originalInfoForPID
		containerInfoForPID = originalContainerInfoForPID
	})

	inf := &fakeInformer{}
	store := kube.NewStore(inf, kube.ResourceLabels{
		"service.name":      []string{"app.kubernetes.io/name"},
		"service.namespace": []string{"app.kubernetes.io/part-of"},
	}, nil, imetrics.NoopReporter{})
	// add one container, the others will be delayed
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "pod-12", Namespace: "the-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:12:56",
			Uid:          "uid-12",
			Owners:       []*informer.Owner{{Kind: "Deployment", Name: "deployment-12"}},
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-12"}},
		},
	}})

	// we need to add PID metadata for all the pod/containers above
	// by convention, the mocked pid namespace will be PID+1000
	kube.InfoForPID = func(pid app.PID) (container.Info, error) {
		if pid < 56 {
			return container.Info{
				ContainerID:  fmt.Sprintf("container-%d", pid),
				PIDNamespace: 1000 + uint32(pid),
			}, nil
		}

		// the other pids all sit in the same container
		return container.Info{
			ContainerID:  "container-56",
			PIDNamespace: 1056,
		}, nil
	}

	containerInfoForPID = kube.InfoForPID

	for _, pid := range []app.PID{12, 34, 56, 78, 83, 66} {
		store.AddProcess(pid)
	}
	inputQueue := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10))

	dec := &procEventMetadataDecorator{
		log:                 slog.With("component", "transform.KubeProcessEventDecoratorProvider"),
		store:               store,
		clusterName:         "the-cluster",
		input:               inputQueue.Subscribe(msg.SubscriberName("transform.KubeProcessEventDecorator")),
		output:              msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10)),
		podEvents:           isync.NewQueue[Event[*informer.ObjectMeta]](),
		podEventsReady:      make(chan struct{}, 1),
		observerDone:        make(chan struct{}),
		subscribeObserver:   store.Subscribe,
		unsubscribeObserver: store.Unsubscribe,
		tracker:             newPidContainerTracker(),
	}

	outputCh := dec.output.Subscribe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		dec.k8sLoop(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		inputQueue.Close()
		waitForLoop(t, done)
	})

	autoNameSvc := svc.Attrs{}
	autoNameSvc.SetAutoName()

	t.Run("complete pod info should set deployment as name", func(t *testing.T) {
		inputQueue.Send(exec.ProcessEvent{File: exec.New(exec.Init{Pid: 12, Ns: 1012, Service: autoNameSvc}), Type: exec.ProcessEventCreated})
		deco := testutil.ReadChannel(t, outputCh, timeout)
		assert.Equal(t, "the-ns", deco.File.ServiceAttrs().UID.Namespace)
		assert.Equal(t, "deployment-12", deco.File.ServiceAttrs().UID.Name)
		assert.Equal(t, "the-ns.pod-12.a-container", deco.File.ServiceAttrs().UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":       "the-node",
			"k8s.namespace.name":  "the-ns",
			"k8s.pod.name":        "pod-12",
			"k8s.container.name":  "a-container",
			"k8s.pod.uid":         "uid-12",
			"k8s.deployment.name": "deployment-12",
			"k8s.owner.name":      "deployment-12",
			"k8s.pod.start_time":  "2020-01-02 12:12:56",
			"k8s.cluster.name":    "the-cluster",
			"k8s.kind":            "Deployment",
		}, deco.File.ServiceAttrs().Metadata)
	})

	// When we send 34 we first get naked PID info, the kubernetes metadata was delayed
	autoPackageSvc := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "acme"}}
	autoPackageSvc.SetAutoName()
	autoPackageSvc.SetAutoNamespace()
	inputQueue.Send(exec.ProcessEvent{File: exec.New(exec.Init{Pid: 34, Ns: 1034, Service: autoPackageSvc}), Type: exec.ProcessEventCreated})
	deco := testutil.ReadChannel(t, outputCh, timeout)
	assert.Equal(t, "acme", deco.File.ServiceAttrs().UID.Namespace)
	assert.Equal(t, "orders", deco.File.ServiceAttrs().UID.Name)
	assert.Empty(t, deco.File.ServiceAttrs().UID.Instance)
	assert.Empty(t, deco.File.ServiceAttrs().Metadata)

	// we now notify on new informer
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "pod-34", Namespace: "the-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			StartTimeStr: "2020-01-02 12:34:56",
			Uid:          "uid-34",
			Owners:       []*informer.Owner{{Kind: "ReplicaSet", Name: "rs"}},
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-34"}},
		},
	}})

	// After we got new information, there's no need to send the event again, it's
	// automatically going to generate a process event with the updated info
	// inputQueue.Send(exec.ProcessEvent{File: exec.New(exec.Init{Pid: 34, Ns: 1034, Service: autoNameSvc}), Type: exec.ProcessEventCreated})
	deco = testutil.ReadChannel(t, outputCh, timeout)
	assert.Equal(t, "the-ns", deco.File.ServiceAttrs().UID.Namespace)
	assert.Equal(t, "rs", deco.File.ServiceAttrs().UID.Name)
	assert.Equal(t, "the-ns.pod-34.a-container", deco.File.ServiceAttrs().UID.Instance)
	assert.Equal(t, map[attr.Name]string{
		"k8s.node.name":       "the-node",
		"k8s.namespace.name":  "the-ns",
		"k8s.replicaset.name": "rs",
		"k8s.owner.name":      "rs",
		"k8s.pod.name":        "pod-34",
		"k8s.container.name":  "a-container",
		"k8s.pod.uid":         "uid-34",
		"k8s.pod.start_time":  "2020-01-02 12:34:56",
		"k8s.cluster.name":    "the-cluster",
		"k8s.kind":            "ReplicaSet",
	}, deco.File.ServiceAttrs().Metadata)

	// Now let's send the rest of the PIDs. We'll send all and remove half
	// 56, 78, 83, 66
	// They all have the same namespace -- they are in the same container
	inputQueue.Send(exec.ProcessEvent{File: exec.New(exec.Init{Pid: 56, Ns: 1056, Service: autoNameSvc}), Type: exec.ProcessEventCreated})
	inputQueue.Send(exec.ProcessEvent{File: exec.New(exec.Init{Pid: 78, Ns: 1056, Service: autoNameSvc}), Type: exec.ProcessEventCreated})
	inputQueue.Send(exec.ProcessEvent{File: exec.New(exec.Init{Pid: 83, Ns: 1056, Service: autoNameSvc}), Type: exec.ProcessEventCreated})
	inputQueue.Send(exec.ProcessEvent{File: exec.New(exec.Init{Pid: 66, Ns: 1056, Service: autoNameSvc}), Type: exec.ProcessEventCreated})

	// remove two
	inputQueue.Send(exec.ProcessEvent{File: exec.New(exec.Init{Pid: 56, Ns: 1056, Service: autoNameSvc}), Type: exec.ProcessEventTerminated})
	inputQueue.Send(exec.ProcessEvent{File: exec.New(exec.Init{Pid: 78, Ns: 1056, Service: autoNameSvc}), Type: exec.ProcessEventTerminated})

	// this produces 6 events exactly
	// all without metadata
	for range 4 {
		deco := testutil.ReadChannel(t, outputCh, timeout)
		assert.Equal(t, exec.ProcessEventCreated, deco.Type)
		assert.Empty(t, deco.File.ServiceAttrs().UID.Namespace)
		assert.Empty(t, deco.File.ServiceAttrs().UID.Name)
		assert.Empty(t, deco.File.ServiceAttrs().UID.Instance)
		assert.Empty(t, deco.File.ServiceAttrs().Metadata)
	}

	for range 2 {
		deco := testutil.ReadChannel(t, outputCh, timeout)
		assert.Equal(t, exec.ProcessEventTerminated, deco.Type)
		assert.Empty(t, deco.File.ServiceAttrs().UID.Namespace)
		assert.Empty(t, deco.File.ServiceAttrs().UID.Name)
		assert.Empty(t, deco.File.ServiceAttrs().UID.Instance)
		assert.Empty(t, deco.File.ServiceAttrs().Metadata)
	}

	// Now we'll receive pod information for 56, this is the container where all the pids are
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "the-pod", Namespace: "the-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-56",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-56"}},
		},
	}})
	// dummy pod launch, we don't care about it, but we want to ensure it doesn't mess up
	// things for us
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "overridden-meta", Namespace: "the-ns", Kind: "Pod",
		Labels: map[string]string{
			"app.kubernetes.io/name":    "a-cool-name",
			"app.kubernetes.io/part-of": "a-cool-namespace",
		},
		Pod: &informer.PodInfo{
			NodeName:     "the-node",
			Uid:          "uid-78",
			StartTimeStr: "2020-01-02 12:56:56",
			Containers:   []*informer.ContainerInfo{{Name: "a-container", Id: "container-78"}},
		},
	}})

	// we'll receive only two process events, two of the 4 naked pids were deleted
	// so no event will be generated for those

	seenPids := map[app.PID]struct{}{}
	for _, deco := range []exec.ProcessEvent{testutil.ReadChannel(t, outputCh, timeout), testutil.ReadChannel(t, outputCh, timeout)} {
		seenPids[deco.File.Pid()] = struct{}{}
		assert.Equal(t, "the-ns", deco.File.ServiceAttrs().UID.Namespace)
		assert.Equal(t, "the-pod", deco.File.ServiceAttrs().UID.Name)
		assert.Equal(t, "the-ns.the-pod.a-container", deco.File.ServiceAttrs().UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "the-pod",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-56",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
		}, deco.File.ServiceAttrs().Metadata)

		assert.Equal(t, "the-ns", deco.File.ServiceAttrs().UID.Namespace)
		assert.Equal(t, "the-pod", deco.File.ServiceAttrs().UID.Name)
		assert.Equal(t, "the-ns.the-pod.a-container", deco.File.ServiceAttrs().UID.Instance)
		assert.Equal(t, map[attr.Name]string{
			"k8s.node.name":      "the-node",
			"k8s.namespace.name": "the-ns",
			"k8s.pod.name":       "the-pod",
			"k8s.container.name": "a-container",
			"k8s.pod.uid":        "uid-56",
			"k8s.pod.start_time": "2020-01-02 12:56:56",
			"k8s.cluster.name":   "the-cluster",
		}, deco.File.ServiceAttrs().Metadata)
	}

	assert.Len(t, seenPids, 2)
	_, exists := seenPids[66]
	assert.True(t, exists)
	_, exists = seenPids[83]
	assert.True(t, exists)

	// no more events
	testutil.ChannelEmpty(t, outputCh, 100*time.Millisecond)
}

type procEventDecoratorHarness struct {
	decorator   *procEventMetadataDecorator
	store       *kube.Store
	input       chan exec.ProcessEvent
	output      <-chan exec.ProcessEvent
	outputQueue *msg.Queue[exec.ProcessEvent]
	cancel      context.CancelFunc
	loopDone    <-chan struct{}
}

func newProcEventDecoratorHarness(t *testing.T) *procEventDecoratorHarness {
	t.Helper()

	originalInfoForPID := kube.InfoForPID
	kube.InfoForPID = func(pid app.PID) (container.Info, error) {
		return container.Info{
			ContainerID:  fmt.Sprintf("container-%d", pid),
			PIDNamespace: 1000 + uint32(pid),
		}, nil
	}
	t.Cleanup(func() {
		kube.InfoForPID = originalInfoForPID
	})

	notifier := meta.NewBaseNotifier(slog.Default())
	store := kube.NewStore(&notifier, nil, nil, imetrics.NoopReporter{})
	input := make(chan exec.ProcessEvent)
	output := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10))
	decorator := &procEventMetadataDecorator{
		log:                 slog.With("component", "transform.KubeProcessEventDecoratorProvider"),
		store:               store,
		clusterName:         "the-cluster",
		input:               input,
		output:              output,
		podEvents:           isync.NewQueue[Event[*informer.ObjectMeta]](),
		podEventsReady:      make(chan struct{}, 1),
		observerDone:        make(chan struct{}),
		subscribeObserver:   store.Subscribe,
		unsubscribeObserver: store.Unsubscribe,
		tracker:             newPidContainerTracker(),
	}
	harness := &procEventDecoratorHarness{
		decorator:   decorator,
		store:       store,
		input:       input,
		output:      output.Subscribe(),
		outputQueue: output,
	}
	t.Cleanup(func() {
		if harness.cancel != nil {
			harness.cancel()
		}
		if harness.loopDone != nil {
			select {
			case <-harness.loopDone:
			case <-time.After(timeout):
				t.Errorf("kubernetes process event decoration loop leaked")
			}
		}
		harness.outputQueue.Close()
		store.Unsubscribe(decorator)
	})

	return harness
}

func (h *procEventDecoratorHarness) addTrackedPod(t *testing.T, pid app.PID, name string) {
	t.Helper()

	h.store.AddProcess(pid)
	processEvent := procEventDecoratorProcessEvent(pid)
	h.decorator.tracker.track(fmt.Sprintf("container-%d", pid), &processEvent)
	require.NoError(t, h.store.On(procEventDecoratorPodEvent(name, pid)))
}

func (h *procEventDecoratorHarness) start(t *testing.T) (context.CancelFunc, <-chan struct{}) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	h.cancel = cancel
	h.loopDone = done
	go func() {
		h.decorator.k8sLoop(ctx)
		close(done)
	}()
	return cancel, done
}

func procEventDecoratorPodEvent(name string, pid app.PID) *informer.Event {
	return &informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name:      name,
			Namespace: "the-ns",
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Uid:        "uid-" + name,
				Containers: []*informer.ContainerInfo{{Name: "app", Id: fmt.Sprintf("container-%d", pid)}},
			},
		},
	}
}

func procEventDecoratorProcessEvent(pid app.PID) exec.ProcessEvent {
	service := svc.Attrs{}
	service.SetAutoName()
	return exec.ProcessEvent{
		File: exec.New(exec.Init{Pid: pid, Ns: 1000 + uint32(pid), Service: service}),
		Type: exec.ProcessEventCreated,
	}
}

func waitForLoop(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatal("kubernetes process event decoration loop did not stop")
	}
}

func requireOutputClosed(t *testing.T, output <-chan exec.ProcessEvent) {
	t.Helper()
	select {
	case _, ok := <-output:
		require.False(t, ok, "decorator output remained open after loop exit")
	case <-time.After(timeout):
		t.Fatal("decorator output remained open after loop exit")
	}
}

func requireUnsubscribed(t *testing.T, h *procEventDecoratorHarness) {
	t.Helper()
	h.store.Notify(procEventDecoratorPodEvent("after-shutdown", 99))
	_, queued := h.decorator.podEvents.TryDequeue()
	require.False(t, queued, "decorator still receives pod events after shutdown")
}

func TestProcEventMetadataDecoratorOnDoesNotBlock(t *testing.T) {
	h := newProcEventDecoratorHarness(t)

	// the loop is not running: On must neither block nor lose events
	const events = 100
	for i := range events {
		require.NoError(t, h.decorator.On(procEventDecoratorPodEvent("pod", app.PID(i))))
	}
	for range events {
		_, ok := h.decorator.podEvents.TryDequeue()
		require.True(t, ok)
	}
	_, ok := h.decorator.podEvents.TryDequeue()
	require.False(t, ok)
}

func TestProcEventMetadataDecoratorDrainsPodEventsInBatches(t *testing.T) {
	h := newProcEventDecoratorHarness(t)

	const queued = 2*podEventsBatchSize + 1
	for i := range queued {
		require.NoError(t, h.decorator.On(procEventDecoratorPodEvent("pod", app.PID(i))))
	}
	<-h.decorator.podEventsReady

	require.True(t, h.decorator.drainPodEvents(t.Context()))

	// the rest is left for later wake-ups, so other sources are served in between
	require.Len(t, h.decorator.podEventsReady, 1)
	remaining := 0
	for {
		if _, ok := h.decorator.podEvents.TryDequeue(); !ok {
			break
		}
		remaining++
	}
	assert.Equal(t, queued-podEventsBatchSize, remaining)
}

func TestProcEventMetadataDecoratorOnAfterStop(t *testing.T) {
	h := newProcEventDecoratorHarness(t)
	close(h.decorator.observerDone)

	require.ErrorIs(t, h.decorator.On(procEventDecoratorPodEvent("late", 1)), errProcEventDecoratorStopped)
}

func TestProcEventMetadataDecoratorCachedAndLiveDelivery(t *testing.T) {
	h := newProcEventDecoratorHarness(t)
	h.addTrackedPod(t, 1, "cached-pod")
	h.addTrackedPod(t, 2, "second-cached-pod")

	cancel, done := h.start(t)

	cached := []string{
		testutil.ReadChannel(t, h.output, timeout).File.ServiceAttrs().UID.Instance,
		testutil.ReadChannel(t, h.output, timeout).File.ServiceAttrs().UID.Instance,
	}
	require.ElementsMatch(t, []string{"the-ns.cached-pod.app", "the-ns.second-cached-pod.app"}, cached)

	h.addTrackedPod(t, 3, "live-pod")
	live := testutil.ReadChannel(t, h.output, timeout)
	require.Equal(t, "the-ns.live-pod.app", live.File.ServiceAttrs().UID.Instance)

	cancel()
	waitForLoop(t, done)
	requireOutputClosed(t, h.output)
}

type gatedReplayObserver struct {
	meta.Observer
	delivered chan<- struct{}
	release   <-chan struct{}
	once      sync.Once
}

func (g *gatedReplayObserver) On(event *informer.Event) error {
	err := g.Observer.On(event)
	g.once.Do(func() {
		g.delivered <- struct{}{}
		<-g.release
	})
	return err
}

// A store writer queued behind a replay in progress must not deadlock the decorator:
// the replay needs the store read lock until it completes, and the loop needs it to
// decorate process events.
func TestProcEventMetadataDecoratorQueuedStoreWriterDuringReplay(t *testing.T) {
	h := newProcEventDecoratorHarness(t)
	h.addTrackedPod(t, 1, "cached-pod")

	replayDelivered := make(chan struct{}, 1)
	releaseReplay := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseReplay)
		})
	}
	t.Cleanup(release)
	h.decorator.subscribeObserver = func(observer meta.Observer) {
		h.store.Subscribe(&gatedReplayObserver{
			Observer:  observer,
			delivered: replayDelivered,
			release:   releaseReplay,
		})
	}

	cancel, done := h.start(t)
	testutil.ReadChannel(t, replayDelivered, timeout)

	writerDone := make(chan struct{})
	go func() {
		h.store.AddProcess(2)
		close(writerDone)
	}()
	inputSent := make(chan struct{})
	go func() {
		h.input <- procEventDecoratorProcessEvent(2)
		close(inputSent)
	}()

	release()
	testutil.ReadChannel(t, writerDone, timeout)
	testutil.ReadChannel(t, inputSent, timeout)

	// there is no ordering between the cached pod and the process event
	instances := map[app.PID]string{}
	for range 2 {
		event := testutil.ReadChannel(t, h.output, timeout)
		instances[event.File.Pid()] = event.File.ServiceAttrs().UID.Instance
	}
	require.Contains(t, instances, app.PID(2))
	require.Equal(t, "the-ns.cached-pod.app", instances[1])

	cancel()
	waitForLoop(t, done)
	requireOutputClosed(t, h.output)
}

func TestProcEventMetadataDecoratorShutdown(t *testing.T) {
	tests := map[string]func(context.CancelFunc, chan exec.ProcessEvent){
		"context cancellation": func(cancel context.CancelFunc, _ chan exec.ProcessEvent) {
			cancel()
		},
		"input closure": func(_ context.CancelFunc, input chan exec.ProcessEvent) {
			close(input)
		},
	}

	for name, shutdown := range tests {
		t.Run(name, func(t *testing.T) {
			h := newProcEventDecoratorHarness(t)
			h.addTrackedPod(t, 1, "cached-pod")

			cancel, done := h.start(t)
			decorated := testutil.ReadChannel(t, h.output, timeout)
			require.Equal(t, "the-ns.cached-pod.app", decorated.File.ServiceAttrs().UID.Instance)

			shutdown(cancel, h.input)
			waitForLoop(t, done)
			requireOutputClosed(t, h.output)
			h.decorator.observerDone = make(chan struct{})
			requireUnsubscribed(t, h)
		})
	}
}

type fakeInformer struct {
	observers map[string]meta.Observer
}

func (f *fakeInformer) Subscribe(observer meta.Observer) {
	if f.observers == nil {
		f.observers = map[string]meta.Observer{}
	}
	f.observers[observer.ID()] = observer
}

func (f *fakeInformer) Unsubscribe(observer meta.Observer) {
	delete(f.observers, observer.ID())
}

func (f *fakeInformer) Notify(event *informer.Event) {
	for _, observer := range f.observers {
		_ = observer.On(event)
	}
}
