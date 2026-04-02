// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"net"
	"sync"
	"testing"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

type fakeNotifier struct {
	mt        sync.Mutex
	observers map[string]meta.Observer
}

func (f *fakeNotifier) Subscribe(observer meta.Observer) {
	f.mt.Lock()
	defer f.mt.Unlock()
	if f.observers == nil {
		f.observers = map[string]meta.Observer{}
	}
	f.observers[observer.ID()] = observer
}

func (f *fakeNotifier) Unsubscribe(observer meta.Observer) {
	f.mt.Lock()
	defer f.mt.Unlock()
	delete(f.observers, observer.ID())
}

func (f *fakeNotifier) Notify(_ *informer.Event) {
	// no-op for tests
}

func ipAddr(ip string) pipe.IPAddr {
	var addr pipe.IPAddr
	copy(addr[:], net.ParseIP(ip).To16())
	return addr
}

func newTestDecorator(t *testing.T, store *kube.Store) *decorator {
	t.Helper()
	lru, err := simplelru.NewLRU[string, struct{}](alreadyLoggedIPsCacheLen, nil)
	require.NoError(t, err)
	return &decorator{
		log:              log(),
		alreadyLoggedIPs: lru,
		store:            store,
	}
}

func TestDecorate_PodSetsServiceNameAsSource(t *testing.T) {
	notifier := &fakeNotifier{}
	store := kube.NewStore(notifier, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name:      "src-pod",
		Namespace: "src-ns",
		Ips:       []string{"10.0.0.1"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{{Kind: "Deployment", Name: "src-deploy"}},
		},
	}})

	dec := newTestDecorator(t, store)
	a := &pipe.CommonAttrs{
		SrcAddr:  ipAddr("10.0.0.1"),
		DstAddr:  ipAddr("10.0.0.2"),
		Metadata: map[attr.Name]string{},
	}

	ok := dec.decorate(a, attrPrefixSrc, "10.0.0.1")
	require.True(t, ok)

	assert.Equal(t, "src-deploy", a.Metadata[attr.ServiceName])
	assert.Equal(t, "src-ns", a.Metadata[attr.ServiceNamespace])
	// source should NOT set peer attributes
	assert.Empty(t, a.Metadata[attr.ServicePeerName])
	assert.Empty(t, a.Metadata[attr.ServicePeerNamespace])
}

func TestDecorate_PodSetsServicePeerNameAsDestination(t *testing.T) {
	notifier := &fakeNotifier{}
	store := kube.NewStore(notifier, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name:      "dst-pod",
		Namespace: "dst-ns",
		Ips:       []string{"10.0.0.2"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{{Kind: "Deployment", Name: "dst-deploy"}},
		},
	}})

	dec := newTestDecorator(t, store)
	a := &pipe.CommonAttrs{
		SrcAddr:  ipAddr("10.0.0.1"),
		DstAddr:  ipAddr("10.0.0.2"),
		Metadata: map[attr.Name]string{},
	}

	ok := dec.decorate(a, attrPrefixDst, "10.0.0.2")
	require.True(t, ok)

	assert.Equal(t, "dst-deploy", a.Metadata[attr.ServicePeerName])
	assert.Equal(t, "dst-ns", a.Metadata[attr.ServicePeerNamespace])
	// destination should NOT set service attributes
	assert.Empty(t, a.Metadata[attr.ServiceName])
	assert.Empty(t, a.Metadata[attr.ServiceNamespace])
}

func TestDecorate_NodeDoesNotSetServiceName(t *testing.T) {
	notifier := &fakeNotifier{}
	store := kube.NewStore(notifier, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name:      "worker-node",
		Namespace: "",
		Ips:       []string{"10.0.1.1"},
		Kind:      "Node",
	}})

	dec := newTestDecorator(t, store)
	a := &pipe.CommonAttrs{
		SrcAddr:  ipAddr("10.0.1.1"),
		DstAddr:  ipAddr("10.0.0.2"),
		Metadata: map[attr.Name]string{},
	}

	ok := dec.decorate(a, attrPrefixSrc, "10.0.1.1")
	require.True(t, ok)

	// Node should not have any service attributes
	assert.Empty(t, a.Metadata[attr.ServiceName])
	assert.Empty(t, a.Metadata[attr.ServiceNamespace])
	assert.Empty(t, a.Metadata[attr.ServicePeerName])
	assert.Empty(t, a.Metadata[attr.ServicePeerNamespace])
}

func TestDecorate_ServiceNameFromOTELEnv(t *testing.T) {
	notifier := &fakeNotifier{}
	store := kube.NewStore(notifier, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name:      "my-pod",
		Namespace: "my-ns",
		Ips:       []string{"10.0.0.3"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{{Kind: "Deployment", Name: "my-deploy"}},
			Containers: []*informer.ContainerInfo{{
				Id:  "c1",
				Env: map[string]string{"OTEL_SERVICE_NAME": "custom-svc"},
			}},
		},
	}})

	dec := newTestDecorator(t, store)
	a := &pipe.CommonAttrs{
		SrcAddr:  ipAddr("10.0.0.3"),
		DstAddr:  ipAddr("10.0.0.4"),
		Metadata: map[attr.Name]string{},
	}

	ok := dec.decorate(a, attrPrefixSrc, "10.0.0.3")
	require.True(t, ok)

	assert.Equal(t, "custom-svc", a.Metadata[attr.ServiceName])
	assert.Equal(t, "my-ns", a.Metadata[attr.ServiceNamespace])
}

func TestTransform_SrcAndDstPods(t *testing.T) {
	notifier := &fakeNotifier{}
	store := kube.NewStore(notifier, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name:      "frontend-pod",
		Namespace: "web",
		Ips:       []string{"10.0.0.10"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{{Kind: "Deployment", Name: "frontend"}},
		},
	}})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name:      "backend-pod",
		Namespace: "api",
		Ips:       []string{"10.0.0.20"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{{Kind: "Deployment", Name: "backend"}},
		},
	}})

	dec := newTestDecorator(t, store)
	a := &pipe.CommonAttrs{
		SrcAddr: ipAddr("10.0.0.10"),
		DstAddr: ipAddr("10.0.0.20"),
	}

	ok := dec.transform(a)
	require.True(t, ok)

	// Source service attributes
	assert.Equal(t, "frontend", a.Metadata[attr.ServiceName])
	assert.Equal(t, "web", a.Metadata[attr.ServiceNamespace])

	// Destination peer attributes
	assert.Equal(t, "backend", a.Metadata[attr.ServicePeerName])
	assert.Equal(t, "api", a.Metadata[attr.ServicePeerNamespace])
}
