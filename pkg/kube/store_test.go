// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"log/slog"
	"slices"
	"sync"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

func TestContainerInfoWithTemplate(t *testing.T) {
	deployment := informer.Owner{
		Name: "service",
		Kind: "Deployment",
	}

	replicaSet := informer.Owner{
		Name: "serviceB",
		Kind: "ReplicaSet",
	}

	service := informer.ObjectMeta{
		Name:      "service",
		Namespace: "namespaceA",
		Ips:       []string{"169.0.0.1", "169.0.0.2"},
		Kind:      "Service",
	}

	podMetaA := informer.ObjectMeta{
		Name:      "podA",
		Namespace: "namespaceA",
		Labels: map[string]string{
			"app.kubernetes.io/name":      "applicationA",
			"app.kubernetes.io/component": "componentA",
		},
		Ips:  []string{"1.1.1.1", "2.2.2.2"},
		Kind: "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&deployment},
			Containers: []*informer.ContainerInfo{
				{
					Id:  "container1",
					Env: map[string]string{"OTEL_SERVICE_NAME": "customName"},
				},
				{
					Id:  "container2",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=boo,other.attr=goo"},
				},
			},
		},
	}

	podMetaA1 := informer.ObjectMeta{
		Name:      "podA_1",
		Namespace: "namespaceA",
		Labels: map[string]string{
			"app.kubernetes.io/name":      "applicationA",
			"app.kubernetes.io/component": "componentB",
		},
		Ips:  []string{"3.1.1.1", "3.2.2.2"},
		Kind: "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&deployment},
			Containers: []*informer.ContainerInfo{
				{
					Id:  "container5",
					Env: map[string]string{"OTEL_SERVICE_NAME_NOT_EXIST": "customName"},
				},
				{
					Id:  "container6",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace1=boo,other.attr=goo"},
				},
			},
		},
	}

	podMetaB := informer.ObjectMeta{
		Name:      "podB",
		Namespace: "namespaceB",
		Labels: map[string]string{
			"app.kubernetes.io/name":      "applicationB",
			"app.kubernetes.io/component": "componentA",
		},
		Ips:  []string{"1.2.1.2", "2.1.2.1"},
		Kind: "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&replicaSet},
			Containers: []*informer.ContainerInfo{
				{
					Id: "container3",
				},
				{
					Id:  "container4",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=boo,other.attr=goo"},
				},
			},
		},
	}

	fInformer := &fakeInformer{}

	templ, _ := template.New("serviceNameTemplate").Parse(`{{- if eq .Meta.Pod nil }}{{.Meta.Name}}{{ else }}{{- .Meta.Namespace }}/{{ index .Meta.Labels "app.kubernetes.io/name" }}/{{ index .Meta.Labels "app.kubernetes.io/component" -}}{{ if .ContainerName }}/{{ .ContainerName -}}{{ end -}}{{ end -}}`)

	store := NewStore(fInformer, ResourceLabels{}, templ, imetrics.NoopReporter{})

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &service})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaB})

	assert.Len(t, store.containersByOwner, 2)

	serviceKey := ownerID(podMetaA.Namespace, service.Name)
	serviceContainers, ok := store.containersByOwner[serviceKey]
	assert.True(t, ok)
	assert.Len(t, serviceContainers, 4)

	replicaSetKey := ownerID(podMetaB.Namespace, replicaSet.Name)
	replicaSetContainers, ok := store.containersByOwner[replicaSetKey]
	assert.True(t, ok)
	assert.Len(t, replicaSetContainers, 2)

	assert.Empty(t, store.otelServiceInfoByIP)

	t.Run("test with service attributes set", func(t *testing.T) {
		for _, ip := range []string{"169.0.0.1", "1.1.1.1"} {
			t.Run(ip, func(t *testing.T) {
				name, namespace := store.ServiceNameNamespaceForIP(ip)
				assert.Equal(t, "customName", name, ip)
				assert.Equal(t, "boo", namespace, ip)
			})
		}
		// Pod with IP 3.1.1.1 does not have any overriding of the service name,
		// so it should follow te template
		t.Run("3.1.1.1", func(t *testing.T) {
			name, namespace := store.ServiceNameNamespaceForIP("3.1.1.1")
			assert.Equal(t, "namespaceA/applicationA/componentB", name)
			assert.Equal(t, "namespaceA", namespace)
		})
	})

	assert.Len(t, store.otelServiceInfoByIP, 3)
	// Delete the pod which had good definition for the OTel variables.
	// We expect much different service names now
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA})
	// We cleaned up the cache for service IPs. We must clean all of it
	// otherwise there will be stale data left
	assert.Empty(t, store.otelServiceInfoByIP)

	serviceKey = ownerID(podMetaA.Namespace, service.Name)
	serviceContainers, ok = store.containersByOwner[serviceKey]
	assert.True(t, ok)
	assert.Len(t, serviceContainers, 2)

	t.Run("test without service attributes set", func(tt *testing.T) {
		// We removed the pod that defined the env variables
		name, namespace := store.ServiceNameNamespaceForIP("169.0.0.1")
		assert.Equal(tt, "service", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForIP("3.1.1.1")
		assert.Equal(tt, "namespaceA/applicationA/componentB", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForIP("1.1.1.1")
		assert.Empty(tt, name)
		assert.Empty(tt, namespace)
	})

	// 3 again, because we cache that we can't see the IP in our info
	assert.Len(t, store.otelServiceInfoByIP, 3)

	t.Run("test with only namespace attributes set", func(tt *testing.T) {
		// We removed the pod that defined the env variables
		name, namespace := store.ServiceNameNamespaceForIP("1.2.1.2")
		assert.Equal(tt, "namespaceB/applicationB/componentA", name)
		assert.Equal(tt, "boo", namespace)

		name, namespace = store.ServiceNameNamespaceForIP("2.1.2.1")
		assert.Equal(tt, "namespaceB/applicationB/componentA", name)
		assert.Equal(tt, "boo", namespace)
	})

	assert.Len(t, store.otelServiceInfoByIP, 5)

	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaB})

	assert.Empty(t, store.otelServiceInfoByIP)

	// No containers left
	replicaSetKey = ownerID(podMetaB.Namespace, replicaSet.Name)
	_, ok = store.containersByOwner[replicaSetKey]
	assert.False(t, ok)

	serviceKey = ownerID(podMetaA.Namespace, service.Name)
	_, ok = store.containersByOwner[serviceKey]
	assert.False(t, ok)

	name, namespace := store.ServiceNameNamespaceForIP("169.0.0.2")
	assert.Equal(t, "service", name)
	assert.Equal(t, "namespaceA", namespace)

	t.Run("test with container name", func(tt *testing.T) {
		name, namespace := store.ServiceNameNamespaceForMetadata(&podMetaA, "container1")
		assert.Equal(tt, "namespaceA/applicationA/componentA/container1", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForMetadata(&podMetaA, "container2")
		assert.Equal(tt, "namespaceA/applicationA/componentA/container2", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForMetadata(&podMetaA1, "container5")
		assert.Equal(tt, "namespaceA/applicationA/componentB/container5", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForMetadata(&podMetaA1, "container6")
		assert.Equal(tt, "namespaceA/applicationA/componentB/container6", name)
		assert.Equal(tt, "namespaceA", namespace)

		name, namespace = store.ServiceNameNamespaceForMetadata(&podMetaB, "container3")
		assert.Equal(tt, "namespaceB/applicationB/componentA/container3", name)
		assert.Equal(tt, "namespaceB", namespace)

		name, namespace = store.ServiceNameNamespaceForMetadata(&podMetaB, "container4")
		assert.Equal(tt, "namespaceB/applicationB/componentA/container4", name)
		assert.Equal(tt, "namespaceB", namespace)
	})
}

func TestContainerInfo(t *testing.T) {
	deployment := informer.Owner{
		Name: "service",
		Kind: "Deployment",
	}

	replicaSet := informer.Owner{
		Name: "serviceB",
		Kind: "ReplicaSet",
	}

	service := informer.ObjectMeta{
		Name:      "service",
		Namespace: "namespaceA",
		Ips:       []string{"169.0.0.1", "169.0.0.2"},
		Kind:      "Service",
	}

	podMetaA := informer.ObjectMeta{
		Name:      "podA",
		Namespace: "namespaceA",
		Ips:       []string{"1.1.1.1", "2.2.2.2"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&deployment},
			Containers: []*informer.ContainerInfo{
				{
					Id:  "container1",
					Env: map[string]string{"OTEL_SERVICE_NAME": "customName"},
				},
				{
					Id:  "container2",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=boo,other.attr=goo"},
				},
			},
		},
	}

	podMetaA1 := informer.ObjectMeta{
		Name:      "podA_1",
		Namespace: "namespaceA",
		Ips:       []string{"3.1.1.1", "3.2.2.2"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&deployment},
			Containers: []*informer.ContainerInfo{
				{
					Id:  "container5",
					Env: map[string]string{"OTEL_SERVICE_NAME_NOT_EXIST": "customName"},
				},
				{
					Id:  "container6",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace1=boo,other.attr=goo"},
				},
			},
		},
	}

	podMetaB := informer.ObjectMeta{
		Name:      "podB",
		Namespace: "namespaceB",
		Ips:       []string{"1.2.1.2", "2.1.2.1"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&replicaSet},
			Containers: []*informer.ContainerInfo{
				{
					Id: "container3",
				},
				{
					Id:  "container4",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=boo,other.attr=goo"},
				},
			},
		},
	}

	fInformer := &fakeInformer{}

	store := NewStore(fInformer, ResourceLabels{}, nil, imetrics.NoopReporter{})

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &service})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaB})

	assert.Len(t, store.containersByOwner, 2)

	serviceKey := ownerID(podMetaA.Namespace, service.Name)
	serviceContainers, ok := store.containersByOwner[serviceKey]
	assert.True(t, ok)
	assert.Len(t, serviceContainers, 4)

	replicaSetKey := ownerID(podMetaB.Namespace, replicaSet.Name)
	replicaSetContainers, ok := store.containersByOwner[replicaSetKey]
	assert.True(t, ok)
	assert.Len(t, replicaSetContainers, 2)

	assert.Empty(t, store.otelServiceInfoByIP)

	t.Run("test with service attributes set", func(t *testing.T) {
		for _, ip := range []string{"169.0.0.1", "1.1.1.1"} {
			t.Run(ip, func(t *testing.T) {
				name, namespace := store.ServiceNameNamespaceForIP(ip)
				assert.Equal(t, "customName", name, ip)
				assert.Equal(t, "boo", namespace, ip)
			})
		}
		// Pod with IP 3.1.1.1 does neither override name nor namespace, so
		// we should expect here the Kubernetes metadata
		t.Run("3.1.1.1", func(t *testing.T) {
			name, namespace := store.ServiceNameNamespaceForIP("3.1.1.1")
			assert.Equal(t, "service", name)
			assert.Equal(t, "namespaceA", namespace)
		})
	})

	assert.Len(t, store.otelServiceInfoByIP, 3)
	// Delete the pod which had good definition for the OTel variables.
	// We expect much different service names now
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA})
	// We cleaned up the cache for service IPs. We must clean all of it
	// otherwise there will be stale data left
	assert.Empty(t, store.otelServiceInfoByIP)

	serviceKey = ownerID(podMetaA.Namespace, service.Name)
	serviceContainers, ok = store.containersByOwner[serviceKey]
	assert.True(t, ok)
	assert.Len(t, serviceContainers, 2)

	t.Run("test without service attributes set", func(t *testing.T) {
		// We removed the pod that defined the env variables
		for _, ip := range []string{"169.0.0.1", "3.1.1.1"} {
			t.Run(ip, func(t *testing.T) {
				name, namespace := store.ServiceNameNamespaceForIP(ip)
				assert.Equal(t, "service", name)
				assert.Equal(t, "namespaceA", namespace)
			})
		}

		name, namespace := store.ServiceNameNamespaceForIP("1.1.1.1")
		assert.Empty(t, name)
		assert.Empty(t, namespace)
	})

	// 3 again, because we cache that we can't see the IP in our info
	assert.Len(t, store.otelServiceInfoByIP, 3)

	t.Run("test with only namespace attributes set", func(t *testing.T) {
		// We removed the pod that defined the env variables
		for _, ip := range []string{"1.2.1.2", "2.1.2.1"} {
			t.Run(ip, func(t *testing.T) {
				name, namespace := store.ServiceNameNamespaceForIP(ip)
				assert.Equal(t, "serviceB", name)
				assert.Equal(t, "boo", namespace)
			})
		}
	})

	assert.Len(t, store.otelServiceInfoByIP, 5)

	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaB})

	assert.Empty(t, store.otelServiceInfoByIP)

	// No containers left
	replicaSetKey = ownerID(podMetaB.Namespace, replicaSet.Name)
	_, ok = store.containersByOwner[replicaSetKey]
	assert.False(t, ok)

	serviceKey = ownerID(podMetaA.Namespace, service.Name)
	_, ok = store.containersByOwner[serviceKey]
	assert.False(t, ok)

	name, namespace := store.ServiceNameNamespaceForIP("169.0.0.2")
	assert.Equal(t, "service", name)
	assert.Equal(t, "namespaceA", namespace)
}

func TestMemoryCleanedUp(t *testing.T) {
	deployment := informer.Owner{
		Name: "service",
		Kind: "Deployment",
	}

	replicaSet := informer.Owner{
		Name: "serviceB",
		Kind: "ReplicaSet",
	}

	service := informer.ObjectMeta{
		Name:      "service",
		Namespace: "namespaceA",
		Ips:       []string{"169.0.0.1", "169.0.0.2"},
		Kind:      "Service",
	}

	podMetaA := informer.ObjectMeta{
		Name:      "podA",
		Namespace: "namespaceA",
		Ips:       []string{"1.1.1.1", "2.2.2.2"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&deployment},
			Containers: []*informer.ContainerInfo{
				{
					Id:  "container1",
					Env: map[string]string{"OTEL_SERVICE_NAME": "customName"},
				},
				{
					Id:  "container2",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=boo,other.attr=goo"},
				},
			},
		},
	}

	podMetaA1 := informer.ObjectMeta{
		Name:      "podA_1",
		Namespace: "namespaceA",
		Ips:       []string{"3.1.1.1", "3.2.2.2"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&deployment},
			Containers: []*informer.ContainerInfo{
				{
					Id:  "container5",
					Env: map[string]string{"OTEL_SERVICE_NAME_NOT_EXIST": "customName"},
				},
				{
					Id:  "container6",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace1=boo,other.attr=goo"},
				},
			},
		},
	}

	podMetaB := informer.ObjectMeta{
		Name:      "podB",
		Namespace: "namespaceB",
		Ips:       []string{"1.2.1.2", "2.1.2.1"},
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{&replicaSet},
			Containers: []*informer.ContainerInfo{
				{
					Id: "container3",
				},
				{
					Id:  "container4",
					Env: map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=boo,other.attr=goo"},
				},
			},
		},
	}

	fInformer := &fakeInformer{}

	store := NewStore(fInformer, ResourceLabels{}, nil, imetrics.NoopReporter{})

	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &service})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &podMetaB})

	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA1})
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaA})
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &podMetaB})
	_ = store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &service})

	assert.Empty(t, store.containerIDs)
	assert.Empty(t, store.containerByPID)
	assert.Empty(t, store.namespaces)
	assert.Empty(t, store.podsByContainer)
	assert.Empty(t, store.containersByOwner)
	assert.Empty(t, store.objectMetaByIP)
	assert.Empty(t, store.otelServiceInfoByIP)
}

// Fixes a memory leak in the store where the objectMetaByIP map was not cleaned up
func TestMetaByIPEntryRemovedIfIPGroupChanges(t *testing.T) {
	// GIVEN a store with
	store := NewStore(&fakeInformer{}, ResourceLabels{}, nil, imetrics.NoopReporter{})
	// WHEN an object is created with several IPs
	_ = store.On(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name:      "object_1",
			Namespace: "namespaceA",
			Ips:       []string{"3.1.1.1", "3.2.2.2"},
			Kind:      "Service",
		},
	})
	// THEN the object is only accessible through all its IPs
	assert.Nil(t, store.ObjectMetaByIP("1.2.3.4"))
	om := store.ObjectMetaByIP("3.1.1.1")
	require.NotNil(t, om)
	assert.Equal(t, "object_1", om.Meta.Name)
	assert.Equal(t, []string{"3.1.1.1", "3.2.2.2"}, om.Meta.Ips)
	om = store.ObjectMetaByIP("3.2.2.2")
	require.NotNil(t, om)
	assert.Equal(t, "object_1", om.Meta.Name)
	assert.Equal(t, []string{"3.1.1.1", "3.2.2.2"}, om.Meta.Ips)

	// AND WHEN an object is updated with a different set of IPs
	_ = store.On(&informer.Event{
		Type: informer.EventType_UPDATED,
		Resource: &informer.ObjectMeta{
			Name:      "object_1",
			Namespace: "namespaceA",
			Ips:       []string{"3.2.2.2", "3.3.3.3"},
			Kind:      "Service",
		},
	})
	// THEN the object is only accessible through all its new IPs, but not the old ones
	assert.Nil(t, store.ObjectMetaByIP("3.1.1.1"))
	om = store.ObjectMetaByIP("3.3.3.3")
	require.NotNil(t, om)
	assert.Equal(t, "object_1", om.Meta.Name)
	assert.Equal(t, []string{"3.2.2.2", "3.3.3.3"}, om.Meta.Ips)
	om = store.ObjectMetaByIP("3.2.2.2")
	require.NotNil(t, om)
	assert.Equal(t, "object_1", om.Meta.Name)
	assert.Equal(t, []string{"3.2.2.2", "3.3.3.3"}, om.Meta.Ips)
}

func TestNoLeakOnUpdateOrDeletion(t *testing.T) {
	store := NewStore(&fakeInformer{}, ResourceLabels{}, nil, imetrics.NoopReporter{})
	topOwner := &informer.Owner{Name: "foo", Kind: "Deployment"}
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name:      "pod-foo-1",
			Namespace: "namespaceA",
			Ips:       []string{"1.1.1.1", "2.2.2.2"},
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Owners: []*informer.Owner{topOwner},
				Containers: []*informer.ContainerInfo{
					{Id: "container1-1"},
					{Id: "container1-2"},
				},
			},
		},
	}))
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name:      "pod-foo-2",
			Namespace: "namespaceA",
			Ips:       []string{"4.4.4.4", "5.5.5.5"},
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Owners: []*informer.Owner{topOwner},
				Containers: []*informer.ContainerInfo{
					{Id: "container2-1"},
					{Id: "container2-2"},
				},
			},
		},
	}))
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_UPDATED,
		Resource: &informer.ObjectMeta{
			Name:      "pod-foo-1",
			Namespace: "namespaceA",
			Ips:       []string{"1.1.1.1", "3.3.3.3"},
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Owners: []*informer.Owner{topOwner},
				Containers: []*informer.ContainerInfo{
					{Id: "container1-1"},
					{Id: "container1-3"},
				},
			},
		},
	}))
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_DELETED,
		Resource: &informer.ObjectMeta{
			Name:      "pod-foo-1",
			Namespace: "namespaceA",
			Ips:       []string{"1.1.1.1", "3.3.3.3"},
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Owners: []*informer.Owner{topOwner},
				Containers: []*informer.ContainerInfo{
					{Id: "container1"},
					{Id: "container3"},
				},
			},
		},
	}))
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_DELETED,
		Resource: &informer.ObjectMeta{
			Name:      "foo",
			Namespace: "namespaceA",
		},
	}))
	require.NoError(t, store.On(&informer.Event{
		Type: informer.EventType_DELETED,
		Resource: &informer.ObjectMeta{
			Name:      "pod-foo-2",
			Namespace: "namespaceA",
			Ips:       []string{"4.4.4.4", "5.5.5.5"},
			Kind:      "Pod",
			Pod: &informer.PodInfo{
				Containers: []*informer.ContainerInfo{
					{Id: "container2-1"},
					{Id: "container2-3"},
				},
			},
		},
	}))

	assert.Empty(t, store.objectMetaByQName)
	assert.Empty(t, store.objectMetaByIP)
	assert.Empty(t, store.containerIDs)
	assert.Empty(t, store.namespaces)
	assert.Empty(t, store.namespaces)
	assert.Empty(t, store.podsByContainer)
	assert.Empty(t, store.containersByOwner)
}

func TestStore_MultiPID_SameContainerAndNamespace(t *testing.T) {
	// Mock InfoForPID to return controlled container info
	originalInfoForPID := InfoForPID
	defer func() { InfoForPID = originalInfoForPID }()

	tests := []struct {
		name        string
		setupPIDs   []uint32
		containerID string
		pidNS       uint32
		operations  func(t *testing.T, store *Store, pids []uint32)
	}{
		{
			name:        "add multiple PIDs same container and namespace",
			setupPIDs:   []uint32{1001, 1002, 1003},
			containerID: "container123",
			pidNS:       5000,
			operations: func(t *testing.T, store *Store, pids []uint32) {
				// Verify all PIDs are stored in namespaces map
				store.access.RLock()
				nsMap, exists := store.namespaces[5000]
				require.True(t, exists, "Namespace map should exist")
				assert.Len(t, nsMap, 3, "Should have 3 PIDs in namespace")

				for _, pid := range pids {
					info, exists := nsMap[pid]
					assert.True(t, exists, "PID %d should exist in namespace map", pid)
					assert.Equal(t, "container123", info.ContainerID)
					assert.Equal(t, uint32(5000), info.PIDNamespace)
				}

				// Verify all PIDs are stored in containerIDs map
				cidMap, exists := store.containerIDs["container123"]
				require.True(t, exists, "Container ID map should exist")
				assert.Len(t, cidMap, 3, "Should have 3 PIDs in container map")

				for _, pid := range pids {
					info, exists := cidMap[pid]
					assert.True(t, exists, "PID %d should exist in container map", pid)
					assert.Equal(t, "container123", info.ContainerID)
					assert.Equal(t, uint32(5000), info.PIDNamespace)
				}

				// Verify all PIDs are in containerByPID map
				for _, pid := range pids {
					info, exists := store.containerByPID[pid]
					assert.True(t, exists, "PID %d should exist in containerByPID", pid)
					assert.Equal(t, "container123", info.ContainerID)
					assert.Equal(t, uint32(5000), info.PIDNamespace)
				}
				store.access.RUnlock()
			},
		},
		{
			name:        "delete one PID among multiple",
			setupPIDs:   []uint32{2001, 2002, 2003, 2004},
			containerID: "container456",
			pidNS:       6000,
			operations: func(t *testing.T, store *Store, _ []uint32) {
				// Delete middle PID
				store.DeleteProcess(2002)

				store.access.RLock()
				// Verify namespace map still has other PIDs
				nsMap, exists := store.namespaces[6000]
				require.True(t, exists, "Namespace map should still exist")
				assert.Len(t, nsMap, 3, "Should have 3 PIDs left in namespace")

				// Verify deleted PID is gone
				_, exists = nsMap[2002]
				assert.False(t, exists, "Deleted PID should not exist in namespace map")

				// Verify other PIDs still exist
				for _, pid := range []uint32{2001, 2003, 2004} {
					_, exists := nsMap[pid]
					assert.True(t, exists, "PID %d should still exist", pid)
				}

				// Verify container map
				cidMap, exists := store.containerIDs["container456"]
				require.True(t, exists, "Container ID map should still exist")
				assert.Len(t, cidMap, 3, "Should have 3 PIDs left in container map")

				_, exists = cidMap[2002]
				assert.False(t, exists, "Deleted PID should not exist in container map")

				// Verify containerByPID
				_, exists = store.containerByPID[2002]
				assert.False(t, exists, "Deleted PID should not exist in containerByPID")

				for _, pid := range []uint32{2001, 2003, 2004} {
					_, exists := store.containerByPID[pid]
					assert.True(t, exists, "PID %d should still exist in containerByPID", pid)
				}
				store.access.RUnlock()
			},
		},
		{
			name:        "delete all PIDs one by one",
			setupPIDs:   []uint32{3001, 3002, 3003},
			containerID: "container789",
			pidNS:       7000,
			operations: func(t *testing.T, store *Store, pids []uint32) {
				// Delete all PIDs one by one
				for _, pid := range pids {
					store.DeleteProcess(pid)
				}

				store.access.RLock()
				// Verify namespace map is empty or doesn't exist
				nsMap, exists := store.namespaces[7000]
				if exists {
					assert.Empty(t, nsMap, "Namespace map should be empty")
				}

				// Verify container map is empty or doesn't exist
				cidMap, exists := store.containerIDs["container789"]
				if exists {
					assert.Empty(t, cidMap, "Container map should be empty")
				}

				// Verify containerByPID has no entries for these PIDs
				for _, pid := range pids {
					_, exists := store.containerByPID[pid]
					assert.False(t, exists, "PID %d should not exist in containerByPID", pid)
				}
				store.access.RUnlock()
			},
		},
		{
			name:        "add PIDs incrementally",
			setupPIDs:   []uint32{}, // Start empty
			containerID: "container999",
			pidNS:       8000,
			operations: func(t *testing.T, store *Store, _ []uint32) {
				// Add PIDs one by one
				testPIDs := []uint32{4001, 4002, 4003, 4004, 4005}

				for i, pid := range testPIDs {
					// Mock InfoForPID for this specific test
					InfoForPID = func(p uint32) (container.Info, error) {
						if p == pid {
							return container.Info{
								ContainerID:  "container999",
								PIDNamespace: 8000,
							}, nil
						}
						return container.Info{}, assert.AnError
					}

					store.AddProcess(pid)

					// Verify incremental addition
					store.access.RLock()
					nsMap, exists := store.namespaces[8000]
					require.True(t, exists, "Namespace map should exist after adding PID %d", pid)
					assert.Len(t, nsMap, i+1, "Should have %d PIDs after adding %d", i+1, pid)

					cidMap, exists := store.containerIDs["container999"]
					require.True(t, exists, "Container map should exist after adding PID %d", pid)
					assert.Len(t, cidMap, i+1, "Should have %d PIDs in container map after adding %d", i+1, pid)
					store.access.RUnlock()
				}
			},
		},
		{
			name:        "mixed operations - add, delete, add again",
			setupPIDs:   []uint32{5001, 5002},
			containerID: "container111",
			pidNS:       9000,
			operations: func(t *testing.T, store *Store, _ []uint32) {
				// Initial state: 2 PIDs
				store.access.RLock()
				nsMap, exists := store.namespaces[9000]
				assert.True(t, exists)
				assert.Len(t, nsMap, 2, "Should start with 2 PIDs")
				store.access.RUnlock()

				// Delete one
				store.DeleteProcess(5001)

				store.access.RLock()
				nsMap, exists = store.namespaces[9000]
				assert.True(t, exists)
				assert.Len(t, nsMap, 1, "Should have 1 PID after deletion")
				store.access.RUnlock()

				// Add new PID
				InfoForPID = func(p uint32) (container.Info, error) {
					if p == 5003 {
						return container.Info{
							ContainerID:  "container111",
							PIDNamespace: 9000,
						}, nil
					}
					return container.Info{}, assert.AnError
				}

				store.AddProcess(5003)

				store.access.RLock()
				nsMap, exists = store.namespaces[9000]
				assert.True(t, exists)
				assert.Len(t, nsMap, 2, "Should have 2 PIDs after re-addition")

				// Verify correct PIDs exist
				_, exists = nsMap[5001]
				assert.False(t, exists, "Deleted PID should not exist")
				_, exists = nsMap[5002]
				assert.True(t, exists, "Original PID should still exist")
				_, exists = nsMap[5003]
				assert.True(t, exists, "New PID should exist")
				store.access.RUnlock()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := createTestStore()

			// Setup: mock InfoForPID for initial PIDs
			if len(tt.setupPIDs) > 0 {
				InfoForPID = func(pid uint32) (container.Info, error) {
					if slices.Contains(tt.setupPIDs, pid) {
						return container.Info{
							ContainerID:  tt.containerID,
							PIDNamespace: tt.pidNS,
						}, nil
					}
					return container.Info{}, assert.AnError
				}

				// Add initial PIDs
				for _, pid := range tt.setupPIDs {
					store.AddProcess(pid)
				}
			}

			// Run test operations
			tt.operations(t, store, tt.setupPIDs)
		})
	}
}

func TestStore_MultiPID_CrossContainerScenarios(t *testing.T) {
	originalInfoForPID := InfoForPID
	defer func() { InfoForPID = originalInfoForPID }()

	store := createTestStore()

	// Setup multiple containers with multiple PIDs each
	scenarios := map[string]struct {
		containerID string
		pidNS       uint32
		pids        []uint32
	}{
		"container1": {"cont1", 1000, []uint32{101, 102, 103}},
		"container2": {"cont2", 2000, []uint32{201, 202}},
		"container3": {"cont3", 1000, []uint32{301, 302, 303, 304}}, // Same namespace as container1
	}

	// Mock InfoForPID to handle all scenarios
	InfoForPID = func(pid uint32) (container.Info, error) {
		for _, scenario := range scenarios {
			if slices.Contains(scenario.pids, pid) {
				return container.Info{
					ContainerID:  scenario.containerID,
					PIDNamespace: scenario.pidNS,
				}, nil
			}
		}
		return container.Info{}, assert.AnError
	}

	// Add all PIDs
	for _, scenario := range scenarios {
		for _, pid := range scenario.pids {
			store.AddProcess(pid)
		}
	}

	t.Run("verify namespace separation", func(t *testing.T) {
		store.access.RLock()
		defer store.access.RUnlock()

		// Namespace 1000 should have PIDs from container1 and container3
		nsMap1000, exists := store.namespaces[1000]
		require.True(t, exists)
		assert.Len(t, nsMap1000, 7, "Namespace 1000 should have 7 PIDs total")

		// Verify container1 PIDs
		for _, pid := range []uint32{101, 102, 103} {
			info, exists := nsMap1000[pid]
			assert.True(t, exists, "PID %d should exist", pid)
			assert.Equal(t, "cont1", info.ContainerID)
		}

		// Verify container3 PIDs
		for _, pid := range []uint32{301, 302, 303, 304} {
			info, exists := nsMap1000[pid]
			assert.True(t, exists, "PID %d should exist", pid)
			assert.Equal(t, "cont3", info.ContainerID)
		}

		// Namespace 2000 should have PIDs only from container2
		nsMap2000, exists := store.namespaces[2000]
		require.True(t, exists)
		assert.Len(t, nsMap2000, 2, "Namespace 2000 should have 2 PIDs")

		for _, pid := range []uint32{201, 202} {
			info, exists := nsMap2000[pid]
			assert.True(t, exists, "PID %d should exist", pid)
			assert.Equal(t, "cont2", info.ContainerID)
		}
	})

	t.Run("verify container separation", func(t *testing.T) {
		store.access.RLock()
		defer store.access.RUnlock()

		// Each container should have its own PIDs
		cont1Map, exists := store.containerIDs["cont1"]
		require.True(t, exists)
		assert.Len(t, cont1Map, 3)

		cont2Map, exists := store.containerIDs["cont2"]
		require.True(t, exists)
		assert.Len(t, cont2Map, 2)

		cont3Map, exists := store.containerIDs["cont3"]
		require.True(t, exists)
		assert.Len(t, cont3Map, 4)
	})

	t.Run("delete container2 PIDs and verify isolation", func(t *testing.T) {
		// Delete all PIDs from container2
		store.DeleteProcess(201)
		store.DeleteProcess(202)

		store.access.RLock()
		defer store.access.RUnlock()

		// Namespace 1000 should be unaffected
		nsMap1000, exists := store.namespaces[1000]
		require.True(t, exists)
		assert.Len(t, nsMap1000, 7, "Namespace 1000 should still have 7 PIDs")

		// Namespace 2000 should be empty or non-existent
		nsMap2000, exists := store.namespaces[2000]
		if exists {
			assert.Empty(t, nsMap2000, "Namespace 2000 should be empty")
		}

		// Container2 map should be empty or non-existent
		cont2Map, exists := store.containerIDs["cont2"]
		if exists {
			assert.Empty(t, cont2Map, "Container2 map should be empty")
		}

		// Other containers should be unaffected
		cont1Map, exists := store.containerIDs["cont1"]
		require.True(t, exists)
		assert.Len(t, cont1Map, 3, "Container1 should still have 3 PIDs")

		cont3Map, exists := store.containerIDs["cont3"]
		require.True(t, exists)
		assert.Len(t, cont3Map, 4, "Container3 should still have 4 PIDs")
	})
}

func TestStore_PodContainerByPIDNs_MultiPID(t *testing.T) {
	originalInfoForPID := InfoForPID
	defer func() { InfoForPID = originalInfoForPID }()

	store := createTestStore()

	// Setup multiple PIDs with same namespace
	pidNS := uint32(5000)
	containerID := "test-container"
	pids := []uint32{1001, 1002, 1003}

	InfoForPID = func(pid uint32) (container.Info, error) {
		if slices.Contains(pids, pid) {
			return container.Info{
				ContainerID:  containerID,
				PIDNamespace: pidNS,
			}, nil
		}
		return container.Info{}, assert.AnError
	}

	// Add all PIDs
	for _, pid := range pids {
		store.AddProcess(pid)
	}

	// Add pod metadata
	podMeta := &informer.ObjectMeta{
		Name:      "test-pod",
		Namespace: "default",
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Containers: []*informer.ContainerInfo{
				{
					Id:   containerID,
					Name: "test-container-name",
				},
			},
		},
	}

	store.addObjectMeta(podMeta)

	t.Run("PodContainerByPIDNs returns correct pod for any PID", func(t *testing.T) {
		// Should return the same pod regardless of which PID is actually found first
		// (since they're all in the same namespace and container)
		pod, containerName := store.PodContainerByPIDNs(pidNS)

		require.NotNil(t, pod, "Should find pod for namespace")
		assert.Equal(t, "test-pod", pod.Meta.Name)
		assert.Equal(t, "test-container-name", containerName)
	})

	t.Run("after deleting some PIDs, still finds pod", func(t *testing.T) {
		// Delete one PID
		store.DeleteProcess(1001)

		pod, containerName := store.PodContainerByPIDNs(pidNS)
		require.NotNil(t, pod, "Should still find pod after deleting one PID")
		assert.Equal(t, "test-pod", pod.Meta.Name)
		assert.Equal(t, "test-container-name", containerName)
	})

	t.Run("after deleting all PIDs, doesn't find pod", func(t *testing.T) {
		// Delete remaining PIDs
		store.DeleteProcess(1002)
		store.DeleteProcess(1003)

		pod, containerName := store.PodContainerByPIDNs(pidNS)
		assert.Nil(t, pod, "Should not find pod after deleting all PIDs")
		assert.Empty(t, containerName)
	})
}

func TestStore_MultiPID_ConcurrentAccess(t *testing.T) {
	originalInfoForPID := InfoForPID
	defer func() { InfoForPID = originalInfoForPID }()

	store := createTestStore()

	// Setup for concurrent access testing
	containerID := "concurrent-container"
	pidNS := uint32(9999)

	InfoForPID = func(uint32) (container.Info, error) {
		return container.Info{
			ContainerID:  containerID,
			PIDNamespace: pidNS,
		}, nil
	}

	t.Run("concurrent adds and deletes", func(t *testing.T) {
		// This test verifies that the store can handle concurrent operations
		// without data races (run with -race flag)

		const numWorkers = 10
		const numOpsPerWorker = 50

		// Start concurrent workers
		done := make(chan bool, numWorkers*2)

		// Add workers
		for i := range numWorkers {
			go func(workerID int) {
				for j := range numOpsPerWorker {
					pid := uint32(workerID*1000 + j)
					store.AddProcess(pid)
				}
				done <- true
			}(i)
		}

		// Delete workers (will delete some of the PIDs being added)
		for i := range numWorkers {
			go func(workerID int) {
				for j := range numOpsPerWorker / 2 {
					pid := uint32(workerID*1000 + j)
					store.DeleteProcess(pid)
				}
				done <- true
			}(i)
		}

		// Wait for all workers to complete
		for range numWorkers * 2 {
			<-done
		}

		// Verify final state is consistent
		store.access.RLock()
		nsMap, exists := store.namespaces[pidNS]
		if exists {
			cidMap, cidExists := store.containerIDs[containerID]
			assert.Equal(t, cidExists, exists, "Both maps should have same existence state")
			if cidExists {
				assert.Len(t, nsMap, len(cidMap), "Both maps should have same number of PIDs")

				// Verify consistency between maps
				for pid, nsInfo := range nsMap {
					cidInfo, cidHasPID := cidMap[pid]
					assert.True(t, cidHasPID, "Container map should have PID %d", pid)
					assert.Equal(t, nsInfo.ContainerID, cidInfo.ContainerID, "Container IDs should match for PID %d", pid)
					assert.Equal(t, nsInfo.PIDNamespace, cidInfo.PIDNamespace, "Namespaces should match for PID %d", pid)
				}
			}
		}
		store.access.RUnlock()
	})
}

// Helper function to create a test store
func createTestStore() *Store {
	n := meta.NewBaseNotifier(slog.Default())
	return NewStore(
		&n,
		DefaultResourceLabels,
		nil, // no service name template
		imetrics.NoopReporter{},
	)
}

type fakeInformer struct {
	mt        sync.Mutex
	observers map[string]meta.Observer
}

func (f *fakeInformer) Subscribe(observer meta.Observer) {
	f.mt.Lock()
	defer f.mt.Unlock()
	if f.observers == nil {
		f.observers = map[string]meta.Observer{}
	}
	f.observers[observer.ID()] = observer
}

func (f *fakeInformer) Unsubscribe(observer meta.Observer) {
	f.mt.Lock()
	defer f.mt.Unlock()
	delete(f.observers, observer.ID())
}

func (f *fakeInformer) Notify(event *informer.Event) {
	f.mt.Lock()
	defer f.mt.Unlock()
	for _, observer := range f.observers {
		_ = observer.On(event)
	}
}
