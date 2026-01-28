// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

func TestSuffixPrefix(t *testing.T) {
	assert.Equal(t, "super", trimSuffixIgnoreCase("superDuper", "DUPER"))
	assert.Equal(t, "superDup", trimSuffixIgnoreCase("superDuper", "ER"))
	assert.Equal(t, "superDuper", trimSuffixIgnoreCase("superDuper", "Not matching"))
	assert.Equal(t, "superDuper", trimSuffixIgnoreCase("superDuper", "SuperDuperDuper"))
	assert.Empty(t, trimSuffixIgnoreCase("superDuper", "SuperDuper"))
	assert.Equal(t, "superDuper", trimSuffixIgnoreCase("superDuper", ""))

	assert.Equal(t, "super", trimPrefixIgnoreCase("Dupersuper", "DUPER"))
	assert.Equal(t, "super", trimPrefixIgnoreCase("Ersuper", "ER"))
	assert.Equal(t, "superDuper", trimPrefixIgnoreCase("superDuper", "Not matching"))
	assert.Equal(t, "superDuper", trimPrefixIgnoreCase("superDuper", "SuperDuperDuper"))
	assert.Empty(t, trimPrefixIgnoreCase("superDuper", "SuperDuper"))
	assert.Equal(t, "superDuper", trimPrefixIgnoreCase("superDuper", ""))
}

func TestResolvePodsFromK8s(t *testing.T) {
	inf := &fakeInformer{}
	db := kube.NewStore(inf, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
	pod1 := &informer.ObjectMeta{Name: "pod1", Kind: "Pod", Ips: []string{"10.0.0.1", "10.1.0.1"}}
	pod2 := &informer.ObjectMeta{Name: "pod2", Namespace: "something", Kind: "Pod", Ips: []string{"10.0.0.2", "10.1.0.2"}}
	pod3 := &informer.ObjectMeta{Name: "pod3", Kind: "Pod", Ips: []string{"10.0.0.3", "10.1.0.3"}}
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod1})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod2})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod3})

	assert.Equal(t, pod1, db.ObjectMetaByIP("10.0.0.1").Meta)
	assert.Equal(t, pod1, db.ObjectMetaByIP("10.1.0.1").Meta)
	assert.Equal(t, pod2, db.ObjectMetaByIP("10.0.0.2").Meta)
	assert.Equal(t, pod2, db.ObjectMetaByIP("10.1.0.2").Meta)
	assert.Equal(t, pod3, db.ObjectMetaByIP("10.1.0.3").Meta)

	inf.Notify(&informer.Event{Type: informer.EventType_DELETED, Resource: pod3})
	assert.Nil(t, db.ObjectMetaByIP("10.1.0.3"))

	nr := NameResolver{
		db:      db,
		cache:   expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sources: resolverSources([]Source{SourceDNS, SourceK8s}),
	}

	name, namespace, k8sNamespace := nr.resolveFromK8s("10.0.0.1")
	assert.Equal(t, "pod1", name)
	assert.Empty(t, namespace)
	assert.Empty(t, k8sNamespace)

	name, namespace, k8sNamespace = nr.resolveFromK8s("10.0.0.2")
	assert.Equal(t, "pod2", name)
	assert.Equal(t, "something", namespace)
	assert.Equal(t, "something", k8sNamespace)

	name, namespace, k8sNamespace = nr.resolveFromK8s("10.0.0.3")
	assert.Empty(t, name)
	assert.Empty(t, namespace)
	assert.Empty(t, k8sNamespace)

	clientSpan := request.Span{
		Type: request.EventTypeHTTPClient,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "pod1",
			Namespace: "",
		}},
	}

	serverSpan := request.Span{
		Type: request.EventTypeHTTP,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "pod2",
			Namespace: "something",
		}},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "pod1", clientSpan.PeerName)
	assert.Empty(t, clientSpan.Service.UID.Namespace)
	assert.Equal(t, "pod2", clientSpan.HostName)
	assert.Equal(t, "something", clientSpan.OtherNamespace)

	nr.resolveNames(&serverSpan)

	assert.Equal(t, "pod1", serverSpan.PeerName)
	assert.Empty(t, serverSpan.OtherNamespace)
	assert.Equal(t, "pod2", serverSpan.HostName)
	assert.Equal(t, "something", serverSpan.Service.UID.Namespace)
}

func TestResolveServiceFromK8s(t *testing.T) {
	inf := &fakeInformer{}
	db := kube.NewStore(inf, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
	pod1 := &informer.ObjectMeta{Name: "pod1", Kind: "Service", Ips: []string{"10.0.0.1", "10.1.0.1"}}
	pod2 := &informer.ObjectMeta{Name: "pod2", Namespace: "something", Kind: "Service", Ips: []string{"10.0.0.2", "10.1.0.2"}}
	pod3 := &informer.ObjectMeta{Name: "pod3", Kind: "Service", Ips: []string{"10.0.0.3", "10.1.0.3"}}
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod1})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod2})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod3})

	assert.Equal(t, pod1, db.ObjectMetaByIP("10.0.0.1").Meta)
	assert.Equal(t, pod1, db.ObjectMetaByIP("10.1.0.1").Meta)
	assert.Equal(t, pod2, db.ObjectMetaByIP("10.0.0.2").Meta)
	assert.Equal(t, pod2, db.ObjectMetaByIP("10.1.0.2").Meta)
	assert.Equal(t, pod3, db.ObjectMetaByIP("10.1.0.3").Meta)
	inf.Notify(&informer.Event{Type: informer.EventType_DELETED, Resource: pod3})
	assert.Nil(t, db.ObjectMetaByIP("10.1.0.3"))

	nr := NameResolver{
		db:      db,
		cache:   expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sources: resolverSources([]Source{SourceDNS, SourceK8s}),
	}

	name, namespace, k8sNamespace := nr.resolveFromK8s("10.0.0.1")
	assert.Equal(t, "pod1", name)
	assert.Empty(t, namespace)
	assert.Empty(t, k8sNamespace)

	name, namespace, k8sNamespace = nr.resolveFromK8s("10.0.0.2")
	assert.Equal(t, "pod2", name)
	assert.Equal(t, "something", namespace)
	assert.Equal(t, "something", k8sNamespace)

	name, namespace, k8sNamespace = nr.resolveFromK8s("10.0.0.3")
	assert.Empty(t, name)
	assert.Empty(t, namespace)
	assert.Empty(t, k8sNamespace)

	clientSpan := request.Span{
		Type: request.EventTypeHTTPClient,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "pod1",
			Namespace: "",
		}},
	}

	serverSpan := request.Span{
		Type: request.EventTypeHTTP,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "pod2",
			Namespace: "something",
		}},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "pod1", clientSpan.PeerName)
	assert.Empty(t, clientSpan.Service.UID.Namespace)
	assert.Equal(t, "pod2", clientSpan.HostName)
	assert.Equal(t, "something", clientSpan.OtherNamespace)

	nr.resolveNames(&serverSpan)

	assert.Equal(t, "pod1", serverSpan.PeerName)
	assert.Empty(t, serverSpan.OtherNamespace)
	assert.Equal(t, "pod2", serverSpan.HostName)
	assert.Equal(t, "something", serverSpan.Service.UID.Namespace)
}

func TestCleanName(t *testing.T) {
	s := svc.Attrs{
		UID: svc.UID{
			Name:      "service",
			Namespace: "special.namespace",
		},
		Metadata: map[attr.Name]string{
			attr.K8sNamespaceName: "k8snamespace",
		},
	}

	nr := NameResolver{}

	assert.Equal(t, "service", nr.cleanName(&s, "127.0.0.1", "127-0-0-1.service"))
	assert.Equal(t, "1.service", nr.cleanName(&s, "127.0.0.1", "1.service"))
	assert.Equal(t, "service", nr.cleanName(&s, "127.0.0.1", "service."))
	assert.Equal(t, "service", nr.cleanName(&s, "127.0.0.1", "service.svc.cluster.local."))
	assert.Equal(t, "service", nr.cleanName(&s, "127.0.0.1", "service.special.namespace.svc.cluster.local."))
	assert.Equal(t, "service", nr.cleanName(&s, "127.0.0.1", "service.k8snamespace.svc.cluster.local."))
}

func TestParseK8sFQDN(t *testing.T) {
	tests := []struct {
		name         string
		fqdn         string
		expectedName string
		expectedNS   string
	}{
		{
			name:         "standard K8s FQDN",
			fqdn:         "bar-server.bar-ns.svc.cluster.local",
			expectedName: "bar-server",
			expectedNS:   "bar-ns",
		},
		{
			name:         "with trailing dot",
			fqdn:         "myservice.mynamespace.svc.cluster.local.",
			expectedName: "myservice",
			expectedNS:   "mynamespace",
		},
		{
			name:         "case insensitive suffix",
			fqdn:         "svc.ns.SVC.CLUSTER.LOCAL",
			expectedName: "svc",
			expectedNS:   "ns",
		},
		{
			name:         "just service name (no namespace in FQDN)",
			fqdn:         "myservice.svc.cluster.local",
			expectedName: "myservice",
			expectedNS:   "",
		},
		{
			name:         "not a K8s FQDN - plain hostname",
			fqdn:         "example.com",
			expectedName: "example.com",
			expectedNS:   "",
		},
		{
			name:         "not a K8s FQDN - IP address",
			fqdn:         "10.0.0.1",
			expectedName: "10.0.0.1",
			expectedNS:   "",
		},
		{
			name:         "empty string",
			fqdn:         "",
			expectedName: "",
			expectedNS:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, ns := parseK8sFQDN(tt.fqdn)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedNS, ns)
		})
	}
}

func TestResolveNodesFromK8s(t *testing.T) {
	inf := &fakeInformer{}
	db := kube.NewStore(inf, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
	node1 := &informer.ObjectMeta{Name: "node1", Kind: "Node", Ips: []string{"10.0.0.1", "10.1.0.1"}}
	node2 := &informer.ObjectMeta{Name: "node2", Namespace: "something", Kind: "Node", Ips: []string{"10.0.0.2", "10.1.0.2"}}
	node3 := &informer.ObjectMeta{Name: "node3", Kind: "Node", Ips: []string{"10.0.0.3", "10.1.0.3"}}
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: node1})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: node2})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: node3})

	assert.Equal(t, node1, db.ObjectMetaByIP("10.0.0.1").Meta)
	assert.Equal(t, node1, db.ObjectMetaByIP("10.1.0.1").Meta)
	assert.Equal(t, node2, db.ObjectMetaByIP("10.0.0.2").Meta)
	assert.Equal(t, node2, db.ObjectMetaByIP("10.1.0.2").Meta)
	assert.Equal(t, node3, db.ObjectMetaByIP("10.1.0.3").Meta)
	inf.Notify(&informer.Event{Type: informer.EventType_DELETED, Resource: node3})
	assert.Nil(t, db.ObjectMetaByIP("10.1.0.3"))

	nr := NameResolver{
		db:      db,
		cache:   expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sources: resolverSources([]Source{SourceDNS, SourceK8s}),
	}

	name, namespace, _ := nr.resolveFromK8s("10.0.0.1")
	assert.Equal(t, "node1", name)
	assert.Empty(t, namespace)

	name, namespace, _ = nr.resolveFromK8s("10.0.0.2")
	assert.Equal(t, "node2", name)
	assert.Equal(t, "something", namespace)

	name, namespace, _ = nr.resolveFromK8s("10.0.0.3")
	assert.Empty(t, name)
	assert.Empty(t, namespace)

	clientSpan := request.Span{
		Type: request.EventTypeHTTPClient,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "node1",
			Namespace: "",
		}},
	}

	serverSpan := request.Span{
		Type: request.EventTypeHTTP,
		Peer: "10.0.0.1",
		Host: "10.0.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "node2",
			Namespace: "something",
		}},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "node1", clientSpan.PeerName)
	assert.Empty(t, clientSpan.Service.UID.Namespace)
	assert.Equal(t, "node2", clientSpan.HostName)
	assert.Equal(t, "something", clientSpan.OtherNamespace)

	nr.resolveNames(&serverSpan)

	assert.Equal(t, "node1", serverSpan.PeerName)
	assert.Empty(t, serverSpan.OtherNamespace)
	assert.Equal(t, "node2", serverSpan.HostName)
	assert.Equal(t, "something", serverSpan.Service.UID.Namespace)
}

func TestResolveClientFromHost(t *testing.T) {
	inf := &fakeInformer{}
	db := kube.NewStore(inf, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
	pod1 := &informer.ObjectMeta{Name: "pod1", Kind: "Service", Ips: []string{"10.0.0.1", "10.1.0.1"}}
	pod2 := &informer.ObjectMeta{Name: "pod2", Namespace: "something", Kind: "Service", Ips: []string{"10.0.0.2", "10.1.0.2"}}
	pod3 := &informer.ObjectMeta{Name: "pod3", Kind: "Service", Ips: []string{"10.0.0.3", "10.1.0.3"}}
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod1})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod2})
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod3})

	assert.Equal(t, pod1, db.ObjectMetaByIP("10.0.0.1").Meta)
	assert.Equal(t, pod1, db.ObjectMetaByIP("10.1.0.1").Meta)
	assert.Equal(t, pod2, db.ObjectMetaByIP("10.0.0.2").Meta)
	assert.Equal(t, pod2, db.ObjectMetaByIP("10.1.0.2").Meta)
	assert.Equal(t, pod3, db.ObjectMetaByIP("10.1.0.3").Meta)
	inf.Notify(&informer.Event{Type: informer.EventType_DELETED, Resource: pod3})
	assert.Nil(t, db.ObjectMetaByIP("10.1.0.3"))

	nr := NameResolver{
		db:      db,
		cache:   expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sources: resolverSources([]Source{SourceK8s}),
	}

	name, namespace, k8sNamespace := nr.resolveFromK8s("10.0.0.1")
	assert.Equal(t, "pod1", name)
	assert.Empty(t, namespace)
	assert.Empty(t, k8sNamespace)

	name, namespace, k8sNamespace = nr.resolveFromK8s("10.0.0.2")
	assert.Equal(t, "pod2", name)
	assert.Equal(t, "something", namespace)
	assert.Equal(t, "something", k8sNamespace)

	name, namespace, k8sNamespace = nr.resolveFromK8s("10.0.0.3")
	assert.Empty(t, name)
	assert.Empty(t, namespace)
	assert.Empty(t, k8sNamespace)

	clientSpan := request.Span{
		Type:      request.EventTypeHTTPClient,
		Peer:      "10.10.0.1",
		Statement: "https;github.com",
		Host:      "10.10.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "pod1",
			Namespace: "",
		}},
	}

	serverSpan := request.Span{
		Type:      request.EventTypeHTTP,
		Peer:      "10.10.0.1",
		Statement: "https;github.com",
		Host:      "10.10.0.2",
		Service: svc.Attrs{UID: svc.UID{
			Name:      "pod2",
			Namespace: "something",
		}},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "pod1", clientSpan.PeerName) // we don't match the IP in k8s, but we have a service name
	assert.Empty(t, clientSpan.Service.UID.Namespace)
	assert.Equal(t, "github.com", clientSpan.HostName)
	assert.Empty(t, clientSpan.OtherNamespace)

	nr.resolveNames(&serverSpan)

	assert.Equal(t, "10.10.0.1", serverSpan.PeerName)
	assert.Empty(t, serverSpan.OtherNamespace)
	assert.Equal(t, "pod2", serverSpan.HostName) // we don't match the IP in k8s, but we have a service name
	assert.Equal(t, "something", serverSpan.Service.UID.Namespace)
}

// TestResolveClientFromHost_K8sFQDN demonstrates the following scenario:
//   - A client (foo-client) makes an HTTP request to a K8s Service (bar-server)
//   - The destination IP seen by eBPF is the Pod IP (after kube-proxy NAT)
//   - The Pod IP is not in the K8s informer cache
//   - The HTTP Host header contains the K8s Service FQDN
func TestResolveClientFromHost_K8sFQDN(t *testing.T) {
	// Create a K8s store with NO matching entries for the destination Pod IP
	// This simulates the case where the Pod IP can't be resolved via K8s metadata
	inf := &fakeInformer{}
	db := kube.NewStore(inf, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})

	// Add only the source pod to the store, not the destination
	sourcePod := &informer.ObjectMeta{
		Name:      "foo-client-abc123",
		Namespace: "foo-ns",
		Kind:      "Pod",
		Ips:       []string{"10.0.1.1"},
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{{Kind: "Deployment", Name: "foo-client"}},
		},
	}
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: sourcePod})

	// The destination Pod IP (10.0.2.5) is NOT in the store
	// This simulates the NAT scenario where we see the Pod IP but can't resolve it
	nr := NameResolver{
		db:      db,
		cache:   expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sources: resolverSources([]Source{SourceK8s}),
	}

	// Create a client span representing an HTTP call to a K8s Service
	// The HTTP Host header contains the K8s Service FQDN
	clientSpan := request.Span{
		Type: request.EventTypeHTTPClient,
		Peer: "10.0.1.1",
		// Destination: Pod IP after NAT (NOT in K8s store)
		Host: "10.0.2.5",
		// HTTP Host header captured by eBPF, stored as "scheme;host"
		Statement: "http;bar-server.bar-ns.svc.cluster.local",
		Service: svc.Attrs{
			UID: svc.UID{
				Name:      "foo-client",
				Namespace: "foo-ns",
			},
		},
	}

	nr.resolveNames(&clientSpan)

	assert.Equal(t, "bar-server", clientSpan.HostName)
	assert.Equal(t, "bar-ns", clientSpan.OtherNamespace)
}

func TestPreserveBPFHostnameWhenResolutionFails(t *testing.T) {
	inf := &fakeInformer{}
	db := kube.NewStore(inf, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})

	nr := NameResolver{
		db:      db,
		cache:   expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sources: resolverSources([]Source{SourceK8s}),
		logger:  nrlog(),
	}

	sqlClientSpan := request.Span{
		Type:     request.EventTypeSQLClient,
		Peer:     "10.0.1.1",
		Host:     "172.18.0.5",
		HostName: "mysqlserver",
		Service: svc.Attrs{
			UID: svc.UID{
				Name:      "myapp",
				Namespace: "default",
			},
		},
	}

	nr.resolveNames(&sqlClientSpan)

	assert.Equal(t, "mysqlserver", sqlClientSpan.HostName)
	assert.Empty(t, sqlClientSpan.OtherNamespace)
}

func TestResolver(t *testing.T) {
	inf := &fakeInformer{}
	db := kube.NewStore(inf, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})

	pod := &informer.ObjectMeta{
		Name:      "resolved-pod",
		Namespace: "test-ns",
		Kind:      "Pod",
		Ips:       []string{"10.0.0.100"},
	}
	inf.Notify(&informer.Event{Type: informer.EventType_CREATED, Resource: pod})

	nr := NameResolver{
		db:      db,
		cache:   expirable.NewLRU[string, string](10, nil, 5*time.Hour),
		sources: resolverSources([]Source{SourceK8s, SourceDNS, SourceRDNS}),
		logger:  nrlog(),
	}

	svcAttrs := svc.Attrs{
		UID: svc.UID{
			Name:      "test-service",
			Namespace: "default",
		},
	}

	tests := []struct {
		name              string
		ip                string
		fallback          string
		expectedName      string
		expectedNamespace string
	}{
		{
			name:              "resolution fails with fallback",
			ip:                "10.0.0.99",
			fallback:          "fallback-hostname",
			expectedName:      "fallback-hostname",
			expectedNamespace: "default",
		},
		{
			name:              "resolution fails without fallback",
			ip:                "10.0.0.99",
			fallback:          "",
			expectedName:      "10.0.0.99",
			expectedNamespace: "default",
		},
		{
			name:              "k8s resolution overrides fallback",
			ip:                "10.0.0.100",
			fallback:          "fallback-hostname",
			expectedName:      "resolved-pod",
			expectedNamespace: "test-ns",
		},
		{
			name:              "k8s resolution without fallback",
			ip:                "10.0.0.100",
			fallback:          "",
			expectedName:      "resolved-pod",
			expectedNamespace: "test-ns",
		},
		{
			name:              "empty ip with fallback",
			ip:                "",
			fallback:          "fallback-hostname",
			expectedName:      "fallback-hostname",
			expectedNamespace: "",
		},
		{
			name:              "empty ip without fallback",
			ip:                "",
			fallback:          "",
			expectedName:      "",
			expectedNamespace: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, ns, _ := nr.resolve(&svcAttrs, tt.ip, tt.fallback)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedNamespace, ns)
		})
	}
}
