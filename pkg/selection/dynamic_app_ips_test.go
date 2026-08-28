// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection

import (
	"net"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

type stubPIDSelector struct {
	pids    []app.PID
	addedCh chan []app.PID
	removed chan []app.PID
}

func (s *stubPIDSelector) GetPIDs() ([]app.PID, bool) {
	if len(s.pids) == 0 {
		return nil, false
	}
	out := make([]app.PID, len(s.pids))
	copy(out, s.pids)
	return out, true
}

func (s *stubPIDSelector) IncludesPID(pid app.PID) bool {
	return slices.Contains(s.pids, pid)
}

func (s *stubPIDSelector) AddedPIDsNotify() <-chan []app.PID { return s.addedCh }
func (s *stubPIDSelector) RemovedNotify() <-chan []app.PID   { return s.removed }

func stubIsolatedProcessIPs(t *testing.T, ipsFor func(app.PID) []string) {
	t.Helper()
	orig := processIPs
	t.Cleanup(func() { processIPs = orig })
	processIPs = ipsFor
}

// container.IPsForPID yields no addresses for a process sharing the host or agent
// network namespace, whether because the namespace is not isolated or because the
// isolation check itself failed.
func stubSharedHostNetNS(t *testing.T) {
	t.Helper()
	stubIsolatedProcessIPs(t, func(app.PID) []string { return nil })
}

// fakeInformer is a meta.Notifier that never publishes anything, so a store built on it
// knows no pods.
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

func newTestKubeStore(t *testing.T) *kube.Store {
	t.Helper()
	return kube.NewStore(&fakeInformer{}, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
}

func TestResolveContainerIPs_netnsFallbackWithoutStore(t *testing.T) {
	stubIsolatedProcessIPs(t, func(pid app.PID) []string {
		assert.Equal(t, app.PID(7), pid)
		return []string{"172.17.0.3", "fd00::a"}
	})

	assert.Equal(t, []string{"172.17.0.3", "fd00::a"}, ResolveContainerIPs(nil, 7))
}

func TestResolveContainerIPs_sharedHostNetNSReturnsNoIPs(t *testing.T) {
	stubSharedHostNetNS(t)
	assert.Empty(t, ResolveContainerIPs(nil, 7))
}

// Host addresses are only usable as identity off Kubernetes. A Kubernetes deployment must
// resolve identity from pod metadata alone, so a PID the store knows nothing about resolves
// to no IPs rather than to whatever its namespace happens to expose.
func TestResolveContainerIPs_withStoreNeverUsesNetNS(t *testing.T) {
	stubIsolatedProcessIPs(t, func(app.PID) []string {
		t.Error("processIPs must not run when a Kubernetes store is configured")
		return []string{"192.168.1.10"}
	})

	assert.Empty(t, ResolveContainerIPs(newTestKubeStore(t), app.PID(os.Getpid())))
}

func TestDynamicAppIPs_withStore_doesNotAdmitTrafficForUnknownPID(t *testing.T) {
	stubIsolatedProcessIPs(t, func(app.PID) []string {
		t.Error("processIPs must not run when a Kubernetes store is configured")
		return []string{"192.168.1.10"}
	})

	pid := app.PID(os.Getpid())
	sel := &stubPIDSelector{pids: []app.PID{pid}}
	tracker := NewDynamicAppIPs(sel, newTestKubeStore(t))
	tracker.addBatch([]app.PID{pid})

	host := pipe.IPAddr(net.ParseIP("192.168.1.10"))
	other := pipe.IPAddr(net.ParseIP("8.8.8.8"))
	assert.False(t, tracker.Allows(&pipe.CommonAttrs{SrcAddr: host, DstAddr: other}))
}

func TestDynamicAppIPs_addBatch_usesResolvedIPs(t *testing.T) {
	stubIsolatedProcessIPs(t, func(pid app.PID) []string {
		if pid == 99 {
			return []string{"10.1.1.5"}
		}
		return nil
	})

	sel := &stubPIDSelector{pids: []app.PID{99}}
	tracker := NewDynamicAppIPs(sel, nil)
	tracker.addBatch([]app.PID{99})

	src := pipe.IPAddr(net.ParseIP("10.1.1.5"))
	dst := pipe.IPAddr(net.ParseIP("10.2.2.2"))
	assert.True(t, tracker.Allows(&pipe.CommonAttrs{SrcAddr: src, DstAddr: dst}))
}

func TestDynamicAppIPs_sharedHostNetNS_doesNotAdmitUnselectedHostTraffic(t *testing.T) {
	stubSharedHostNetNS(t)

	sel := &stubPIDSelector{pids: []app.PID{100}}
	tracker := NewDynamicAppIPs(sel, nil)
	tracker.addBatch([]app.PID{100})

	host := pipe.IPAddr(net.ParseIP("192.168.1.10"))
	other := pipe.IPAddr(net.ParseIP("8.8.8.8"))
	assert.False(t, tracker.Allows(&pipe.CommonAttrs{SrcAddr: host, DstAddr: other}))
}

func TestDynamicAppIPs_twoSelectedInSharedNetNS_neitherGetsHostIPs(t *testing.T) {
	stubSharedHostNetNS(t)

	sel := &stubPIDSelector{pids: []app.PID{10, 20}}
	tracker := NewDynamicAppIPs(sel, nil)
	tracker.addBatch([]app.PID{10, 20})

	host := pipe.IPAddr(net.ParseIP("192.168.1.10"))
	other := pipe.IPAddr(net.ParseIP("8.8.8.8"))
	assert.False(t, tracker.Allows(&pipe.CommonAttrs{SrcAddr: host, DstAddr: other}))
}

func TestDynamicAppIPs_twoIsolatedNetNS_eachKeepsOwnIP(t *testing.T) {
	stubIsolatedProcessIPs(t, func(pid app.PID) []string {
		switch pid {
		case 10:
			return []string{"172.17.0.2"}
		case 20:
			return []string{"172.17.0.3"}
		}
		return nil
	})

	sel := &stubPIDSelector{pids: []app.PID{10, 20}}
	tracker := NewDynamicAppIPs(sel, nil)
	tracker.addBatch([]app.PID{10, 20})

	dst := pipe.IPAddr(net.ParseIP("8.8.8.8"))
	assert.True(t, tracker.Allows(&pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("172.17.0.2")),
		DstAddr: dst,
	}))
	assert.True(t, tracker.Allows(&pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("172.17.0.3")),
		DstAddr: dst,
	}))
	assert.False(t, tracker.Allows(&pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("192.168.1.10")),
		DstAddr: dst,
	}))
}

func TestDynamicAppIPs_Allows_emptySelectorBlocks(t *testing.T) {
	sel := &stubPIDSelector{}
	tracker := NewDynamicAppIPs(sel, nil)

	attrs := &pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("10.0.0.1")),
		DstAddr: pipe.IPAddr(net.ParseIP("10.0.0.2")),
	}
	assert.False(t, tracker.Allows(attrs))

	sel.pids = []app.PID{42}
	assert.False(t, tracker.Allows(attrs))
}

func TestDynamicAppIPs_Allows_matchingIP(t *testing.T) {
	sel := &stubPIDSelector{pids: []app.PID{99}}
	tracker := NewDynamicAppIPs(sel, nil)
	tracker.addBatch([]app.PID{99})
	tracker.mu.Lock()
	tracker.pidToIPs[99] = []string{"10.1.1.5"}
	tracker.allowedIPs["10.1.1.5"] = 1
	tracker.mu.Unlock()

	src := pipe.IPAddr(net.ParseIP("10.1.1.5"))
	dst := pipe.IPAddr(net.ParseIP("10.2.2.2"))
	assert.True(t, tracker.Allows(&pipe.CommonAttrs{SrcAddr: src, DstAddr: dst}))
	assert.False(t, tracker.Allows(&pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("10.3.3.3")),
		DstAddr: dst,
	}))
}

func TestDynamicAppIPs_removeBatch(t *testing.T) {
	sel := &stubPIDSelector{pids: []app.PID{1}}
	tracker := NewDynamicAppIPs(sel, nil)
	tracker.mu.Lock()
	tracker.pidToIPs[1] = []string{"10.0.0.1"}
	tracker.allowedIPs["10.0.0.1"] = 1
	tracker.mu.Unlock()

	tracker.removeBatch([]app.PID{1})
	pids, ok := sel.GetPIDs()
	require.True(t, ok)
	require.Equal(t, []app.PID{1}, pids)

	attrs := &pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("10.0.0.1")),
		DstAddr: pipe.IPAddr(net.ParseIP("10.0.0.2")),
	}
	assert.False(t, tracker.Allows(attrs))
}

func TestDynamicAppIPs_sharedPodIP(t *testing.T) {
	sel := &stubPIDSelector{pids: []app.PID{1, 2}}
	tracker := NewDynamicAppIPs(sel, nil)

	tracker.mu.Lock()
	tracker.pidToIPs[1] = []string{"10.0.0.5"}
	tracker.pidToIPs[2] = []string{"10.0.0.5"}
	tracker.allowedIPs["10.0.0.5"] = 2
	tracker.mu.Unlock()

	attrs := &pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("10.0.0.5")),
		DstAddr: pipe.IPAddr(net.ParseIP("10.0.0.9")),
	}
	assert.True(t, tracker.Allows(attrs))

	tracker.removeBatch([]app.PID{1})
	assert.True(t, tracker.Allows(attrs))

	tracker.removeBatch([]app.PID{2})
	assert.False(t, tracker.Allows(attrs))
}
