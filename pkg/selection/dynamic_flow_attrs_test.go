// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
)

type stubMultiPIDSelector struct {
	stubPIDSelector
	entries     map[app.PID]DynamicPIDEntry
	attrsUpdate chan app.PID
}

func (s *stubMultiPIDSelector) AddPID(uint32, DynamicPIDOptions) {}
func (s *stubMultiPIDSelector) AddPIDs(...uint32)                {}
func (s *stubMultiPIDSelector) RemovePIDs(...uint32)             {}
func (s *stubMultiPIDSelector) Traces() MutablePIDSelector       { return s }
func (s *stubMultiPIDSelector) AppMetrics() MutablePIDSelector   { return s }
func (s *stubMultiPIDSelector) NetworkMetrics() MutablePIDSelector {
	return s
}
func (s *stubMultiPIDSelector) StatsMetrics() MutablePIDSelector { return s }

func (s *stubMultiPIDSelector) GetPID(pid uint32) (DynamicPIDEntry, bool) {
	entry, ok := s.entries[app.PID(pid)]
	return entry, ok
}

func (s *stubMultiPIDSelector) SetPID(entry DynamicPIDEntry) bool {
	if s.entries == nil {
		s.entries = map[app.PID]DynamicPIDEntry{}
	}
	if _, ok := s.entries[entry.PID]; !ok {
		return false
	}
	s.entries[entry.PID] = entry
	return true
}

func (s *stubMultiPIDSelector) AttrsUpdatedNotify() <-chan app.PID {
	if s.attrsUpdate == nil {
		s.attrsUpdate = make(chan app.PID, 1)
	}
	return s.attrsUpdate
}

func TestDynamicFlowAttrs_Apply_srcAndDst(t *testing.T) {
	sel := &stubMultiPIDSelector{
		stubPIDSelector: stubPIDSelector{pids: []app.PID{42}},
		entries: map[app.PID]DynamicPIDEntry{
			42: {
				PID:              42,
				ServiceName:      "payments",
				ServiceNamespace: "prod",
			},
		},
	}
	tracker := NewDynamicFlowAttrs(sel, sel, nil)
	tracker.mu.Lock()
	tracker.ipDecor["10.0.0.5"] = decorationFromEntry(sel.entries[42])
	tracker.mu.Unlock()

	srcFlow := &pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("10.0.0.5")),
		DstAddr: pipe.IPAddr(net.ParseIP("10.0.0.9")),
	}
	tracker.Apply(srcFlow)
	require.NotNil(t, srcFlow.Metadata)
	assert.Equal(t, "payments", srcFlow.Metadata[attr.ServiceName])
	assert.Equal(t, "prod", srcFlow.Metadata[attr.ServiceNamespace])

	dstFlow := &pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("10.0.0.9")),
		DstAddr: pipe.IPAddr(net.ParseIP("10.0.0.5")),
	}
	tracker.Apply(dstFlow)
	require.NotNil(t, dstFlow.Metadata)
	assert.Equal(t, "payments", dstFlow.Metadata[attr.ServicePeerName])
	assert.Equal(t, "prod", dstFlow.Metadata[attr.ServicePeerNamespace])
}

func TestDynamicFlowAttrs_rebuild_clearsWhenEmpty(t *testing.T) {
	sel := &stubMultiPIDSelector{
		stubPIDSelector: stubPIDSelector{pids: []app.PID{1}},
		entries: map[app.PID]DynamicPIDEntry{
			1: {PID: 1, ServiceName: "a"},
		},
	}
	tracker := NewDynamicFlowAttrs(sel, sel, nil)
	tracker.mu.Lock()
	tracker.ipDecor["10.0.0.1"] = flowIPDecoration{serviceName: "old"}
	tracker.registeredPIDs[1] = struct{}{}
	tracker.mu.Unlock()

	sel.pids = nil
	tracker.rebuild()

	tracker.mu.RLock()
	assert.Empty(t, tracker.ipDecor)
	assert.Empty(t, tracker.registeredPIDs)
	tracker.mu.RUnlock()
}

func TestDynamicFlowAttrs_rebuild_doesNotTrackPIDWithoutDecoration(t *testing.T) {
	sel := &stubMultiPIDSelector{
		stubPIDSelector: stubPIDSelector{pids: []app.PID{1, 2}},
		entries: map[app.PID]DynamicPIDEntry{
			1: {PID: 1, ServiceName: "a"},
			2: {PID: 2},
		},
	}
	tracker := NewDynamicFlowAttrs(sel, sel, nil)
	tracker.mu.Lock()
	tracker.registeredPIDs[2] = struct{}{}
	tracker.mu.Unlock()

	tracker.rebuild()

	tracker.mu.RLock()
	assert.Empty(t, tracker.registeredPIDs)
	tracker.mu.RUnlock()
}

func TestDynamicFlowAttrs_rebuild_netnsFallbackWithoutStore(t *testing.T) {
	stubIsolatedProcessIPs(t, func(pid app.PID) []string {
		if pid == 42 {
			return []string{"10.0.0.5"}
		}
		return nil
	})

	sel := &stubMultiPIDSelector{
		stubPIDSelector: stubPIDSelector{pids: []app.PID{42}},
		entries: map[app.PID]DynamicPIDEntry{
			42: {PID: 42, ServiceName: "coupon", ServiceNamespace: "demo"},
		},
	}
	tracker := NewDynamicFlowAttrs(sel, sel, nil)
	tracker.rebuild()

	tracker.mu.RLock()
	dec, ok := tracker.ipDecor["10.0.0.5"]
	assert.Empty(t, tracker.registeredPIDs) // no kube store → no DeleteProcess tracking
	tracker.mu.RUnlock()

	require.True(t, ok)
	assert.Equal(t, "coupon", dec.serviceName)
	assert.Equal(t, "demo", dec.serviceNamespace)
}

func TestDynamicFlowAttrs_rebuild_sharedHostNetNS_doesNotDecorate(t *testing.T) {
	stubSharedHostNetNS(t)

	sel := &stubMultiPIDSelector{
		stubPIDSelector: stubPIDSelector{pids: []app.PID{100}},
		entries: map[app.PID]DynamicPIDEntry{
			100: {PID: 100, ServiceName: "sshd"},
		},
	}
	tracker := NewDynamicFlowAttrs(sel, sel, nil)
	tracker.rebuild()

	flow := &pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("192.168.1.10")),
		DstAddr: pipe.IPAddr(net.ParseIP("8.8.8.8")),
	}
	tracker.Apply(flow)
	assert.Nil(t, flow.Metadata)
}

func TestDynamicFlowAttrs_rebuild_twoSelectedSharedNetNS_noLastWriterWins(t *testing.T) {
	stubSharedHostNetNS(t)

	sel := &stubMultiPIDSelector{
		stubPIDSelector: stubPIDSelector{pids: []app.PID{10, 20}},
		entries: map[app.PID]DynamicPIDEntry{
			10: {PID: 10, ServiceName: "sshd"},
			20: {PID: 20, ServiceName: "nginx"},
		},
	}
	tracker := NewDynamicFlowAttrs(sel, sel, nil)
	tracker.rebuild()

	tracker.mu.RLock()
	assert.Empty(t, tracker.ipDecor)
	tracker.mu.RUnlock()

	flow := &pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("192.168.1.10")),
		DstAddr: pipe.IPAddr(net.ParseIP("8.8.8.8")),
	}
	tracker.Apply(flow)
	assert.Nil(t, flow.Metadata)
}

func TestDynamicFlowAttrs_rebuild_twoIsolatedNetNS_eachKeepsOwnAttrs(t *testing.T) {
	stubIsolatedProcessIPs(t, func(pid app.PID) []string {
		switch pid {
		case 1:
			return []string{"172.17.0.2"}
		case 2:
			return []string{"172.17.0.3"}
		}
		return nil
	})

	sel := &stubMultiPIDSelector{
		stubPIDSelector: stubPIDSelector{pids: []app.PID{1, 2}},
		entries: map[app.PID]DynamicPIDEntry{
			1: {PID: 1, ServiceName: "payments"},
			2: {PID: 2, ServiceName: "checkout"},
		},
	}
	tracker := NewDynamicFlowAttrs(sel, sel, nil)
	tracker.rebuild()

	payments := &pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("172.17.0.2")),
		DstAddr: pipe.IPAddr(net.ParseIP("8.8.8.8")),
	}
	tracker.Apply(payments)
	require.NotNil(t, payments.Metadata)
	assert.Equal(t, "payments", payments.Metadata[attr.ServiceName])

	checkout := &pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(net.ParseIP("172.17.0.3")),
		DstAddr: pipe.IPAddr(net.ParseIP("8.8.8.8")),
	}
	tracker.Apply(checkout)
	require.NotNil(t, checkout.Metadata)
	assert.Equal(t, "checkout", checkout.Metadata[attr.ServiceName])
}
