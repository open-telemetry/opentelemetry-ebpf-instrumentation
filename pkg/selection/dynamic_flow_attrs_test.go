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
