// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
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

func (s *stubPIDSelector) AddedPIDsNotify() <-chan []app.PID { return s.addedCh }
func (s *stubPIDSelector) RemovedNotify() <-chan []app.PID   { return s.removed }

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
