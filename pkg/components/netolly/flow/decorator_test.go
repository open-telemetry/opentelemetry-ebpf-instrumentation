// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
)

func TestDecoration(t *testing.T) {
	srcIP := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4}
	dstIP := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 4, 3, 2, 1}

	ifaceNamer := func(n int) string {
		return fmt.Sprintf("eth%d", n)
	}

	agentIP := "3.3.3.3"

	decorate := FlowDecorator(agentIP, ifaceNamer)

	f1 := ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id:      ebpf.NetFlowIdT{IfIndex: 1},
		Metrics: ebpf.NetFlowMetricsT{IfaceDirection: 1, StartDirection: 1},
	}, Attrs: ebpf.RecordAttrs{Src: ebpf.InnerAttrs{TargetName: "source"}}}
	f1.Id.LocalIp.In6U.U6Addr8 = srcIP
	f1.Id.RemoteIp.In6U.U6Addr8 = dstIP

	f2 := ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id:      ebpf.NetFlowIdT{IfIndex: 2},
		Metrics: ebpf.NetFlowMetricsT{IfaceDirection: 1, StartDirection: 1},
	}, Attrs: ebpf.RecordAttrs{Dst: ebpf.InnerAttrs{TargetName: "destination"}}}
	f2.Id.LocalIp.In6U.U6Addr8 = srcIP
	f2.Id.RemoteIp.In6U.U6Addr8 = dstIP

	// decorates the flows, by adding IPs to source/destination
	// names only when they were missing
	decorate(&f1)
	decorate(&f2)

	assert.Equal(t, "eth1", f1.Attrs.Interface)
	assert.Equal(t, "3.3.3.3", f1.Attrs.OBIIP)
	assert.Equal(t, "source", f1.Attrs.Src.TargetName)
	assert.Equal(t, "4.3.2.1", f1.Attrs.Dst.TargetName)

	assert.Equal(t, "eth2", f2.Attrs.Interface)
	assert.Equal(t, "3.3.3.3", f2.Attrs.OBIIP)
	assert.Equal(t, "1.2.3.4", f2.Attrs.Src.TargetName)
	assert.Equal(t, "destination", f2.Attrs.Dst.TargetName)
}
