// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const timeout = 5 * time.Second

func TestDecoration(t *testing.T) {
	srcIP := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4}
	dstIP := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 4, 3, 2, 1}

	// Given a flow Decorator node
	in := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	go Decorate(net.IPv4(3, 3, 3, 3), func(n int) string {
		return fmt.Sprintf("eth%d", n)
	}, in, out)(t.Context())

	// When it receives flows
	f1 := &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{IfIndex: 1},
	}, CommonAttrs: pipe.CommonAttrs{SrcName: "source"}}
	f1.CommonAttrs.SrcAddr = pipe.IPAddr(srcIP)
	f1.CommonAttrs.DstAddr = pipe.IPAddr(dstIP)

	f2 := &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{IfIndex: 2},
	}, CommonAttrs: pipe.CommonAttrs{DstName: "destination"}}
	f2.CommonAttrs.SrcAddr = pipe.IPAddr(srcIP)
	f2.CommonAttrs.DstAddr = pipe.IPAddr(dstIP)

	in.Send([]*ebpf.Record{f1, f2})

	// THEN it decorates them, by adding IPs to source/destination
	// names only when they were missing
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 2)

	assert.Equal(t, "eth1", decorated[0].NetAttrs.Interface)
	assert.Equal(t, "3.3.3.3", decorated[0].CommonAttrs.OBIIP)
	assert.Equal(t, "source", decorated[0].CommonAttrs.SrcName)
	assert.Equal(t, "4.3.2.1", decorated[0].CommonAttrs.DstName)

	assert.Equal(t, "eth2", decorated[1].NetAttrs.Interface)
	assert.Equal(t, "3.3.3.3", decorated[1].CommonAttrs.OBIIP)
	assert.Equal(t, "1.2.3.4", decorated[1].CommonAttrs.SrcName)
	assert.Equal(t, "destination", decorated[1].CommonAttrs.DstName)
}
