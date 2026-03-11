// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const timeout = 5 * time.Second

func TestDecoration(t *testing.T) {
	// Given a flow Decorator node
	in := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	go Decorate(func(n int) string {
		return fmt.Sprintf("eth%d", n)
	}, in, out)(t.Context())

	// When it receives flows
	f1 := &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{IfIndex: 1},
	}}
	f2 := &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{IfIndex: 2},
	}}

	in.Send([]*ebpf.Record{f1, f2})

	// THEN it decorates them with the interface name
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 2)

	assert.Equal(t, "eth1", decorated[0].NetAttrs.Interface)
	assert.Equal(t, "eth2", decorated[1].NetAttrs.Interface)
}
