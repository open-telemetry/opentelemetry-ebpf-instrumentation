// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/netolly/flow/transport"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

var (
	tcp1  = ebpf.NewRecord(ebpf.NetFlowId{TransportProtocol: uint8(transport.TCP), SrcPort: 1}, ebpf.NetFlowMetrics{})
	tcp2  = ebpf.NewRecord(ebpf.NetFlowId{TransportProtocol: uint8(transport.TCP), SrcPort: 2}, ebpf.NetFlowMetrics{})
	tcp3  = ebpf.NewRecord(ebpf.NetFlowId{TransportProtocol: uint8(transport.TCP), SrcPort: 3}, ebpf.NetFlowMetrics{})
	udp1  = ebpf.NewRecord(ebpf.NetFlowId{TransportProtocol: uint8(transport.UDP), SrcPort: 4}, ebpf.NetFlowMetrics{})
	udp2  = ebpf.NewRecord(ebpf.NetFlowId{TransportProtocol: uint8(transport.UDP), SrcPort: 5}, ebpf.NetFlowMetrics{})
	icmp1 = ebpf.NewRecord(ebpf.NetFlowId{TransportProtocol: uint8(transport.ICMP), SrcPort: 7}, ebpf.NetFlowMetrics{})
	icmp2 = ebpf.NewRecord(ebpf.NetFlowId{TransportProtocol: uint8(transport.ICMP), SrcPort: 8}, ebpf.NetFlowMetrics{})
	icmp3 = ebpf.NewRecord(ebpf.NetFlowId{TransportProtocol: uint8(transport.ICMP), SrcPort: 9}, ebpf.NetFlowMetrics{})
)

func TestProtocolFilter_Allow(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	defer input.Close()
	outputQu := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	output := outputQu.Subscribe()
	protocolFilter, err := ProtocolFilterProvider([]string{"TCP"}, nil, input, outputQu)(t.Context())
	require.NoError(t, err)
	go protocolFilter(t.Context())

	input.Send([]*ebpf.Record{})
	input.Send([]*ebpf.Record{tcp1, tcp2, tcp3})
	input.Send([]*ebpf.Record{icmp2, udp1, icmp1, udp2, icmp3})
	input.Send([]*ebpf.Record{icmp2, tcp1, udp1, icmp1, tcp2, udp2, tcp3, icmp3})

	filtered := testutil.ReadChannel(t, output, timeout)
	assert.Equal(t, []*ebpf.Record{tcp1, tcp2, tcp3}, filtered)
	filtered = testutil.ReadChannel(t, output, timeout)
	assert.Equal(t, []*ebpf.Record{tcp1, tcp2, tcp3}, filtered)
	// no more slices are sent (the second was completely filtered)
	select {
	case o := <-output:
		require.Failf(t, "unexpected flows!", "%v", o)
	default:
		// ok!!
	}
}

func TestProtocolFilter_Exclude(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	defer input.Close()
	outputQu := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	output := outputQu.Subscribe()
	protocolFilter, err := ProtocolFilterProvider(nil, []string{"TCP"}, input, outputQu)(t.Context())
	require.NoError(t, err)
	go protocolFilter(t.Context())

	input.Send([]*ebpf.Record{tcp1, tcp2, tcp3})
	input.Send([]*ebpf.Record{icmp2, udp1, icmp1, udp2, icmp3})
	input.Send([]*ebpf.Record{})
	input.Send([]*ebpf.Record{icmp2, tcp1, udp1, icmp1, tcp2, udp2, tcp3, icmp3})

	filtered := testutil.ReadChannel(t, output, timeout)
	assert.Equal(t, []*ebpf.Record{icmp2, udp1, icmp1, udp2, icmp3}, filtered)
	filtered = testutil.ReadChannel(t, output, timeout)
	assert.Equal(t, []*ebpf.Record{icmp2, udp1, icmp1, udp2, icmp3}, filtered)
	// no more slices are sent (the first was completely filtered)
	select {
	case o := <-output:
		require.Failf(t, "unexpected flows!", "%v", o)
	default:
		// ok!!
	}
}

func TestProtocolFilter_ParsingErrors(t *testing.T) {
	_, err := ProtocolFilterProvider([]string{"TCP", "tralara"}, nil, nil, nil)(t.Context())
	require.Error(t, err)
	_, err = ProtocolFilterProvider([]string{"TCP", "tralara"}, []string{"UDP"}, nil, nil)(t.Context())
	require.Error(t, err)
	_, err = ProtocolFilterProvider(nil, []string{"TCP", "tralara"}, nil, nil)(t.Context())
	require.Error(t, err)
}
