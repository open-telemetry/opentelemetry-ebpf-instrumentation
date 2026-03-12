// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cidr

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const testTimeout = 5 * time.Second

type testRecord struct {
	pipe.CommonAttrs
}

func TestCIDRDecorator(t *testing.T) {
	input := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	defer input.Close()
	outputQu := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := outputQu.Subscribe()
	grouper, err := DecoratorProvider([]string{
		"10.0.0.0/8",
		"10.1.2.0/24",
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	}, func(r *testRecord) *pipe.CommonAttrs { return &r.CommonAttrs },
		input, outputQu)(t.Context())
	require.NoError(t, err)
	go grouper(t.Context())
	input.Send([]*testRecord{
		flow("10.3.4.5", "10.1.2.3"),
		flow("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		flow("140.130.22.11", "140.130.23.11"),
		flow("180.130.22.11", "10.1.2.4"),
	})
	decorated := testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, decorated, 4)
	assert.Equal(t, "10.0.0.0/8", decorated[0].Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[0].Metadata["dst.cidr"])
	assert.Equal(t, "2001:db8:3c4d:15::/64", decorated[1].Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", decorated[1].Metadata["dst.cidr"])
	assert.Equal(t, "140.130.22.0/24", decorated[2].Metadata["src.cidr"])
	assert.Empty(t, decorated[2].Metadata["dst.cidr"])
	assert.Empty(t, decorated[3].Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[3].Metadata["dst.cidr"])
}

func TestCIDRDecorator_GroupAllUnknownTraffic(t *testing.T) {
	input := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	defer input.Close()
	outputQu := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := outputQu.Subscribe()
	grouper, err := DecoratorProvider([]string{
		"10.0.0.0/8",
		"10.1.2.0/24",
		"0.0.0.0/0", // this entry will capture all the unknown traffic
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	}, func(r *testRecord) *pipe.CommonAttrs { return &r.CommonAttrs },
		input, outputQu)(t.Context())
	require.NoError(t, err)
	go grouper(t.Context())
	input.Send([]*testRecord{
		flow("10.3.4.5", "10.1.2.3"),
		flow("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		flow("140.130.22.11", "140.130.23.11"),
		flow("180.130.22.11", "10.1.2.4"),
	})
	decorated := testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, decorated, 4)
	assert.Equal(t, "10.0.0.0/8", decorated[0].Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[0].Metadata["dst.cidr"])
	assert.Equal(t, "2001:db8:3c4d:15::/64", decorated[1].Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", decorated[1].Metadata["dst.cidr"])
	assert.Equal(t, "140.130.22.0/24", decorated[2].Metadata["src.cidr"])
	assert.Equal(t, "0.0.0.0/0", decorated[2].Metadata["dst.cidr"])
	assert.Equal(t, "0.0.0.0/0", decorated[3].Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[3].Metadata["dst.cidr"])
}

func flow(srcIP, dstIP string) *testRecord {
	r := &testRecord{}
	copy(r.SrcAddr[:], net.ParseIP(srcIP).To16())
	copy(r.DstAddr[:], net.ParseIP(dstIP).To16())
	return r
}
