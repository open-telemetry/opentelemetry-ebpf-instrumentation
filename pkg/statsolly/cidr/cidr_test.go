// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cidr

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const testTimeout = 5 * time.Second

func TestCIDRDecorator(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(100))
	defer input.Close()
	outputQu := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(100))
	outCh := outputQu.Subscribe()
	grouper, err := DecoratorProvider([]string{
		"10.0.0.0/8",
		"10.1.2.0/24",
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	}, input, outputQu)(t.Context())
	require.NoError(t, err)
	go grouper(t.Context())
	input.Send([]*ebpf.Stat{
		stat("10.3.4.5", "10.1.2.3"),
		stat("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		stat("140.130.22.11", "140.130.23.11"),
		stat("180.130.22.11", "10.1.2.4"),
	})
	decorated := testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, decorated, 4)
	assert.Equal(t, "10.0.0.0/8", decorated[0].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[0].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "2001:db8:3c4d:15::/64", decorated[1].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", decorated[1].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "140.130.22.0/24", decorated[2].Attrs.Metadata["src.cidr"])
	assert.Empty(t, decorated[2].Attrs.Metadata["dst.cidr"])
	assert.Empty(t, decorated[3].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[3].Attrs.Metadata["dst.cidr"])
}

func TestCIDRDecorator_GroupAllUnknownTraffic(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(100))
	defer input.Close()
	outputQu := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(100))
	outCh := outputQu.Subscribe()
	grouper, err := DecoratorProvider([]string{
		"10.0.0.0/8",
		"10.1.2.0/24",
		"0.0.0.0/0", // this entry will capture all the unknown traffic
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	}, input, outputQu)(t.Context())
	require.NoError(t, err)
	go grouper(t.Context())
	input.Send([]*ebpf.Stat{
		stat("10.3.4.5", "10.1.2.3"),
		stat("2001:db8:3c4d:15:3210::", "2001:3333:3333::"),
		stat("140.130.22.11", "140.130.23.11"),
		stat("180.130.22.11", "10.1.2.4"),
	})
	decorated := testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, decorated, 4)
	assert.Equal(t, "10.0.0.0/8", decorated[0].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[0].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "2001:db8:3c4d:15::/64", decorated[1].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "2001::/16", decorated[1].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "140.130.22.0/24", decorated[2].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "0.0.0.0/0", decorated[2].Attrs.Metadata["dst.cidr"])
	assert.Equal(t, "0.0.0.0/0", decorated[3].Attrs.Metadata["src.cidr"])
	assert.Equal(t, "10.1.2.0/24", decorated[3].Attrs.Metadata["dst.cidr"])
}

func stat(srcIP, dstIP string) *ebpf.Stat {
	er := ebpf.Stat{}
	er.Attrs.SourceAddress = srcIP
	er.Attrs.DestinationAddress = dstIP
	return &er
}
