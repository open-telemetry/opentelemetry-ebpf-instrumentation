// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package decorate

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

const timeout = 5 * time.Second

type testRecord struct {
	pipe.CommonAttrs
}

func TestDecoration(t *testing.T) {
	srcIP := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 2, 3, 4}
	dstIP := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 4, 3, 2, 1}

	// Given a Decorator node
	in := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	dec, err := Decorate(net.IPv4(3, 3, 3, 3),
		func(r *testRecord) *pipe.CommonAttrs { return &r.CommonAttrs },
		in, out)(t.Context())
	require.NoError(t, err)
	go dec(t.Context())

	// When it receives items
	f1 := &testRecord{CommonAttrs: pipe.CommonAttrs{SrcName: "source"}}
	f1.SrcAddr = pipe.IPAddr(srcIP)
	f1.DstAddr = pipe.IPAddr(dstIP)

	f2 := &testRecord{CommonAttrs: pipe.CommonAttrs{DstName: "destination"}}
	f2.SrcAddr = pipe.IPAddr(srcIP)
	f2.DstAddr = pipe.IPAddr(dstIP)

	in.Send([]*testRecord{f1, f2})

	// THEN it decorates them, by adding IPs to source/destination
	// names only when they were missing
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 2)

	assert.Equal(t, "3.3.3.3", decorated[0].OBIIP)
	assert.Equal(t, "source", decorated[0].SrcName)
	assert.Equal(t, "4.3.2.1", decorated[0].DstName)

	assert.Equal(t, "3.3.3.3", decorated[1].OBIIP)
	assert.Equal(t, "1.2.3.4", decorated[1].SrcName)
	assert.Equal(t, "destination", decorated[1].DstName)
}
