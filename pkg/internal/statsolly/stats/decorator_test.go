// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const timeout = 5 * time.Second

func TestDecoration(t *testing.T) {

	// Given a flow Decorator node
	in := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	go Decorate(net.IPv4(3, 3, 3, 3), in, out)(t.Context())

	// When it receives flows
	s1 := &ebpf.Stat{}
	s2 := &ebpf.Stat{}

	in.Send([]*ebpf.Stat{s1, s2})

	// THEN it decorates them, by adding agent IP
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 2)

	assert.Equal(t, "3.3.3.3", decorated[0].Attrs.OBIIP)

	assert.Equal(t, "3.3.3.3", decorated[1].Attrs.OBIIP)

}
