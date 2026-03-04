// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

var (
	srcIP = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 140, 82, 121, 4}
	dstIP = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1}
)

func TestReverseDNS(t *testing.T) {
	netLookupAddr = func(addr string) (names []string, err error) {
		switch addr {
		case "140.82.121.4":
			return []string{"foo.github.com"}, nil
		case "127.0.0.1":
			return []string{"localhost.localdomain"}, nil
		default:
			return []string{"unknown"}, nil
		}
	}
	// Given a Reverse DNS node
	in := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute}, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())

	// When it receives stats without source nor destination name
	s1 := &ebpf.Stat{}
	srcStr := net.IP(srcIP[:]).String() // Result: "140.82.121.4"
	dstStr := net.IP(dstIP[:]).String() // Result: "127.0.0.1"

	s1.Attrs.SourceAddress = srcStr
	s1.Attrs.DestinationAddress = dstStr

	in.Send([]*ebpf.Stat{s1})

	// THEN it decorates them with the looked up source/destination names
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)

	assert.Contains(t, decorated[0].Attrs.SrcName, "github")
	assert.Contains(t, decorated[0].Attrs.DstName, "local")
}

func TestReverseDNS_AlreadyProvidedNames(t *testing.T) {
	netLookupAddr = func(addr string) ([]string, error) {
		require.Fail(t, "network lookup shouldn't be invoked!", "Got:", addr)
		return nil, errors.New("boom")
	}
	// Given a Reverse DNS node
	in := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute}, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())

	// When it receives stats with source and destination names
	s1 := &ebpf.Stat{
		Attrs: ebpf.StatAttrs{SrcName: "src", DstName: "dst"},
	}
	srcStr := net.IP(srcIP[:]).String() // Result: "140.82.121.4"
	dstStr := net.IP(dstIP[:]).String() // Result: "127.0.0.1"

	s1.Attrs.SourceAddress = srcStr
	s1.Attrs.DestinationAddress = dstStr

	in.Send([]*ebpf.Stat{s1})

	// THEN it does not cange the decoration
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)

	assert.Contains(t, decorated[0].Attrs.SrcName, "src")
	assert.Contains(t, decorated[0].Attrs.DstName, "dst")
}

func TestReverseDNS_Cache(t *testing.T) {
	lookups := 0
	netLookupAddr = func(_ string) (_ []string, _ error) {
		require.Zero(t, lookups, "address lookup should only happen once", lookups)
		lookups++
		return []string{"amazon"}, nil
	}
	// Given a Reverse DNS node
	in := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute}, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())

	// When it receives a flow with an unknown destination for the first time
	s1 := &ebpf.Stat{
		Attrs: ebpf.StatAttrs{SrcName: "src"},
	}
	srcStr := net.IP(srcIP[:]).String() // Result: "140.82.121.4"
	dstStr := net.IP(dstIP[:]).String() // Result: "127.0.0.1"

	s1.Attrs.SourceAddress = srcStr
	s1.Attrs.DestinationAddress = dstStr

	in.Send([]*ebpf.Stat{s1})

	// THEN it decorates it
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)
	assert.Contains(t, decorated[0].Attrs.DstName, "amazon")

	// AND when it receives the same stat again
	s1.Attrs.DstName = ""
	in.Send([]*ebpf.Stat{s1})

	// THEN it decorates it from the cached copy (otherwise the fake netLookupAddr would crash)
	decorated = testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)
	assert.Contains(t, decorated[0].Attrs.DstName, "amazon")
}
