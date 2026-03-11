// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rdns

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const timeout = 5 * time.Second

var (
	srcIP = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 140, 82, 121, 4}
	dstIP = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1}
)

type testRecord struct {
	pipe.CommonAttrs
}

func attrsOf(r *testRecord) *pipe.CommonAttrs { return &r.CommonAttrs }

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
	in := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute},
		attrsOf, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())

	// When it receives flows without source nor destination name
	f1 := &testRecord{}
	f1.SrcAddr = pipe.IPAddr(srcIP)
	f1.DstAddr = pipe.IPAddr(dstIP)

	in.Send([]*testRecord{f1})

	// THEN it decorates them with the looked up source/destination names
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)

	assert.Contains(t, decorated[0].SrcName, "github")
	assert.Contains(t, decorated[0].DstName, "local")
}

func TestReverseDNS_AlreadyProvidedNames(t *testing.T) {
	netLookupAddr = func(addr string) ([]string, error) {
		require.Fail(t, "network lookup shouldn't be invoked!", "Got:", addr)
		return nil, errors.New("boom")
	}
	// Given a Reverse DNS node
	in := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute},
		attrsOf, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())

	// When it receives flows with source and destination names
	f1 := &testRecord{
		CommonAttrs: pipe.CommonAttrs{SrcName: "src", DstName: "dst"},
	}
	f1.SrcAddr = pipe.IPAddr(srcIP)
	f1.DstAddr = pipe.IPAddr(dstIP)

	in.Send([]*testRecord{f1})

	// THEN it does not change the decoration
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)

	assert.Contains(t, decorated[0].SrcName, "src")
	assert.Contains(t, decorated[0].DstName, "dst")
}

func TestReverseDNS_Cache(t *testing.T) {
	lookups := 0
	netLookupAddr = func(_ string) (_ []string, _ error) {
		require.Zero(t, lookups, "address lookup should only happen once", lookups)
		lookups++
		return []string{"amazon"}, nil
	}
	// Given a Reverse DNS node
	in := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute},
		attrsOf, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())

	// When it receives a flow with an unknown destination for the first time
	f1 := &testRecord{
		CommonAttrs: pipe.CommonAttrs{SrcName: "src"},
	}
	f1.SrcAddr = pipe.IPAddr(srcIP)
	f1.DstAddr = pipe.IPAddr(dstIP)

	in.Send([]*testRecord{f1})

	// THEN it decorates it
	decorated := testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)
	assert.Contains(t, decorated[0].DstName, "amazon")

	// AND when it receives the same flow again
	f1.DstName = ""
	in.Send([]*testRecord{f1})

	// THEN it decorates it from the cached copy (otherwise the fake netLookupAddr would crash)
	decorated = testutil.ReadChannel(t, outCh, timeout)
	require.Len(t, decorated, 1)
	assert.Contains(t, decorated[0].DstName, "amazon")
}
