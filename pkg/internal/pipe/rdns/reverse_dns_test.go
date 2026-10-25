// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/rdns/store"
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
		attrsOf, nil, in, out)(t.Context())
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
		attrsOf, nil, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())

	// When it receives flows with source and destination names
	f1 := &testRecord{
		CommonAttrs: pipe.CommonAttrs{DstName: "dst", SrcName: "src"},
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
		attrsOf, nil, in, out)(t.Context())
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

func TestReverseDNS_EBPFSharedByPipelines(t *testing.T) {
	started := fakeDNSPacketInspector(t)

	// Given two pipelines using the eBPF reverse DNS in the same OBI run
	cfg := &ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 255, CacheTTL: time.Minute}
	ebpfLookup := NewEBPFLookup(t.Context(), nil, cfg)
	in1, out1 := startReverseDNS(t, cfg, ebpfLookup)
	in2, out2 := startReverseDNS(t, cfg, ebpfLookup)

	// THEN the DNS packet inspector is started only once
	assert.Len(t, *started, 1)

	// AND both pipelines decorate their flows
	in1.Send([]*testRecord{newTestRecord()})
	in2.Send([]*testRecord{newTestRecord()})
	for _, out := range []<-chan []*testRecord{out1, out2} {
		decorated := testutil.ReadChannel(t, out, timeout)
		require.Len(t, decorated, 1)
		assert.Equal(t, "ebpf.github.com", decorated[0].SrcName)
		assert.Equal(t, "ebpf.localdomain", decorated[0].DstName)
	}
}

func TestReverseDNS_EBPFAndLocalPipelines(t *testing.T) {
	fakeDNSPacketInspector(t)
	netLookupAddr = func(_ string) ([]string, error) {
		return []string{"local"}, nil
	}

	// Given a pipeline using the eBPF reverse DNS and another using the local lookup
	ebpfCfg := &ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 255, CacheTTL: time.Minute}
	localCfg := &ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 255, CacheTTL: time.Minute}
	ebpfLookup := NewEBPFLookup(t.Context(), nil, ebpfCfg, localCfg)
	ebpfIn, ebpfOut := startReverseDNS(t, ebpfCfg, ebpfLookup)
	localIn, localOut := startReverseDNS(t, localCfg, ebpfLookup)

	// When both receive flows without source nor destination name
	ebpfIn.Send([]*testRecord{newTestRecord()})
	localIn.Send([]*testRecord{newTestRecord()})

	// THEN each pipeline decorates them with its own lookup method
	decorated := testutil.ReadChannel(t, ebpfOut, timeout)
	require.Len(t, decorated, 1)
	assert.Equal(t, "ebpf.github.com", decorated[0].SrcName)

	decorated = testutil.ReadChannel(t, localOut, timeout)
	require.Len(t, decorated, 1)
	assert.Equal(t, "local", decorated[0].SrcName)
}

func TestReverseDNS_EBPFRestartedOnNewRun(t *testing.T) {
	started := fakeDNSPacketInspector(t)
	cfg := &ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 255, CacheTTL: time.Minute}

	// Given an OBI run using the eBPF reverse DNS that is stopped
	firstRun, stopFirstRun := context.WithCancel(t.Context())
	startReverseDNS(t, cfg, NewEBPFLookup(firstRun, nil, cfg))
	stopFirstRun()

	// THEN its DNS packet inspector is stopped too
	require.Len(t, *started, 1)
	require.Error(t, (*started)[0].Err())

	// When OBI runs again in the same process
	in, out := startReverseDNS(t, cfg, NewEBPFLookup(t.Context(), nil, cfg))

	// THEN the DNS packet inspector is started again
	assert.Len(t, *started, 2)

	// AND the new run decorates its flows
	in.Send([]*testRecord{newTestRecord()})
	decorated := testutil.ReadChannel(t, out, timeout)
	require.Len(t, decorated, 1)
	assert.Equal(t, "ebpf.github.com", decorated[0].SrcName)
}

func TestNewEBPFLookup_LargestCacheLen(t *testing.T) {
	ebpfLookup := NewEBPFLookup(t.Context(), nil,
		&ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 100},
		&ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 300},
		&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 999},
	)
	assert.Equal(t, 300, ebpfLookup.cacheLen)
}

// fakeDNSPacketInspector returns the contexts the inspector has been started with
func fakeDNSPacketInspector(t *testing.T) *[]context.Context {
	start := startDNSPacketInspector
	t.Cleanup(func() { startDNSPacketInspector = start })

	var started []context.Context
	startDNSPacketInspector = func(ctx context.Context, dnsCache *store.InMemory, _ *config.EBPFTracer) error {
		started = append(started, ctx)
		dnsCache.StorePair("140.82.121.4", "ebpf.github.com")
		dnsCache.StorePair("127.0.0.1", "ebpf.localdomain")
		return nil
	}
	return &started
}

func startReverseDNS(
	t *testing.T, cfg *ReverseDNS, ebpfLookup *EBPFLookup,
) (*msg.Queue[[]*testRecord], <-chan []*testRecord) {
	in := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(cfg, attrsOf, ebpfLookup, in, out)(t.Context())
	require.NoError(t, err)
	go reverseDNS(t.Context())
	return in, outCh
}

func newTestRecord() *testRecord {
	r := &testRecord{}
	r.SrcAddr = pipe.IPAddr(srcIP)
	r.DstAddr = pipe.IPAddr(dstIP)
	return r
}
