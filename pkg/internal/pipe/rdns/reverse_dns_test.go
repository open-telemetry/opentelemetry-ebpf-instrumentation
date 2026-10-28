// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rdns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/rdns/store"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
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
	in1, out1 := startReverseDNS(t.Context(), t, cfg, ebpfLookup)
	in2, out2 := startReverseDNS(t.Context(), t, cfg, ebpfLookup)

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
	ebpfIn, ebpfOut := startReverseDNS(t.Context(), t, ebpfCfg, ebpfLookup)
	localIn, localOut := startReverseDNS(t.Context(), t, localCfg, ebpfLookup)

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

func TestReverseDNS_EBPFRunsWithTheOBIRun(t *testing.T) {
	started := fakeDNSPacketInspector(t)
	cfg := &ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 255, CacheTTL: time.Minute}

	// Given the eBPF reverse DNS of an OBI run, used by a pipeline
	runCtx, stopRun := context.WithCancel(t.Context())
	ebpfLookup := NewEBPFLookup(runCtx, nil, cfg)
	pipelineCtx, stopPipeline := context.WithCancel(runCtx)
	startReverseDNS(pipelineCtx, t, cfg, ebpfLookup)
	require.Len(t, *started, 1)
	inspector := (*started)[0]

	// When the pipeline stops
	stopPipeline()

	// THEN the DNS packet inspector keeps running for the rest of the run
	assert.Never(t, func() bool { return inspector.Err() != nil }, 100*time.Millisecond, 10*time.Millisecond)

	// AND it is stopped when the OBI run is stopped
	stopRun()
	require.Eventually(t, func() bool { return inspector.Err() != nil }, timeout, 10*time.Millisecond)
}

func TestEBPFLookup_CloseWaitsForDetach(t *testing.T) {
	attached := lateDetachDNSPacketInspector(t)
	cfg := &ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 255, CacheTTL: time.Minute}

	// Given an OBI run whose graph fails to build after the reverse DNS node
	ebpfLookup := NewEBPFLookup(t.Context(), nil, cfg)
	in := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	swi := &swarm.Instancer{}
	swi.Add(ReverseDNSProvider(cfg, attrsOf, ebpfLookup, in, out))
	swi.Add(func(_ context.Context) (swarm.RunFunc, error) { return nil, errors.New("can't build") })
	_, err := swi.Instance(t.Context())
	require.Error(t, err)
	require.True(t, attached.Load())

	// When the run is closed
	ebpfLookup.Close(timeout)

	// THEN the inspector has been detached
	assert.False(t, attached.Load())

	// AND the next run, with its own context info, can attach it again
	_, err = instantiateReverseDNS(t, cfg, NewEBPFLookup(t.Context(), nil, cfg))
	require.NoError(t, err)
}

func TestEBPFLookup_CloseTimeout(t *testing.T) {
	start := startDNSPacketInspector
	t.Cleanup(func() { startDNSPacketInspector = start })
	startDNSPacketInspector = func(_ context.Context, _ *store.InMemory, _ *config.EBPFTracer) (<-chan struct{}, error) {
		return make(chan struct{}), nil
	}
	cfg := &ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 255, CacheTTL: time.Minute}

	// Given an inspector that never detaches
	ebpfLookup := NewEBPFLookup(t.Context(), nil, cfg)
	_, err := instantiateReverseDNS(t, cfg, ebpfLookup)
	require.NoError(t, err)

	// THEN Close gives up after the timeout
	closed := make(chan struct{})
	go func() {
		ebpfLookup.Close(10 * time.Millisecond)
		close(closed)
	}()
	testutil.ReadChannel(t, closed, timeout)
}

func TestEBPFLookup_CloseNotStarted(t *testing.T) {
	started := fakeDNSPacketInspector(t)
	cfg := &ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 255, CacheTTL: time.Minute}

	// Given an eBPF reverse DNS that no pipeline has used
	ebpfLookup := NewEBPFLookup(t.Context(), nil, cfg)

	// THEN Close returns without starting it
	ebpfLookup.Close(timeout)
	assert.Empty(t, *started)
}

func TestNewEBPFLookup_LargestCacheLen(t *testing.T) {
	ebpfLookup := NewEBPFLookup(t.Context(), nil,
		&ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 100},
		&ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 300},
		&ReverseDNS{Type: ReverseDNSLocalLookup, CacheLen: 999},
	)
	assert.Equal(t, 300, ebpfLookup.cacheLen)
}

func TestReverseDNS_EBPFStartError(t *testing.T) {
	start := startDNSPacketInspector
	t.Cleanup(func() { startDNSPacketInspector = start })
	starts := 0
	startDNSPacketInspector = func(_ context.Context, _ *store.InMemory, _ *config.EBPFTracer) (<-chan struct{}, error) {
		starts++
		return nil, errors.New("no interfaces found")
	}
	cfg := &ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 255, CacheTTL: time.Minute}
	ebpfLookup := NewEBPFLookup(t.Context(), nil, cfg)

	// THEN both pipelines get the error of the only start attempt
	for range 2 {
		_, err := instantiateReverseDNS(t, cfg, ebpfLookup)
		require.ErrorContains(t, err, "starting eBPF-based reverse DNS: no interfaces found")
	}
	assert.Equal(t, 1, starts)
}

func TestReverseDNS_EBPFCacheError(t *testing.T) {
	fakeDNSPacketInspector(t)
	cfg := &ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 0, CacheTTL: time.Minute}

	_, err := instantiateReverseDNS(t, cfg, NewEBPFLookup(t.Context(), nil, cfg))
	require.ErrorContains(t, err, "initializing eBPF-based reverse DNS cache")
}

func TestReverseDNS_EBPFWithoutLookup(t *testing.T) {
	cfg := &ReverseDNS{Type: ReverseDNSEBPF, CacheLen: 255, CacheTTL: time.Minute}

	_, err := instantiateReverseDNS(t, cfg, nil)
	require.ErrorContains(t, err, "eBPF-based reverse DNS is not available")
}

func instantiateReverseDNS(t *testing.T, cfg *ReverseDNS, ebpfLookup *EBPFLookup) (swarm.RunFunc, error) {
	in := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	return ReverseDNSProvider(cfg, attrsOf, ebpfLookup, in, out)(t.Context())
}

// lateDetachDNSPacketInspector detaches a while after being stopped, and can't be
// attached again until then. It returns whether it is attached.
func lateDetachDNSPacketInspector(t *testing.T) *atomic.Bool {
	start := startDNSPacketInspector
	t.Cleanup(func() { startDNSPacketInspector = start })

	attached := &atomic.Bool{}
	startDNSPacketInspector = func(ctx context.Context, _ *store.InMemory, _ *config.EBPFTracer) (<-chan struct{}, error) {
		if !attached.CompareAndSwap(false, true) {
			return nil, errors.New("no interfaces found")
		}
		stopped := make(chan struct{})
		go func() {
			<-ctx.Done()
			time.Sleep(100 * time.Millisecond)
			attached.Store(false)
			close(stopped)
		}()
		return stopped, nil
	}
	return attached
}

// fakeDNSPacketInspector returns the contexts the inspector has been started with
func fakeDNSPacketInspector(t *testing.T) *[]context.Context {
	start := startDNSPacketInspector
	t.Cleanup(func() { startDNSPacketInspector = start })

	var started []context.Context
	startDNSPacketInspector = func(ctx context.Context, dnsCache *store.InMemory, _ *config.EBPFTracer) (<-chan struct{}, error) {
		started = append(started, ctx)
		dnsCache.StorePair("140.82.121.4", "ebpf.github.com")
		dnsCache.StorePair("127.0.0.1", "ebpf.localdomain")
		return ctx.Done(), nil
	}
	return &started
}

func startReverseDNS(
	ctx context.Context, t *testing.T, cfg *ReverseDNS, ebpfLookup *EBPFLookup,
) (*msg.Queue[[]*testRecord], <-chan []*testRecord) {
	in := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*testRecord](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	reverseDNS, err := ReverseDNSProvider(cfg, attrsOf, ebpfLookup, in, out)(ctx)
	require.NoError(t, err)
	go reverseDNS(ctx)
	return in, outCh
}

func newTestRecord() *testRecord {
	r := &testRecord{}
	r.SrcAddr = pipe.IPAddr(srcIP)
	r.DstAddr = pipe.IPAddr(dstIP)
	return r
}
