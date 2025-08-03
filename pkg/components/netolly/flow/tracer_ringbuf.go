// Copyright The OpenTelemetry Authors

// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package flow

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	ebpfcommon "go.opentelemetry.io/obi/pkg/components/ebpf/common"
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/components/netolly/deduper"
	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/components/netolly/protofilter"
	"go.opentelemetry.io/obi/pkg/components/netolly/rdns"
	"go.opentelemetry.io/obi/pkg/components/netolly/transform/cidr"
	"go.opentelemetry.io/obi/pkg/components/netolly/transform/k8s"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func rtlog() *slog.Logger {
	return slog.With("component", "flow.RingBufTracer")
}

// RingBufTracer receives single-packet flows via ringbuffer (usually, these that couldn't be
// added in the eBPF kernel space due to the map being full or busy) and submits them to the
// userspace Aggregator map
type RingBufTracer struct {
	cfg            *obi.Config
	mapFlusher     mapFlusher
	ringBuffer     ringBufReader
	stats          stats
	protocolFilter *protofilter.ProtocolFilter
	deduper        *deduper.Deduper
	k8sDecorator   *k8s.Decorator
	rdnsEnricher   rdns.ReverseDNSFunc
	cidrDecorator  cidr.CIDRDecoratorFunc
	flowDecorator  FlowDecoratorFunc
}

type ringBufReader interface {
	ReadRingBuf() (ringbuf.Record, error)
	RingBufReader() *ringbuf.Reader
}

// stats supports atomic logging of ringBuffer metrics
type stats struct {
	loggingTimeout time.Duration
	isForwarding   int32
	forwardedFlows int32
	mapFullErrs    int32
}

type mapFlusher interface {
	Flush()
}

func NewRingBufTracer(reader ringBufReader, flusher mapFlusher, cfg *obi.Config) *RingBufTracer {
	return &RingBufTracer{
		cfg:        cfg,
		mapFlusher: flusher,
		ringBuffer: reader,
		stats:      stats{loggingTimeout: cfg.NetworkFlows.CacheActiveTimeout},
		deduper: deduper.NewDeduper(cfg.NetworkFlows.Deduper,
			cfg.NetworkFlows.DeduperFCTTL,
			cfg.NetworkFlows.CacheActiveTimeout),
	}
}

/*
// 1) A pool of byte-slices, each sized for the largest event you expect.
var eventPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, maxPayloadSize)
	},
}
*/

func (m *RingBufTracer) ringbufferLoop(ctx context.Context,
		k8sDecorator *k8s.Decorator,
		flowDecorator FlowDecoratorFunc,
		out *msg.Queue[ebpf.Record]) {
	defer out.MarkCloseable()

	rtlog := rtlog()

	protocolFilter, err := protofilter.NewFilter(m.cfg.NetworkFlows.Protocols, m.cfg.NetworkFlows.ExcludeProtocols)

	if err != nil {
		rtlog.Error("error creating protocol filter", "error", err)
		return
	}

	m.protocolFilter = protocolFilter
	m.k8sDecorator = k8sDecorator

	rdnsEnricher, err := rdns.ReverseDNSEnricher(ctx, &m.cfg.NetworkFlows.ReverseDNS)

	if err != nil {
		rtlog.Error("error creating rdns enricher ", "error", err)
		return
	}

	m.rdnsEnricher = rdnsEnricher

	cidrDecorator, err := cidr.CIDRDecorator(m.cfg.NetworkFlows.CIDRs)

	if err != nil {
		rtlog.Error("error creating CIDR decorator ", "error", err)
		return
	}

	m.cidrDecorator = cidrDecorator
	m.flowDecorator = flowDecorator

	// debugging := rtlog.Enabled(ctx, slog.LevelDebug)

	reader := m.ringBuffer.RingBufReader()

	resetDeadline := func() {
		reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
	}

	resetDeadline()

	var rec ringbuf.Record

	for {
		select {
		case <-ctx.Done():
			rtlog.Debug("exiting trace loop due to context cancellation")
			return
		default:
			if err := reader.ReadInto(&rec); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					resetDeadline()
					continue
				}

				if errors.Is(err, ringbuf.ErrClosed) {
					rtlog.Debug("Received signal, exiting..")
					return
				}

				rtlog.Warn("ignoring flow event", "error", err)
				continue
			}

			event, err := ebpfcommon.ReinterpretCast[ebpf.NetFlowRecordT](rec.RawSample)
			if err != nil {
				continue
			}

			m.handleEvent(event, out)

			// out.Send(ebpf.Record{ NetFlowRecordT: *event, })
		}
	}
}

func (m *RingBufTracer) handleEvent(event *ebpf.NetFlowRecordT, out *msg.Queue[ebpf.Record]) {
	if !m.protocolFilter.IsAllowed(event) {
		return
	}

	if m.deduper.IsDupe(event) {
		return
	}

	rec := ebpf.Record{ NetFlowRecordT: *event }

	if !m.k8sDecorator.Decorate(&rec) {
		return
	}

	m.rdnsEnricher(&rec)
	m.cidrDecorator(&rec)
	m.flowDecorator(&rec)

	out.Send(rec)
}

func (m *RingBufTracer) TraceLoop(k8sDecorator *k8s.Decorator,
		flowDecorator FlowDecoratorFunc,
		out *msg.Queue[ebpf.Record]) swarm.RunFunc {
	return func(ctx context.Context) {
		m.ringbufferLoop(ctx, k8sDecorator, flowDecorator, out)
	}
}

// logRingBufferFlows avoids flooding logs on long series of evicted flows by grouping how
// many flows are forwarded
func (m *stats) logRingBufferFlows(mapFullErr bool) {
	atomic.AddInt32(&m.forwardedFlows, 1)
	if mapFullErr {
		atomic.AddInt32(&m.mapFullErrs, 1)
	}
	if atomic.CompareAndSwapInt32(&m.isForwarding, 0, 1) {
		go func() {
			time.Sleep(m.loggingTimeout)
			mfe := atomic.LoadInt32(&m.mapFullErrs)
			l := rtlog().With(
				"flows", atomic.LoadInt32(&m.forwardedFlows),
				"mapFullErrs", mfe,
			)
			if mfe == 0 {
				l.Debug("received flows via ringbuffer")
			} else {
				l.Debug("received flows via ringbuffer due to Map Full. You might want to increase the OTEL_EBPF_NETWORK_CACHE_MAX_FLOWS value")
			}
			atomic.StoreInt32(&m.forwardedFlows, 0)
			atomic.StoreInt32(&m.isForwarding, 0)
			atomic.StoreInt32(&m.mapFullErrs, 0)
		}()
	}
}
