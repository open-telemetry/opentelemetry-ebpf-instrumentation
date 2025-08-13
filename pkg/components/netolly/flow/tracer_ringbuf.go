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

	ebpfcommon "go.opentelemetry.io/obi/pkg/components/ebpf/common"
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/components/netolly/rdns"
	"go.opentelemetry.io/obi/pkg/components/netolly/transform/cidr"
	"go.opentelemetry.io/obi/pkg/components/netolly/transform/k8s"
	"go.opentelemetry.io/obi/pkg/filter"
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
	flowFetcher    *ebpf.SockFlowFetcher
	k8sDecorator   *k8s.Decorator
	rdnsEnricher   rdns.ReverseDNSFunc
	cidrDecorator  cidr.CIDRDecoratorFunc
	flowDecorator  FlowDecoratorFunc
	flowFilter     *filter.Filter2[*ebpf.Record]
}

func NewRingBufTracer(fetcher *ebpf.SockFlowFetcher, cfg *obi.Config) *RingBufTracer {
	return &RingBufTracer{
		cfg:        cfg,
		flowFetcher: fetcher,
	}
}

func (m *RingBufTracer) ringbufferLoop(ctx context.Context,
	k8sDecorator *k8s.Decorator,
	flowDecorator FlowDecoratorFunc,
	flowFilter *filter.Filter2[*ebpf.Record],
	out *msg.Queue[ebpf.Record],
) {
	defer out.MarkCloseable()

	rtlog := rtlog()

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
	m.flowFilter = flowFilter

	reader := m.flowFetcher.RingBufReader()

	var rec ringbuf.Record

	for {
		select {
		case <-ctx.Done():
			rtlog.Debug("exiting trace loop due to context cancellation")
			return
		default:
			if err := reader.ReadInto(&rec); err != nil {
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
		}
	}
}

func (m *RingBufTracer) handleEvent(event *ebpf.NetFlowRecordT, out *msg.Queue[ebpf.Record]) {
	rec := ebpf.Record{NetFlowRecordT: *event}

	if !m.k8sDecorator.Decorate(&rec) {
		return
	}

	m.rdnsEnricher(&rec)
	m.cidrDecorator(&rec)
	m.flowDecorator(&rec)

	if !m.flowFilter.Allow(&rec) {
		return
	}

	out.Send(rec)
}

func (m *RingBufTracer) TraceLoop(k8sDecorator *k8s.Decorator,
	flowDecorator FlowDecoratorFunc,
	flowFilter *filter.Filter2[*ebpf.Record],
	out *msg.Queue[ebpf.Record],
) swarm.RunFunc {
	return func(ctx context.Context) {
		m.ringbufferLoop(ctx, k8sDecorator, flowDecorator, flowFilter, out)
	}
}

