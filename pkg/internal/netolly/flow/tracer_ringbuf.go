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

package flow // import "go.opentelemetry.io/obi/pkg/internal/netolly/flow"
// TODO pino change pkg name

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func rtlog() *slog.Logger {
	return slog.With("component", "flow.RingBufTracer")
}

type RingBufStatsTracer struct {
	ringBuffer ringBufReader
}

// RingBufTracer receives single-packet flows via ringbuffer (usually, these that couldn't be
// added in the eBPF kernel space due to the map being full or busy) and submits them to the
// userspace Aggregator map
type RingBufTracer struct {
	mapFlusher mapFlusher
	ringBuffer ringBufReader
	stats      stats
}

type ringBufReader interface {
	ReadRingBuf() (ringbuf.Record, error)
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

func NewRingBufTracer(
	reader ringBufReader, flusher mapFlusher, logTimeout time.Duration,
) *RingBufTracer {
	return &RingBufTracer{
		mapFlusher: flusher,
		ringBuffer: reader,
		stats:      stats{loggingTimeout: logTimeout},
	}
}

func NewRingBufStatsTracer(reader ringBufReader) *RingBufStatsTracer {
	return &RingBufStatsTracer{
		ringBuffer: reader,
	}
}

func (m *RingBufStatsTracer) TraceLoop(out *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		rtlog := rtlog()
		debugging := rtlog.Enabled(ctx, slog.LevelDebug)
		for {
			select {
			case <-ctx.Done():
				rtlog.Debug("exiting trace loop due to context cancellation")
				return
			default:
				if err := m.listenAndForwardRingBuffer(debugging, out); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						rtlog.Debug("Received signal, exiting..")
						return
					}
					rtlog.Warn("ignoring flow event", "error", err)
					continue
				}
			}
		}
	}
}

func (m *RingBufTracer) TraceLoop(out *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		rtlog := rtlog()
		debugging := rtlog.Enabled(ctx, slog.LevelDebug)
		for {
			select {
			case <-ctx.Done():
				rtlog.Debug("exiting trace loop due to context cancellation")
				return
			default:
				if err := m.listenAndForwardRingBuffer(debugging, out); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						rtlog.Debug("Received signal, exiting..")
						return
					}
					rtlog.Warn("ignoring flow event", "error", err)
					continue
				}
			}
		}
	}
}

func (m *RingBufStatsTracer) listenAndForwardRingBuffer(debugging bool, forwardCh *msg.Queue[[]*ebpf.Record]) error {
	rRecord, err := m.ringBuffer.ReadRingBuf()
	if err != nil {
		return fmt.Errorf("reading from ring buffer: %w", err)
	}
	record, err := m.handleStatsEvent(&rRecord)
	if err != nil {
		return fmt.Errorf("handle stat event: %w", err)
	}
	forwardCh.Send([]*ebpf.Record{&record})

	return nil
}

// The following consts need to coincide with some C identifiers defined in bpf/appnetworktracer/types.h
const (
	EventTypeAppNetTCPRtt = 1 // event_app_net_tcp_rtt Application Network metrics related event - RTT
)

func (m *RingBufStatsTracer) handleStatsEvent(record *ringbuf.Record) (ebpf.Record, error) {
	eventType := record.RawSample[0]
	switch eventType {
	case EventTypeAppNetTCPRtt:
		return m.readTCPRttIntoSpan(record)
	default:
		fmt.Errorf("unknown net app event", "eventType", eventType)
	}

	return ebpf.Record{}, nil
}

func (m *RingBufStatsTracer) readTCPRttIntoSpan(record *ringbuf.Record) (ebpf.Record, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.AppNetTCPRtt](record.RawSample)
	if err != nil {
		return ebpf.Record{}, err
	}

	// peer := ""
	// hostname := ""
	// hostPort := 0
	// if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
	// 	peer, hostname = reqHostInfo(event.Conn.S_addr, event.Conn.D_addr)
	// 	hostPort = int(event.Conn.D_port)
	// }

	// peerPort := int(event.Conn.S_port)
	return ebpf.Record{
		NetStats: ebpf.NetStats{
			TCPRtt: ebpf.TCPRtt{
				Srtt: event.Srtt,
			},
		},
	}, nil
}

func reqHostInfo(srcAddr, dstAddr [16]uint8) (source, target string) {
	src := make(net.IP, net.IPv6len)
	dst := make(net.IP, net.IPv6len)
	copy(src, srcAddr[:])
	copy(dst, dstAddr[:])

	srcStr := src.String()
	dstStr := dst.String()

	if src.IsUnspecified() {
		srcStr = ""
	}

	if dst.IsUnspecified() {
		dstStr = ""
	}

	return srcStr, dstStr
}

func (m *RingBufTracer) listenAndForwardRingBuffer(debugging bool, forwardCh *msg.Queue[[]*ebpf.Record]) error {
	event, err := m.ringBuffer.ReadRingBuf()
	if err != nil {
		return fmt.Errorf("reading from ring buffer: %w", err)
	}
	// Parses the ringbuf event entry into an Event structure.
	readFlow, err := ebpf.ReadFrom(bytes.NewBuffer(event.RawSample))
	if err != nil {
		return fmt.Errorf("parsing data received from the ring buffer: %w", err)
	}
	mapFullError := readFlow.Metrics.Errno == uint8(syscall.E2BIG)
	// TODO pino is this needed for netStats?
	if debugging {
		m.stats.logRingBufferFlows(mapFullError)
	}
	// if the flow was received due to lack of space in the eBPF map
	// forces a flow's eviction to leave room for new flows in the ebpf cache
	if mapFullError {
		m.mapFlusher.Flush()
	}

	forwardCh.Send([]*ebpf.Record{{
		NetFlowRecordT: readFlow,
	}})

	return nil
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
