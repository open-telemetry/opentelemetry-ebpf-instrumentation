// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func rtlog() *slog.Logger {
	return slog.With("component", "stat.RingBufTracer")
}

// RingBufTracer receives a single stat via ringbuffer and submits it to the pipeline
type RingBufTracer struct {
	ringBuffer ringBufReader
}

type ringBufReader interface {
	ReadRingBuf() (ringbuf.Record, error)
}

func NewRingBufTracer(reader ringBufReader) *RingBufTracer {
	return &RingBufTracer{
		ringBuffer: reader,
	}
}

func (m *RingBufTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		rtlog := rtlog()
		for {
			select {
			case <-ctx.Done():
				rtlog.Debug("exiting trace loop due to context cancellation")
				return
			default:
				if err := m.listenAndForwardRingBuffer(ctx, out); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						rtlog.Debug("Received signal, exiting..")
						return
					}
					rtlog.Warn("ignoring stat event", "error", err)
					continue
				}
			}
		}
	}
}

func (m *RingBufTracer) listenAndForwardRingBuffer(ctx context.Context, forwardCh *msg.Queue[[]*ebpf.Stat]) error {
	event, err := m.ringBuffer.ReadRingBuf()
	if err != nil {
		return fmt.Errorf("reading from ring buffer: %w", err)
	}

	stat, err := m.handleStatEvent(&event)
	if err != nil {
		return fmt.Errorf("handle stat event: %w", err)
	}
	forwardCh.SendCtx(ctx, []*ebpf.Stat{&stat})

	return nil
}

func (m *RingBufTracer) handleStatEvent(record *ringbuf.Record) (ebpf.Stat, error) {
	eventType := ebpf.StatType(record.RawSample[0])
	switch eventType {
	case ebpf.StatTypeTCPRtt:
		return m.readTCPRttIntoStat(record)
	default:
		return ebpf.Stat{}, fmt.Errorf("unknown stats event [type %d]", uint8(eventType))
	}
}

func (m *RingBufTracer) readTCPRttIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPRtt](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}

	sourceAddress := ""
	destinationAddress := ""
	destinationPort := 0
	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		sourceAddress, destinationAddress = reqHostInfo(event.Conn.S_addr, event.Conn.D_addr)
		destinationPort = int(event.Conn.D_port)
	}

	sourcePort := int(event.Conn.S_port)
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPRtt,
		TCPRtt: &ebpf.TCPRtt{
			Srtt: event.Srtt,
		},
		Attrs: ebpf.StatAttrs{
			SourceAddress:      sourceAddress,
			DestinationAddress: destinationAddress,
			SourcePort:         sourcePort,
			DestinationPort:    destinationPort,
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
