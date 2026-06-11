// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const benchBatchLen = 100

// BenchmarkForwardRingbuf measures events/sec through the forwarder pipeline.
//
// latency is applied to both ReadInto (simulating BPF ring-buffer wake-up and
// copy time) and parse (simulating span decoding). In the current design these
// two phases run in separate goroutines; compare with benchstat against a commit
// where they ran serially to see the parallelism gain.
//
//	go test -bench=BenchmarkForwardRingbuf -benchtime=5s ./pkg/ebpf/common/...
func BenchmarkForwardRingbuf(b *testing.B) {
	for _, latency := range []time.Duration{time.Microsecond, 10 * time.Microsecond, 100 * time.Microsecond} {
		b.Run(fmt.Sprintf("latency=%v", latency), func(b *testing.B) {
			benchForwardRingbuf(b, latency)
		})
	}
}

func benchForwardRingbuf(b *testing.B, latency time.Duration) {
	b.Helper()

	// Round up to a full batch so every flush is triggered by BatchLength events,
	// not by a timeout. This avoids a stall on the last partial batch and keeps
	// the measurement boundary clean.
	n := ((b.N + benchBatchLen - 1) / benchBatchLen) * benchBatchLen

	rb := &benchReader{n: n, latency: latency}
	prevFactory := readerFactory
	readerFactory = func(_ *ebpf.Map) (ringBufReader, error) { return rb, nil }
	defer func() { readerFactory = prevFactory }()

	cfg := &config.EBPFTracer{BatchLength: benchBatchLen}
	parse := func(_ *ringbuf.Record) (request.Span, bool, error) {
		spin(latency)
		return request.Span{Type: 1}, false, nil
	}

	batches := n / benchBatchLen
	out := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(batches + 1))
	sub := out.Subscribe()

	ctx, cancel := context.WithCancel(context.Background())

	fwd := ForwardRingbuf[request.Span](
		cfg, nil, parse, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&metricsReporter{},
	)

	done := make(chan struct{})
	b.ResetTimer()
	go func() {
		defer close(done)
		fwd(ctx, out)
	}()

	for range batches {
		<-sub
	}

	b.StopTimer()
	cancel()
	<-done
	b.ReportMetric(float64(n)/b.Elapsed().Seconds(), "events/s")
}

// benchReader delivers n records, each taking latency to produce, then closes.
type benchReader struct {
	n       int
	latency time.Duration
}

func (r *benchReader) ReadInto(rec *ringbuf.Record) error {
	if r.n == 0 {
		return ringbuf.ErrClosed
	}
	r.n--
	spin(r.latency)
	rec.RawSample = nil
	return nil
}

func (r *benchReader) Read() (ringbuf.Record, error) {
	rec := ringbuf.Record{}
	return rec, r.ReadInto(&rec)
}

func (r *benchReader) Close() error        { return nil }
func (r *benchReader) AvailableBytes() int { return r.n }
func (r *benchReader) Flush() error        { return nil }

// spin burns CPU for approximately d without sleeping (avoids OS scheduler noise
// for sub-millisecond durations).
func spin(d time.Duration) {
	if d == 0 {
		return
	}
	end := time.Now().Add(d)
	for time.Now().Before(end) {
	}
}
