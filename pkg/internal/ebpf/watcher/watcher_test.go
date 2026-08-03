// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestProcessWatchEventRejectsTruncatedRecords(t *testing.T) {
	events := make(chan Event, 1)
	w := New(&obi.Config{}, events)
	sample := watchSample(1, 8080)
	for length := 0; length < 8; length++ {
		_, _, err := w.processWatchEvent(t.Context(), &ringbuf.Record{RawSample: sample[:length]})
		if err == nil {
			t.Errorf("flags length %d: expected error", length)
		}
	}
	for length := 8; length < len(sample); length++ {
		_, _, err := w.processWatchEvent(t.Context(), &ringbuf.Record{RawSample: sample[:length]})
		if err == nil {
			t.Errorf("bind length %d: expected error", length)
		}
	}
	assertNoEvent(t, events)
}

func TestProcessWatchEventEmitsDecodedBind(t *testing.T) {
	events := make(chan Event, 2)
	_, ignore, err := New(&obi.Config{}, events).processWatchEvent(t.Context(), &ringbuf.Record{RawSample: watchSample(1, 8080)})
	if err != nil || !ignore {
		t.Fatalf("process bind event: ignore=%t, error=%v", ignore, err)
	}
	if event := testutil.ReadChannel(t, events, time.Second); event != (Event{Type: NewPort, Payload: 8080}) {
		t.Fatalf("unexpected event: %+v", event)
	}
	assertNoEvent(t, events)
}

func TestProcessWatchEventIgnoresUnknownFlags(t *testing.T) {
	events := make(chan Event, 1)
	_, ignore, err := New(&obi.Config{}, events).processWatchEvent(t.Context(), &ringbuf.Record{RawSample: watchSample(2, 8080)[:8]})
	if err != nil {
		t.Fatalf("process unknown event: %v", err)
	}
	if !ignore {
		t.Fatal("unknown watcher event must not be forwarded as a span")
	}
	assertNoEvent(t, events)
}

func TestRunReturnsWhenBufferedReadySendIsCanceled(t *testing.T) {
	events := make(chan Event, 100)
	w := New(&obi.Config{}, events)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	forwarded := false
	w.forward = func(context.Context, watchEventParser) { forwarded = true }
	w.Run(ctx)
	if !forwarded {
		t.Fatal("canceled Run did not reach the forwarder")
	}
	assertNoEvent(t, events)
}

func TestBlockedReadySendStopsOnCancellation(t *testing.T) {
	events := make(chan Event)
	base, cancel := context.WithCancel(t.Context())
	ctx := checkedContext{Context: base, checked: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- New(&obi.Config{}, events).sendEvent(ctx, Event{Type: Ready}) }()
	testutil.ReadChannel(t, ctx.checked, time.Second)
	cancel()
	if err := testutil.ReadChannel(t, done, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("send ready event: %v", err)
	}
	assertNoEvent(t, events)
}

func TestRunEmitsOneReadyAndStopsOnCancellation(t *testing.T) {
	events := make(chan Event, 100)
	w := New(&obi.Config{}, events)
	ctx, cancel := context.WithCancel(t.Context())
	parseErr := make(chan error, 1)
	w.forward = func(ctx context.Context, parse watchEventParser) {
		<-ctx.Done()
		_, _, err := parse(&ringbuf.Record{RawSample: watchSample(1, 8080)})
		parseErr <- err
	}
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	if event := testutil.ReadChannel(t, events, time.Second); event != (Event{Type: Ready}) {
		t.Fatalf("unexpected event: %+v", event)
	}
	cancel()
	if err := testutil.ReadChannel(t, parseErr, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("process bind event: %v", err)
	}
	testutil.ReadChannel(t, done, time.Second)
	assertNoEvent(t, events)
}

func watchSample(flags, payload uint64) []byte {
	sample := make([]byte, 16)
	binary.LittleEndian.PutUint64(sample, flags)
	binary.LittleEndian.PutUint64(sample[8:], payload)
	return sample
}

func assertNoEvent(t *testing.T, events <-chan Event) {
	t.Helper()
	select {
	case event := <-events:
		t.Fatalf("unexpected event: %+v", event)
	default:
	}
}

type checkedContext struct {
	context.Context
	checked chan struct{}
}

func (c checkedContext) Err() error {
	err := c.Context.Err()
	if err == nil {
		close(c.checked)
	}
	return err
}
