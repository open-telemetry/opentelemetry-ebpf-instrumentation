// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metric

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	api "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/metric/global"
)

type testReader struct {
	producer sdkProducer
	shutdown func(context.Context) error
}

type readerError struct{ name string }

func (e *readerError) Error() string { return e.name }

func (r *testReader) register(p sdkProducer) {
	r.producer = p
}

func (*testReader) temporality(InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func (*testReader) aggregation(kind InstrumentKind) sdkmetric.Aggregation {
	return DefaultAggregationSelector(kind)
}

func (r *testReader) Collect(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	return r.producer.produce(ctx, rm)
}

func (r *testReader) Shutdown(ctx context.Context) error {
	if r.shutdown == nil {
		return nil
	}
	return r.shutdown(ctx)
}

func TestMeterProviderAfterShutdownReturnsNoopMeter(t *testing.T) {
	reader := &testReader{}
	provider := NewMeterProvider(WithReader(reader))
	if err := provider.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown MeterProvider: %v", err)
	}

	meter := provider.Meter("after-shutdown")
	if meter == nil {
		t.Fatal("Meter returned nil after shutdown")
	}

	counter, err := meter.Int64Counter("requests")
	if err != nil {
		t.Fatalf("create counter: %v", err)
	}
	counter.Add(t.Context(), 1)

	var callbackCalls atomic.Int32
	gauge, err := meter.Float64ObservableGauge("load")
	if err != nil {
		t.Fatalf("create observable gauge: %v", err)
	}
	registration, err := meter.RegisterCallback(
		func(_ context.Context, observer api.Observer) error {
			callbackCalls.Add(1)
			observer.ObserveFloat64(gauge, 1)
			return nil
		},
		gauge,
	)
	if err != nil {
		t.Fatalf("register callback: %v", err)
	}

	var data metricdata.ResourceMetrics
	if err := reader.producer.produce(t.Context(), &data); err != nil {
		t.Fatalf("produce metrics: %v", err)
	}
	if got := len(data.ScopeMetrics); got != 0 {
		t.Fatalf("post-shutdown meter produced %d scope metrics", got)
	}
	if got := callbackCalls.Load(); got != 0 {
		t.Fatalf("post-shutdown callback called %d times", got)
	}
	if err := registration.Unregister(); err != nil {
		t.Fatalf("unregister callback: %v", err)
	}
}

func TestMeterProviderShutdownIsConcurrentAndIdempotent(t *testing.T) {
	shutdownErr := errors.New("reader shutdown failed")
	var calls atomic.Int32
	reader := &testReader{shutdown: func(context.Context) error {
		calls.Add(1)
		return shutdownErr
	}}
	provider := NewMeterProvider(WithReader(reader))

	const goroutines = 16
	start := make(chan struct{})
	results := make(chan error, goroutines)
	var workers sync.WaitGroup
	workers.Add(goroutines)
	for range goroutines {
		go func() {
			defer workers.Done()
			<-start
			results <- provider.Shutdown(t.Context())
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	var shutdownResults, repeatedResults int
	for err := range results {
		switch {
		case errors.Is(err, shutdownErr):
			shutdownResults++
		case errors.Is(err, ErrReaderShutdown):
			repeatedResults++
		default:
			t.Errorf("unexpected shutdown error: %v", err)
		}
	}
	if shutdownResults != 1 || repeatedResults != goroutines-1 {
		t.Errorf("shutdown results = (%d initial, %d repeated), want (1, %d)", shutdownResults, repeatedResults, goroutines-1)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("reader Shutdown called %d times, want 1", got)
	}
}

func TestMeterAndShutdownConcurrent(t *testing.T) {
	shutdownStarted := make(chan struct{})
	releaseShutdown := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseShutdown) }) }
	defer release()

	reader := &testReader{shutdown: func(ctx context.Context) error {
		close(shutdownStarted)
		select {
		case <-releaseShutdown:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	provider := NewMeterProvider(WithReader(reader))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	start := make(chan struct{})
	shutdownDone := make(chan error, 1)
	go func() {
		<-start
		shutdownDone <- provider.Shutdown(ctx)
	}()

	const goroutines = 16
	const callsPerWorker = 2
	meters := make(chan api.Meter, goroutines*callsPerWorker)
	var workers sync.WaitGroup
	workers.Add(goroutines)
	for range goroutines {
		go func() {
			defer workers.Done()
			<-start
			meters <- provider.Meter("concurrent")
			select {
			case <-shutdownStarted:
				meters <- provider.Meter("concurrent")
			case <-ctx.Done():
			}
		}()
	}
	workersDone := make(chan struct{})
	go func() {
		workers.Wait()
		close(workersDone)
	}()

	close(start)
	select {
	case <-shutdownStarted:
	case <-ctx.Done():
		t.Fatalf("wait for shutdown: %v", ctx.Err())
	}
	select {
	case <-workersDone:
	case <-ctx.Done():
		t.Fatalf("wait for Meter workers: %v", ctx.Err())
	}
	close(meters)

	var meterCalls int
	for meter := range meters {
		meterCalls++
		if meter == nil {
			t.Error("Meter returned nil during concurrent shutdown")
			continue
		}
		counter, err := meter.Int64Counter("requests")
		if err != nil {
			t.Errorf("create counter: %v", err)
			continue
		}
		counter.Add(ctx, 1)
	}
	if meterCalls != goroutines*callsPerWorker {
		t.Errorf("Meter called %d times, want %d", meterCalls, goroutines*callsPerWorker)
	}

	release()
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutdown MeterProvider: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("wait for shutdown completion: %v", ctx.Err())
	}
}

func TestObservableDuplicateDetectionSeparatesNumberKinds(t *testing.T) {
	const repeatedWarning = "Repeated observable instrument creation with callbacks."
	var logs strings.Builder
	logger := funcr.New(func(_, args string) { logs.WriteString(args) }, funcr.Options{Verbosity: 1})
	previousLogger := global.GetLogger()
	global.SetLogger(logger)
	t.Cleanup(func() { global.SetLogger(previousLogger) })

	t.Run("int does not mark float duplicate", func(t *testing.T) {
		meter := NewMeterProvider(WithReader(&testReader{})).Meter("cache-separation")
		_, err := meter.Int64ObservableGauge("usage", api.WithInt64Callback(func(context.Context, api.Int64Observer) error { return nil }))
		if err != nil {
			t.Fatalf("create int observable: %v", err)
		}
		logs.Reset()
		_, err = meter.Float64ObservableGauge("usage", api.WithFloat64Callback(func(context.Context, api.Float64Observer) error { return nil }))
		if err != nil {
			t.Fatalf("create float observable: %v", err)
		}
		if strings.Contains(logs.String(), repeatedWarning) {
			t.Error("first float observable was reported as a duplicate")
		}
	})

	t.Run("float duplicate is detected", func(t *testing.T) {
		meter := NewMeterProvider(WithReader(&testReader{})).Meter("float-duplicate")
		callback := api.WithFloat64Callback(func(context.Context, api.Float64Observer) error { return nil })
		if _, err := meter.Float64ObservableGauge("usage", callback); err != nil {
			t.Fatalf("create float observable: %v", err)
		}
		logs.Reset()
		if _, err := meter.Float64ObservableGauge("usage", callback); err != nil {
			t.Fatalf("create duplicate float observable: %v", err)
		}
		if !strings.Contains(logs.String(), repeatedWarning) {
			t.Error("duplicate float observable was not reported")
		}
	})

	t.Run("int duplicate remains detected", func(t *testing.T) {
		meter := NewMeterProvider(WithReader(&testReader{})).Meter("int-duplicate")
		callback := api.WithInt64Callback(func(context.Context, api.Int64Observer) error { return nil })
		if _, err := meter.Int64ObservableGauge("usage", callback); err != nil {
			t.Fatalf("create int observable: %v", err)
		}
		logs.Reset()
		if _, err := meter.Int64ObservableGauge("usage", callback); err != nil {
			t.Fatalf("create duplicate int observable: %v", err)
		}
		if !strings.Contains(logs.String(), repeatedWarning) {
			t.Error("duplicate int observable was not reported")
		}
	})
}

func TestCallbackRegistrationLifecycle(t *testing.T) {
	reader := NewManualReader()
	meter := NewMeterProvider(WithReader(reader)).Meter("callbacks")
	floatGauge, err := meter.Float64ObservableGauge("float.usage")
	if err != nil {
		t.Fatalf("create float gauge: %v", err)
	}
	intGauge, err := meter.Int64ObservableGauge("int.usage")
	if err != nil {
		t.Fatalf("create int gauge: %v", err)
	}

	var calls atomic.Int32
	registration, err := meter.RegisterCallback(func(_ context.Context, observer api.Observer) error {
		calls.Add(1)
		observer.ObserveFloat64(floatGauge, 1.5)
		observer.ObserveInt64(intGauge, 2)
		return nil
	}, floatGauge, intGauge)
	if err != nil {
		t.Fatalf("register callback: %v", err)
	}

	var data metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &data); err != nil {
		t.Fatalf("collect registered callback: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback called %d times, want 1", got)
	}
	names := metricNames(data)
	for _, name := range []string{"float.usage", "int.usage"} {
		if !names[name] {
			t.Errorf("collection missing metric %q", name)
		}
	}

	if err := registration.Unregister(); err != nil {
		t.Fatalf("unregister callback: %v", err)
	}
	if err := registration.Unregister(); err != nil {
		t.Fatalf("unregister callback again: %v", err)
	}
	data = metricdata.ResourceMetrics{}
	if err := reader.Collect(t.Context(), &data); err != nil {
		t.Fatalf("collect after unregister: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("callback called %d times after unregister, want 1", got)
	}
	if got := len(data.ScopeMetrics); got != 0 {
		t.Errorf("collection after unregister has %d scope metrics, want 0", got)
	}
}

func TestMeterProviderShutdownPreservesReaderErrors(t *testing.T) {
	first := &readerError{name: "first reader"}
	second := errors.New("second reader")
	provider := NewMeterProvider(
		WithReader(&testReader{shutdown: func(context.Context) error { return first }}),
		WithReader(&testReader{shutdown: func(context.Context) error { return second }}),
	)

	err := provider.Shutdown(t.Context())
	if !errors.Is(err, first) {
		t.Errorf("Shutdown error %v does not contain first reader error", err)
	}
	if !errors.Is(err, second) {
		t.Errorf("Shutdown error %v does not contain second reader error", err)
	}
	var typed *readerError
	if !errors.As(err, &typed) || typed != first {
		t.Errorf("Shutdown error %v does not preserve reader error type", err)
	}
}

func metricNames(data metricdata.ResourceMetrics) map[string]bool {
	names := make(map[string]bool)
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			names[metric.Name] = true
		}
	}
	return names
}
