// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	listenAddress         = ":8090"
	oversizedAttrLen      = 20 * 1024
	pageBoundarySearchMax = 2048
)

var (
	version = os.Getenv("OTEL_TEST_VERSION")
	tracer  = otel.Tracer(
		"go-auto-sdk-activation-test",
		trace.WithInstrumentationVersion("v1.0.0"),
		trace.WithSchemaURL("https://opentelemetry.io/schemas/1.30.0"),
	)
	work = make(chan func())
)

func init() {
	go func() {
		for f := range work {
			f()
		}
	}()
}

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/activation", func(w http.ResponseWriter, _ *http.Request) {
		if !autoSDKActivated() {
			http.Error(w, "Auto SDK is not active", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	http.HandleFunc("/spans", func(w http.ResponseWriter, _ *http.Request) {
		runOnWorker(emitNestedSpans)
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/page-boundary", func(w http.ResponseWriter, _ *http.Request) {
		var spanAddress uintptr
		runOnWorker(func() {
			spanAddress = emitPageBoundarySpans()
		})
		if spanAddress == 0 {
			http.Error(w, "could not allocate a page-aligned Auto SDK span", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Auto-SDK-Span-Address", fmt.Sprintf("%x", spanAddress))
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/oversized", func(w http.ResponseWriter, _ *http.Request) {
		runOnWorker(emitOversizedThenRoot)
		w.WriteHeader(http.StatusOK)
	})

	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		panic(err)
	}
}

func autoSDKActivated() bool {
	var recording bool
	runOnWorker(func() {
		_, span := tracer.Start(context.Background(), spanName("activation-probe"))
		recording = span.IsRecording()
		span.End()
	})
	return recording
}

func runOnWorker(f func()) {
	done := make(chan struct{})
	work <- func() {
		f()
		close(done)
	}
	<-done
}

func emitNestedSpans() {
	ctx, root := tracer.Start(
		context.Background(),
		spanName("root"),
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.String("obitest.activation.version", version),
			attribute.Bool("obitest.activation.root", true),
		),
	)
	root.AddEvent(
		"root event",
		trace.WithAttributes(attribute.String("obitest.event.detail", "preserved")),
	)

	_, child := tracer.Start(
		ctx,
		spanName("child-before-rename"),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.Int("obitest.activation.answer", 42)),
	)
	child.SetName(spanName("child"))
	child.SetStatus(codes.Error, "expected test status")
	child.RecordError(
		errors.New("expected test error"),
		trace.WithAttributes(attribute.String("error.detail", "preserved")),
	)
	child.End()
	root.End()
}

func emitPageBoundarySpans() uintptr {
	spans := make([]trace.Span, 0, pageBoundarySearchMax)
	for range pageBoundarySearchMax {
		ctx, span := tracer.Start(context.Background(), spanName("page-boundary-search"))
		spans = append(spans, span)
		value := reflect.ValueOf(span)
		if value.Kind() == reflect.Pointer &&
			value.Pointer()%uintptr(os.Getpagesize()) == 0 {
			span.SetName(spanName("page-boundary-root"))
			_, child := tracer.Start(ctx, spanName("page-boundary-child"))
			child.End()
			span.End()
			runtime.KeepAlive(spans)
			return value.Pointer()
		}
		span.End()
	}
	runtime.KeepAlive(spans)
	return 0
}

func emitOversizedThenRoot() {
	_, oversized := tracer.Start(
		context.Background(),
		spanName("oversized"),
		trace.WithAttributes(attribute.String("oversized.value", strings.Repeat("x", oversizedAttrLen))),
	)
	oversized.End()

	_, after := tracer.Start(context.Background(), spanName("after-oversized"))
	after.End()
}

func spanName(name string) string {
	return fmt.Sprintf("auto-sdk-%s-%s", name, version)
}
