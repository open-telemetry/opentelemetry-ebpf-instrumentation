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
	version        = os.Getenv("OTEL_TEST_VERSION")
	tracer         trace.Tracer
	rootContext    = context.Background()
	nameSuffix     string
	externalTracer func(context.Context) trace.Tracer
	work           = make(chan func())
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
	http.HandleFunc("/activation", func(w http.ResponseWriter, r *http.Request) {
		if !autoSDKActivated(r) {
			http.Error(w, "Auto SDK is not active", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	http.HandleFunc("/spans", func(w http.ResponseWriter, r *http.Request) {
		runWithTracer(r, emitNestedSpans)
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/page-boundary", func(w http.ResponseWriter, r *http.Request) {
		var spanAddress uintptr
		runWithTracer(r, func() {
			spanAddress = emitPageBoundarySpans()
		})
		if spanAddress == 0 {
			http.Error(w, "could not allocate a page-aligned Auto SDK span", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Auto-SDK-Span-Address", fmt.Sprintf("%x", spanAddress))
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/oversized", func(w http.ResponseWriter, r *http.Request) {
		runWithTracer(r, emitOversizedThenRoot)
		w.WriteHeader(http.StatusOK)
	})

	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		panic(err)
	}
}

func autoSDKActivated(r *http.Request) bool {
	var recording bool
	runWithTracer(r, func() {
		_, span := tracer.Start(rootContext, spanName("activation-probe"))
		recording = span.IsRecording() && span.SpanContext().IsValid()
		span.End()
	})
	return recording
}

func runWithTracer(r *http.Request, f func()) {
	runOnWorker(func() {
		rootContext = context.Background()
		nameSuffix = r.URL.Query().Get("context")
		if nameSuffix != "" {
			sc := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
			})
			rootContext = trace.ContextWithSpanContext(rootContext, sc)
			if nameSuffix == "remote" {
				rootContext = trace.ContextWithRemoteSpanContext(context.Background(), sc)
			}
		}
		if externalTracer != nil && (r.URL.Query().Get("sdk") == "external" ||
			os.Getenv("OTEL_TEST_SDK") != "embedded" && r.URL.Query().Get("sdk") != "embedded") {
			tracer = externalTracer(rootContext)
		} else {
			tracer = trace.SpanFromContext(rootContext).TracerProvider().Tracer("go-auto-sdk-activation-test",
				trace.WithInstrumentationVersion("v1.0.0"),
				trace.WithSchemaURL("https://opentelemetry.io/schemas/1.30.0"))
		}
		nameSuffix += r.URL.Query().Get("sdk")
		f()
	})
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
		rootContext,
		spanName("root"),
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.String("obitest.activation.version", version),
			attribute.Bool("obitest.activation.root", true),
		),
	)
	if !root.IsRecording() || !root.SpanContext().IsValid() {
		panic("root span is not recording with a valid context")
	}
	root.AddEvent(
		"root event",
		trace.WithAttributes(attribute.String("obitest.event.detail", "preserved")),
	)

	childTracer := root.TracerProvider().Tracer("go-auto-sdk-activation-test")
	_, child := childTracer.Start(
		ctx,
		spanName("child-before-rename"),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.Int("obitest.activation.answer", 42)),
	)
	if !child.IsRecording() || !child.SpanContext().IsValid() {
		panic("child span is not recording with a valid context")
	}
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
	suffix := version
	if nameSuffix != "" {
		suffix += "-" + nameSuffix
	}
	return fmt.Sprintf("auto-sdk-%s-%s", name, suffix)
}
