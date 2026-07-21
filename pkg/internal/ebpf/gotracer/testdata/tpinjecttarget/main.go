// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Command tpinjecttarget is a small helper binary used by the gotracer
// privileged test (TestGoSDKTraceparentNotDuplicated). On demand it issues an
// HTTP/1 request that already carries its own `traceparent` to its own loopback
// server, which reports how many `Traceparent` header values it received. Two
// modes drive the two test scenarios:
//
//   - "SDK": the request is made under an OpenTelemetry Go SDK span (obtained
//     BEFORE SetTracerProvider, so Start routes through global.(*tracer).Start,
//     where OBI detects the SDK and marks the process). OBI must NOT add a
//     second traceparent -> receiver sees 1.
//   - "PLAIN": the request sets its own traceparent by hand, without ever
//     touching the global tracer, so OBI does not detect an SDK and injects as
//     usual -> receiver sees 2. This is the control that proves the injection
//     path is active and the test can actually observe a duplicate.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// A valid W3C traceparent used by the PLAIN (non-SDK) control mode.
const staticTraceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func main() {
	// Obtain the tracer BEFORE installing the SDK provider so that, in SDK mode,
	// Start() routes through global.(*tracer).Start (the uprobe where OBI
	// detects the SDK). Obtaining it here does not create a span, so it does not
	// mark the process on its own.
	tracer := otel.Tracer("tpinjecttarget")

	tp := sdktrace.NewTracerProvider()
	defer func() { _ = tp.Shutdown(context.Background()) }()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Loopback server that reports how many Traceparent header values arrived.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%d", len(r.Header.Values("Traceparent")))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}
	go func() { _ = http.Serve(ln, mux) }()

	url := "http://" + ln.Addr().String() + "/"

	// Signal readiness only after the listener is up.
	fmt.Println("READY")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch scanner.Text() {
		case "SDK":
			report(doSDKRequest(tracer, url))
		case "PLAIN":
			report(doPlainRequest(url))
		case "EXIT":
			return
		}
	}
}

func report(count string, err error) {
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		return
	}
	fmt.Printf("TP_COUNT=%s\n", count)
}

// doSDKRequest starts an SDK span (routing through global.(*tracer).Start ->
// delegate) and lets the propagator write the span's traceparent.
func doSDKRequest(tracer trace.Tracer, url string) (string, error) {
	ctx, span := tracer.Start(context.Background(), "call")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", err
	}
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
	return do(req)
}

// doPlainRequest writes its own traceparent by hand, without any SDK span, so
// OBI does not detect a self-instrumented process and injects as usual.
func doPlainRequest(url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Traceparent", staticTraceparent)
	return do(req)
}

func do(req *http.Request) (string, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
