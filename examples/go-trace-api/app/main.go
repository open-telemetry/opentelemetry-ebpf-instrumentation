// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const listenAddress = ":8080"

var tracer = otel.Tracer(
	"go-trace-api-example",
	trace.WithInstrumentationVersion("1.0.0"),
)

var checkoutRequests = make(chan chan traceResponse)

type traceResponse struct {
	RootRecording  bool `json:"root_recording"`
	ChildRecording bool `json:"child_recording"`
}

func main() {
	go runCheckoutWorker()

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	http.HandleFunc("/trace", emitTrace)

	log.Printf("listening on %s", listenAddress)
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		log.Fatal(err)
	}
}

func emitTrace(w http.ResponseWriter, _ *http.Request) {
	result := make(chan traceResponse)
	checkoutRequests <- result
	response := <-result

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("write response: %v", err)
	}
}

func runCheckoutWorker() {
	for result := range checkoutRequests {
		result <- createCheckoutTrace()
	}
}

func createCheckoutTrace() traceResponse {
	ctx, root := tracer.Start(
		context.Background(),
		"checkout",
		trace.WithAttributes(
			attribute.String("example.order.id", "order-123"),
			attribute.Int("example.cart.items", 2),
		),
	)
	root.AddEvent(
		"checkout started",
		trace.WithAttributes(attribute.String("example.customer.tier", "gold")),
	)

	_, child := tracer.Start(
		ctx,
		"reserve inventory",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("example.inventory.sku", "sku-42"),
			attribute.Int("example.inventory.quantity", 2),
		),
	)
	child.SetStatus(codes.Ok, "")
	response := traceResponse{
		RootRecording:  root.IsRecording(),
		ChildRecording: child.IsRecording(),
	}
	child.End()
	root.End()

	return response
}
