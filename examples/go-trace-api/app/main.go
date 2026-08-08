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

type traceResponse struct {
	CheckoutRecording  bool `json:"checkout_recording"`
	InventoryRecording bool `json:"inventory_recording"`
}

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	http.HandleFunc("/checkout", checkoutHandler)

	log.Printf("listening on %s", listenAddress)
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		log.Fatal(err)
	}
}

func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	ctx, checkout := tracer.Start(
		r.Context(),
		"checkout",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("example.order.id", "order-123"),
			attribute.Int("example.cart.items", 2),
		),
	)
	defer checkout.End()

	checkout.AddEvent(
		"checkout started",
		trace.WithAttributes(attribute.String("example.customer.tier", "gold")),
	)

	response := traceResponse{
		CheckoutRecording:  checkout.IsRecording(),
		InventoryRecording: reserveInventory(ctx),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("write response: %v", err)
	}
}

func reserveInventory(ctx context.Context) bool {
	_, child := tracer.Start(
		ctx,
		"reserve inventory",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("example.inventory.sku", "sku-42"),
			attribute.Int("example.inventory.quantity", 2),
		),
	)
	defer child.End()

	child.SetStatus(codes.Ok, "")

	return child.IsRecording()
}
