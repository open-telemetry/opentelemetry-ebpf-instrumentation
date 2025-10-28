// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// OpenTelemetry-eBPF-instumentation is also designed to be vendored inside other components
// (for example, the OpenTelemetry Collector).
// This involves not only being able to instantiate it from a Go function, but also
// being able to inspect some internal communication channels to provide extra exporters
// or decorations.
func main() {
	// Adding shutdown hook for graceful stop.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// you can override here default configuration before passing it to Run
	config := obi.DefaultConfig
	// for example, we override the instrumentation ports from the PORT env, otherwise we provide some defaults
	if err := config.Port.UnmarshalText([]byte(os.Getenv("PORT"))); err != nil {
		log.Println("Error parsing PORT environment variable. Defaulting to 80,8080,443,8443: " + err.Error())
		config.Port.Ranges = []services.PortRange{{Start: 80}, {Start: 8080}, {Start: 443}, {Start: 8443}}
	}

	// the instrumenter creates internally some communication Queues, but we can override some of them
	// for inspection. In this case, we override the exporter queue to connect our own exporter
	// (If other exporters are defined in the config, like OTEL or Prometheus, they will use this queue also)
	exportedSpans := msg.NewQueue[[]request.Span](
		msg.ChannelBufferLen(config.ChannelBufferLen), msg.Name("exportedSpans"))

	// running 2 goroutines:
	// - one containing the vendored instrumentation
	// - another containing our own exporter
	go myOwnSpanExporter(ctx, exportedSpans)

	runVendoredInstrumenter(ctx, config, exportedSpans)
	<-ctx.Done()
}

func runVendoredInstrumenter(ctx context.Context, config obi.Config, exportedSpans *msg.Queue[[]request.Span]) {
	log.Print("starting eBPF instrumentation in vendored mode...")
	if err := instrumenter.Run(ctx, &config,
		// very important!! The exporter queue needs to be overridden here
		instrumenter.OverrideAppExportQueue(exportedSpans),
	); err != nil {
		fmt.Println("Error running eBPF instrumentation. Exiting: " + err.Error())
		os.Exit(1)
	}
}

func myOwnSpanExporter(ctx context.Context, input *msg.Queue[[]request.Span]) {
	log.Print("starting my own span exporter...")
	spansInput := input.Subscribe()
	for {
		select {
		case <-ctx.Done():
			log.Println("Context done. Exiting")
			return
		case spans := <-spansInput:
			log.Println("received a bunch of spans")
			for _, s := range spans {
				jsonBytes, _ := s.MarshalJSON()
				fmt.Println(string(jsonBytes))
			}
		}
	}
}
