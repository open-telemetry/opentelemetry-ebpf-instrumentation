// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/selection"
)

// This example shows how a vendored host (collector, agent, control plane) typically
// drives DynamicSelector: start OBI once, then add/remove targets as workloads come
// and go — without reloading config.
//
//	go run ./examples/dynamicselector-host
//
// Optional: also select a concrete PID on this host.
//
//	PID=4242 go run ./examples/dynamicselector-host
func main() {
	// Adding shutdown hook for graceful stop.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	config := obi.DefaultConfig
	exportedSpans := msg.NewQueue[[]request.Span](
		msg.ChannelBufferLen(config.ChannelBufferLen), msg.Name("exportedSpans"))

	selector := discover.NewDynamicSelector()

	go printSpans(ctx, exportedSpans)
	go simulateHostDecisions(ctx, selector)

	log.Print("starting eBPF instrumentation with dynamic selector...")
	if err := instrumenter.Run(ctx, &config,
		instrumenter.OverrideAppExportQueue(exportedSpans),
		instrumenter.WithDynamicSelector(selector),
	); err != nil {
		fmt.Println("Error running eBPF instrumentation. Exiting: " + err.Error())
		os.Exit(1)
	}
	<-ctx.Done()
}

// simulateHostDecisions stands in for your orchestration loop: instrument a Deployment
// when the user enables a service, optionally pin a local PID, update attributes later,
// then tear the workload down.
func simulateHostDecisions(ctx context.Context, selector *discover.DynamicSelector) {
	checkout := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "payments",
			Name:      "checkout",
		},
	}
	opts := selection.DynamicOptions{
		ServiceName:      "checkout",
		ServiceNamespace: "payments",
		ResourceAttributes: map[string]string{
			"team":                   "payments",
			"deployment.environment": "staging",
		},
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}

	// All signals for the Deployment's pods (once kube metadata is available).
	if err := selector.AddK8sWorkload(checkout, opts); err != nil {
		log.Printf("add checkout deployment: %v", err)
		return
	}
	log.Printf("selected Deployment %s/%s for all signals", checkout.Namespace, checkout.Name)

	// Traces-only for an optional local process (sidecar, batch job, etc.).
	if pidEnv := os.Getenv("PID"); pidEnv != "" {
		pid, err := strconv.ParseUint(pidEnv, 10, 32)
		if err != nil {
			log.Printf("invalid PID %q: %v", pidEnv, err)
		} else {
			selector.Traces().AddPID(uint32(pid), selection.DynamicOptions{
				ServiceName: "local-helper",
			})
			log.Printf("selected PID %d for traces only", pid)
		}
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}

	// Enrich identity without re-adding the target. For PIDs materialized from the
	// workload, SetPID updates shared attributes used at export time.
	if pids, _ := selector.GetPIDs(); len(pids) > 0 {
		pid := pids[0]
		entry, ok := selector.GetPID(uint32(pid))
		if ok {
			if entry.ResourceAttributes == nil {
				entry.ResourceAttributes = map[string]string{}
			}
			entry.ResourceAttributes["cloud.region"] = "us-east-1"
			if selector.SetPID(entry) {
				log.Printf("updated attributes for PID %d", pid)
			}
		}
	} else if pidEnv := os.Getenv("PID"); pidEnv != "" {
		pid, _ := strconv.ParseUint(pidEnv, 10, 32)
		_ = selector.SetPID(selection.DynamicPIDEntry{
			PID:         app.PID(pid),
			ServiceName: "local-helper",
			ResourceAttributes: map[string]string{
				"cloud.region": "us-east-1",
			},
		})
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}

	if err := selector.RemoveK8sWorkload(checkout); err != nil {
		log.Printf("remove checkout deployment: %v", err)
		return
	}
	log.Printf("removed Deployment %s/%s", checkout.Namespace, checkout.Name)
}

func printSpans(ctx context.Context, input *msg.Queue[[]request.Span]) {
	spansInput := input.Subscribe()
	for {
		select {
		case <-ctx.Done():
			return
		case spans := <-spansInput:
			for _, s := range spans {
				jsonBytes, _ := s.MarshalJSON()
				fmt.Println(string(jsonBytes))
			}
		}
	}
}
