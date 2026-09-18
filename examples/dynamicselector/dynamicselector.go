// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/selection"
)

// This example exposes a tiny HTTP control plane over DynamicSelector so a host can
// decide at runtime which PIDs or Kubernetes workloads to instrument — and which
// signals / service identity to attach — without a config reload.
//
// For a linear host-style walkthrough (no HTTP), see examples/dynamicselector-host.
//
//	go run ./examples/dynamicselector
//
//	# instrument PID 4242 for traces + app metrics
//	curl -X POST localhost:7777/select -d '{
//	  "pid": 4242,
//	  "service_name": "checkout",
//	  "service_namespace": "payments",
//	  "resource_attributes": {"team": "payments"},
//	  "signals": ["traces", "app_metrics"]
//	}'
//
//	# or select a Deployment (requires kube metadata enrichment)
//	curl -X POST localhost:7777/select -d '{
//	  "kind": "Deployment",
//	  "namespace": "payments",
//	  "name": "checkout",
//	  "service_name": "checkout",
//	  "service_namespace": "payments",
//	  "resource_attributes": {"team": "payments"}
//	}'
//
//	# later, enrich attributes for an already-selected PID
//	curl -X PATCH localhost:7777/select -d '{
//	  "pid": 4242,
//	  "service_name": "checkout",
//	  "service_namespace": "payments",
//	  "resource_attributes": {"team": "payments", "cloud.region": "us-east-1"}
//	}'
//
//	curl -X DELETE localhost:7777/select/4242
//	curl -X DELETE 'localhost:7777/select/workload?kind=Deployment&namespace=payments&name=checkout'
func main() {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	config := obi.DefaultConfig

	exportedSpans := msg.NewQueue[[]request.Span](
		msg.ChannelBufferLen(config.ChannelBufferLen), msg.Name("exportedSpans"))

	selector := discover.NewDynamicSelector()

	go myOwnSpanExporter(ctx, exportedSpans)
	go serveControlPlane(ctx, selector)

	runVendoredInstrumenter(ctx, config, exportedSpans, selector)
	<-ctx.Done()
}

func runVendoredInstrumenter(
	ctx context.Context,
	config obi.Config,
	exportedSpans *msg.Queue[[]request.Span],
	selector *discover.DynamicSelector,
) {
	log.Print("starting eBPF instrumentation with dynamic selector...")
	if err := instrumenter.Run(ctx, &config,
		instrumenter.OverrideAppExportQueue(exportedSpans),
		instrumenter.WithDynamicSelector(selector),
	); err != nil {
		fmt.Println("Error running eBPF instrumentation. Exiting: " + err.Error())
		os.Exit(1)
	}
}

type telemetrySignal string

const (
	signalTraces         telemetrySignal = "traces"
	signalAppMetrics     telemetrySignal = "app_metrics"
	signalNetworkMetrics telemetrySignal = "network_metrics"
	signalStatsMetrics   telemetrySignal = "stats_metrics"
)

func (s telemetrySignal) valid() bool {
	switch s {
	case signalTraces, signalAppMetrics, signalNetworkMetrics, signalStatsMetrics:
		return true
	default:
		return false
	}
}

type selectRequest struct {
	// PID selects a concrete process. Mutually exclusive with Kind/Namespace/Name.
	PID uint32 `json:"pid"`
	// Kind/Namespace/Name select a Kubernetes workload (e.g. Deployment).
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`

	ServiceName        string            `json:"service_name"`
	ServiceNamespace   string            `json:"service_namespace"`
	ResourceAttributes map[string]string `json:"resource_attributes"`
	// Signals chooses which views to enable. Empty means all signals.
	Signals []telemetrySignal `json:"signals"`
}

func (r selectRequest) workloadRef() (selection.K8sWorkloadRef, bool) {
	if r.Kind == "" && r.Namespace == "" && r.Name == "" {
		return selection.K8sWorkloadRef{}, false
	}
	return selection.K8sWorkloadRef{Kind: r.Kind, Namespace: r.Namespace, Name: r.Name}, true
}

func serveControlPlane(ctx context.Context, selector *discover.DynamicSelector) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /select", func(w http.ResponseWriter, r *http.Request) {
		req, ok := decodeSelectRequest(w, r)
		if !ok {
			return
		}
		opts := selection.DynamicOptions{
			ServiceName:        req.ServiceName,
			ServiceNamespace:   req.ServiceNamespace,
			ResourceAttributes: req.ResourceAttributes,
		}
		if ref, isWorkload := req.workloadRef(); isWorkload {
			if len(req.Signals) > 0 {
				http.Error(w, "workload selection applies to all signals; omit signals", http.StatusBadRequest)
				return
			}
			if err := selector.AddK8sWorkload(ref, opts); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			log.Printf("selected %s %s/%s service=%q",
				ref.Kind, ref.Namespace, ref.Name, req.ServiceName)
			writeJSON(w, map[string]any{"status": "selected", "workload": ref})
			return
		}
		addPIDToSignals(selector, req.PID, opts, req.Signals)
		log.Printf("selected PID %d service=%q signals=%v", req.PID, req.ServiceName, req.Signals)
		writeJSON(w, map[string]any{"status": "selected", "pid": req.PID})
	})

	mux.HandleFunc("PATCH /select", func(w http.ResponseWriter, r *http.Request) {
		req, ok := decodeSelectRequest(w, r)
		if !ok {
			return
		}
		if req.PID == 0 {
			http.Error(w, "pid is required for attribute updates", http.StatusBadRequest)
			return
		}
		if !selector.SetPID(selection.DynamicPIDEntry{
			PID:                app.PID(req.PID),
			ServiceName:        req.ServiceName,
			ServiceNamespace:   req.ServiceNamespace,
			ResourceAttributes: req.ResourceAttributes,
		}) {
			http.Error(w, "pid is not currently selected", http.StatusNotFound)
			return
		}
		log.Printf("updated PID %d service=%q", req.PID, req.ServiceName)
		writeJSON(w, map[string]any{"status": "updated", "pid": req.PID})
	})

	mux.HandleFunc("DELETE /select/{pid}", func(w http.ResponseWriter, r *http.Request) {
		pid, err := strconv.ParseUint(r.PathValue("pid"), 10, 32)
		if err != nil {
			http.Error(w, "invalid pid", http.StatusBadRequest)
			return
		}
		selector.RemovePIDs(uint32(pid))
		log.Printf("removed PID %d", pid)
		writeJSON(w, map[string]any{"status": "removed", "pid": pid})
	})

	mux.HandleFunc("DELETE /select/workload", func(w http.ResponseWriter, r *http.Request) {
		ref := selection.K8sWorkloadRef{
			Kind:      r.URL.Query().Get("kind"),
			Namespace: r.URL.Query().Get("namespace"),
			Name:      r.URL.Query().Get("name"),
		}
		if err := selector.RemoveK8sWorkload(ref); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("removed %s %s/%s", ref.Kind, ref.Namespace, ref.Name)
		writeJSON(w, map[string]any{"status": "removed", "workload": ref})
	})

	mux.HandleFunc("GET /select", func(w http.ResponseWriter, _ *http.Request) {
		pids, _ := selector.GetPIDs()
		entries := make([]selection.DynamicPIDEntry, 0, len(pids))
		for _, pid := range pids {
			if entry, ok := selector.GetPID(uint32(pid)); ok {
				entries = append(entries, entry)
			}
		}
		writeJSON(w, map[string]any{
			"pids":      entries,
			"workloads": selector.GetK8sWorkloads(),
		})
	})

	addr := ":7777"
	if v := os.Getenv("CONTROL_ADDR"); v != "" {
		addr = v
	}
	server := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()

	log.Printf("dynamic selector control plane listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("control plane stopped: %v", err)
	}
}

func addPIDToSignals(
	selector *discover.DynamicSelector,
	pid uint32,
	opts selection.DynamicOptions,
	signals []telemetrySignal,
) {
	if len(signals) == 0 {
		selector.AddPID(pid, opts)
		return
	}
	for _, s := range signals {
		switch s {
		case signalTraces:
			selector.Traces().AddPID(pid, opts)
		case signalAppMetrics:
			selector.AppMetrics().AddPID(pid, opts)
		case signalNetworkMetrics:
			selector.NetworkMetrics().AddPID(pid, opts)
		case signalStatsMetrics:
			selector.StatsMetrics().AddPID(pid, opts)
		}
	}
}

func decodeSelectRequest(w http.ResponseWriter, r *http.Request) (selectRequest, bool) {
	var req selectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return selectRequest{}, false
	}
	_, isWorkload := req.workloadRef()
	if req.PID == 0 && !isWorkload {
		http.Error(w, "pid or kind/namespace/name is required", http.StatusBadRequest)
		return selectRequest{}, false
	}
	if req.PID != 0 && isWorkload {
		http.Error(w, "specify either pid or kind/namespace/name, not both", http.StatusBadRequest)
		return selectRequest{}, false
	}
	for _, s := range req.Signals {
		if !s.valid() {
			http.Error(w, fmt.Sprintf("invalid signal %q", s), http.StatusBadRequest)
			return selectRequest{}, false
		}
	}
	return req, true
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
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
