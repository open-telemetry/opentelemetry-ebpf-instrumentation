// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"

	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/components/netolly/export"
	"go.opentelemetry.io/obi/pkg/components/netolly/deduper"
	"go.opentelemetry.io/obi/pkg/components/netolly/flow"
	//"go.opentelemetry.io/obi/pkg/components/netolly/transform/cidr"
	"go.opentelemetry.io/obi/pkg/components/netolly/transform/k8s"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	//"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	//"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// mockable functions for testing
var newMapTracer = func(f *Flows, out *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	return f.mapTracer.TraceLoop(out)
}

var newRingBufTracer = func(f *Flows, k8sDecorator *k8s.Decorator,out *msg.Queue[ebpf.Record]) swarm.RunFunc {
	flowDecorator := flow.FlowDecorator(f.agentIP.String(), f.makeInterfaceNamer())

	return f.rbTracer.TraceLoop(k8sDecorator, flowDecorator, out)
}

func (f *Flows) makeInterfaceNamer() flow.InterfaceNamer {
	ifaceNamer := f.interfaceNamer

	if f.cfg.NetworkFlows.Deduper == deduper.DeduperFirstCome {
		ifaceNamer = func(_ int) string { return "" }
	}

	return ifaceNamer
}

// buildPipeline defines the different nodes in the Beyla's NetO11y module,
// as well as how they are interconnected (in its Connect() method)
func (f *Flows) buildPipeline(ctx context.Context) (*swarm.Runner, error) {
	alog := alog()

	alog.Debug("creating flows' processing graph")

	selectorCfg := &attributes.SelectorConfig{
		SelectionCfg:            f.cfg.Attributes.Select,
		ExtraGroupAttributesCfg: f.cfg.Attributes.ExtraGroupAttributes,
	}

	k8sDecorator, err := k8s.NewDecorator(ctx, &f.cfg.Attributes.Kubernetes, f.ctxInfo.K8sInformer)

	if err != nil {
		return nil, fmt.Errorf("error creating k8s decorator: %w", err)
	}

	swi := &swarm.Instancer{}
	// Start nodes: those generating flow records (reading them from eBPF)
	ebpfFlows := msg.NewQueue[ebpf.Record](
		msg.ChannelBufferLen(f.cfg.ChannelBufferLen),
		msg.ClosingAttempts(2), // queue won't close until both tracers try to close it
	)

	// swi.Add(swarm.DirectInstance(newMapTracer(f, ebpfFlows)), swarm.WithID("MapTracer"))
	swi.Add(swarm.DirectInstance(newRingBufTracer(f, k8sDecorator, ebpfFlows)), swarm.WithID("RingBufTracer"))

	/*
		filteredFlows := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(f.cfg.ChannelBufferLen))
		swi.Add(filter.ByAttribute(f.cfg.Filters.Network, nil, selectorCfg.ExtraGroupAttributesCfg, ebpf.RecordStringGetters, decoratedFlows, filteredFlows),
			swarm.WithID("AttributeFilter"))

		// Terminal nodes export the flow record information out of the pipeline: OTEL, Prom and printer.
		// Not all the nodes are mandatory here. Is the responsibility of each Provider function to decide
		// whether each node is going to be instantiated or just ignored.
		f.cfg.Attributes.Select.Normalize()
		swi.Add(otel.NetMetricsExporterProvider(f.ctxInfo, &otel.NetMetricsConfig{
			Metrics:         &f.cfg.Metrics,
			SelectorCfg:     selectorCfg,
			GloballyEnabled: f.cfg.NetworkFlows.Enable,
		}, filteredFlows), swarm.WithID("OTelExporter"))

	*/

	swi.Add(prom.NetPrometheusEndpoint(f.ctxInfo, &prom.NetPrometheusConfig{
		Config:          &f.cfg.Prometheus,
		SelectorCfg:     selectorCfg,
		GloballyEnabled: f.cfg.NetworkFlows.Enable,
	}, ebpfFlows), swarm.WithID("PrometheusExporter"))

	swi.Add(swarm.DirectInstance(export.FlowPrinterProvider(f.cfg.NetworkFlows.Print, ebpfFlows)),
	swarm.WithID("FlowPrinter"))

	return swi.Instance(ctx)
}
