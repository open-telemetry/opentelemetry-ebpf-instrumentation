// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	msgh "go.opentelemetry.io/obi/pkg/internal/helpers/msg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/export"
	stats "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/transform/k8s"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/statsolly/cidr"
)

// mockable functions for testing

var newRingBufTracer = func(ctx context.Context, s *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return s.rbTracer.TraceLoop(ctx, out)
}

// buildPipeline defines the different nodes in the OBI's StatsO11y module,
// as well as how they are interconnected (in its Connect() method)
func (s *Stats) buildPipeline(ctx context.Context) (*swarm.Runner, error) {
	alog := alog()

	alog.Debug("creating stats processing graph")

	selectorCfg := &attributes.SelectorConfig{
		SelectionCfg:            s.cfg.Attributes.Select,
		ExtraGroupAttributesCfg: s.cfg.Attributes.ExtraGroupAttributes,
	}

	swi := &swarm.Instancer{}
	// Start nodes: those generating stats (reading them from eBPF)
	ebpfStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "ebpfStats")
	swi.Add(swarm.DirectInstance(newRingBufTracer(ctx, s, ebpfStats)), swarm.WithID("RingBufTracer"))

	// Middle nodes: transforming stats and passing them to the next stage in the pipeline.
	// Many of the nodes here are not mandatory. It's decision of each InstanceFunc to decide
	// whether the node needs to be instantiated or just bypass their input/output channels.
	kubeDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "kubeDecoratedStats")
	swi.Add(k8s.MetadataDecoratorProvider(ctx, &s.cfg.Attributes.Kubernetes, s.ctxInfo.K8sInformer,
		ebpfStats, kubeDecoratedStats), swarm.WithID("K8sMetadataDecorator"))

	dnsDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "dnsDecoratedStats")
	swi.Add(stats.ReverseDNSProvider(&s.cfg.Stats.ReverseDNS, kubeDecoratedStats, dnsDecoratedStats),
		swarm.WithID("ReverseDNS"))

	geoIPDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "geoIPDecoratedStats")
	swi.Add(stats.GeoIPProvider(&s.cfg.Stats.GeoIP,
		dnsDecoratedStats, geoIPDecoratedStats), swarm.WithID("GeoIPDecorator"))

	cidrDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "cidrDecoratedStats")
	swi.Add(cidr.DecoratorProvider(cidr.Definitions(s.cfg.Stats.CIDRs), geoIPDecoratedStats, cidrDecoratedStats),
		swarm.WithID("CIDRDecorator"))

	decoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "decoratedStats")
	swi.Add(func(_ context.Context) (swarm.RunFunc, error) {
		return stats.Decorate(s.agentIP, cidrDecoratedStats, decoratedStats), nil
	}, swarm.WithID("StatsDecorator"))

	filteredStats := s.ctxInfo.OverrideStatsExportQueue
	if filteredStats == nil {
		filteredStats = msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "filteredStats")
	}
	swi.Add(filter.ByAttribute(s.cfg.Filters.Network, nil, selectorCfg.ExtraGroupAttributesCfg, ebpf.StatStringGetters, decoratedStats, filteredStats),
		swarm.WithID("AttributeFilter"))

	// Terminal nodes export the stats record information out of the pipeline: OTEL, Prom and printer.
	// Not all the nodes are mandatory here. Is the responsibility of each Provider function to decide
	// whether each node is going to be instantiated or just ignored.
	swi.Add(otel.StatsMetricsExporterProvider(s.ctxInfo, &otel.StatsMetricsConfig{
		Metrics:     &s.cfg.OTELMetrics,
		SelectorCfg: selectorCfg,
		CommonCfg:   &s.cfg.Metrics,
	}, filteredStats), swarm.WithID("OTelExporter"))

	swi.Add(prom.StatsPrometheusEndpoint(s.ctxInfo, &prom.StatsPrometheusConfig{
		Config:      &s.cfg.Prometheus,
		SelectorCfg: selectorCfg,
		CommonCfg:   &s.cfg.Metrics,
	}, filteredStats), swarm.WithID("PrometheusExporter"))

	swi.Add(swarm.DirectInstance(export.StatPrinterProvider(s.cfg.Stats.Print, filteredStats)),
		swarm.WithID("StatPrinter"))

	return swi.Instance(ctx)
}
