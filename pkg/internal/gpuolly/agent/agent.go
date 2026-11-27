// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package agent reports the metrics of the NVIDIA GPUs of the host, which it
// reads through the embedded NVML helper.
package agent // import "go.opentelemetry.io/obi/pkg/internal/gpuolly/agent"

import (
	"context"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/internal/gpuolly"
	"go.opentelemetry.io/obi/pkg/internal/nvml"
	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

// OBI sees the filesystem of the host through its init process, which
// requires OBI to share the PID namespace of the host.
const hostRoot = "/proc/1/root"

func alog() *slog.Logger {
	return slog.With("component", "gpuolly.Agent")
}

// Run reports the GPU device metrics through the enabled metric exporters
// until ctx is done.
func Run(ctx context.Context, ctxInfo *global.ContextInfo, cfg *obi.Config) error {
	alog().Info("starting GPU device metrics", "interval", cfg.GPUDevices.Interval)

	snapshot := &gpuolly.Snapshot{}
	selectorCfg := &attributes.SelectorConfig{
		SelectionCfg:            cfg.Attributes.Select,
		UseV2Selection:          cfg.Attributes.UseV2Selection,
		ExtraGroupAttributesCfg: cfg.Attributes.ExtraGroupAttributes,
	}
	if selectorCfg.SelectionCfg == nil {
		selectorCfg.SelectionCfg = attributes.Selection{}
	}

	g, ctx := errgroup.WithContext(ctx)
	if cfg.OTELMetrics.EndpointEnabled() {
		g.Go(func() error { return otel.ReportGPUMetrics(ctx, ctxInfo, &cfg.OTELMetrics, selectorCfg, snapshot) })
	}
	if cfg.Prometheus.EndpointEnabled() {
		g.Go(func() error { return prom.ReportGPUMetrics(ctx, ctxInfo, &cfg.Prometheus, selectorCfg, snapshot) })
	}

	g.Go(func() error {
		resolve := newProcessResolver(ctx, ctxInfo, cfg).resolve
		nvml.Run(ctx, nvml.RunnerConfig{Interval: cfg.GPUDevices.Interval, HostRoot: hostRoot}, func(s sample.Sample) {
			snapshot.Store(gpuolly.Convert(&s, resolve))
		})
		return nil
	})

	return g.Wait()
}
