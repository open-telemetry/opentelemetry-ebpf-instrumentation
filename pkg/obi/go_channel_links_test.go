// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/collector/pdata/ptrace"

	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func TestGoChannelLinksEnabled(t *testing.T) {
	enabled, disabled := true, false
	printer := func(p debug.TracePrinter) func(*Config) {
		return func(c *Config) { c.TracePrinter = p }
	}

	for _, test := range []struct {
		name     string
		explicit *bool
		setup    func(*Config)
		want     bool
	}{
		{name: "unset, metrics only", want: false},
		// spans leave OBI through the traces exporter
		{name: "unset, OTLP traces endpoint", setup: func(c *Config) { c.Traces.TracesEndpoint = "http://localhost:4318" }, want: true},
		{name: "unset, common OTLP endpoint", setup: func(c *Config) { c.Traces.CommonEndpoint = "http://localhost:4318" }, want: true},
		{name: "unset, debug traces protocol", setup: func(c *Config) { c.Traces.TracesProtocol = otelcfg.ProtocolDebug }, want: true},
		{name: "unset, endpoint provider", setup: func(c *Config) {
			c.Traces.OTLPEndpointProvider = func() (string, bool) { return "http://localhost:4318", true }
		}, want: true},
		{name: "unset, embedder traces export", setup: func(c *Config) {
			c.Traces.TracesExport = func(context.Context, ptrace.Traces) error { return nil }
		}, want: true},
		// ...or through the trace printer
		{name: "unset, JSON printer", setup: printer(debug.TracePrinterJSON), want: true},
		{name: "unset, text printer", setup: printer(debug.TracePrinterText), want: true},
		// any enabled printer keeps the probes, even one that does not show links
		{name: "unset, counter printer", setup: printer(debug.TracePrinterCounter), want: true},
		{name: "unset, printer disabled", setup: printer(debug.TracePrinterDisabled), want: false},
		{name: "explicit true, metrics only", explicit: &enabled, want: true},
		{name: "explicit false, OTLP traces", explicit: &disabled, setup: func(c *Config) {
			c.Traces.TracesEndpoint = "http://localhost:4318"
		}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig
			cfg.EBPF.GoChannelLinks = test.explicit
			if test.setup != nil {
				test.setup(&cfg)
			}
			assert.Equal(t, test.want, cfg.GoChannelLinksEnabled())
		})
	}

	var nilCfg *Config
	assert.False(t, nilCfg.GoChannelLinksEnabled())
}
