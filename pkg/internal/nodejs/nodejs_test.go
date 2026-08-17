// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/obi"
)

// nodejs.enabled is the global injection opt-out: with the flag off the
// injector stays disabled even when the application_runtime feature would
// otherwise trigger the agent for runtime metrics.
func TestEnabledFlagDisablesInjectionEntirely(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = false
	cfg.Metrics.Features = export.FeatureApplicationRuntime
	require.False(t, NewNodeInjector(&cfg).Enabled())

	cfg.NodeJS.Enabled = true
	require.True(t, NewNodeInjector(&cfg).Enabled())
}

func TestNewExecutableSkipsDeno(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = true
	cfg.TracePrinter = debug.TracePrinterText

	injector := NewNodeInjector(&cfg)
	require.True(t, injector.Enabled())
	require.NotPanics(t, func() {
		injector.NewExecutable(&ebpf.Instrumentable{Type: svc.InstrumentableDeno})
	})
}
