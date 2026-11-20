// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumenter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestConfigForExportQueueOverride(t *testing.T) {
	enabled, disabled := true, false
	for _, test := range []struct {
		name     string
		override bool
		explicit *bool
		want     *bool // nil: left unset, so it follows trace export
	}{
		{name: "no override", want: nil},
		{name: "explicit false without override", explicit: &disabled, want: &disabled},
		{name: "override queue keeps the links", override: true, want: &enabled},
		{name: "explicit true with override", override: true, explicit: &enabled, want: &enabled},
		{name: "explicit false wins over override", override: true, explicit: &disabled, want: &disabled},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := obi.DefaultConfig
			cfg.EBPF.GoChannelLinks = test.explicit
			ctxInfo := &global.ContextInfo{}
			if test.override {
				ctxInfo.OverrideAppExportQueue = msg.NewQueue[[]request.Span]()
			}

			runCfg := configForExportQueueOverride(&cfg, ctxInfo)

			assert.Equal(t, test.want, runCfg.EBPF.GoChannelLinks)
			// the caller's configuration is never modified
			assert.Equal(t, test.explicit, cfg.EBPF.GoChannelLinks)
		})
	}
}

// The caller's configuration stays usable for criteria updates when the run resolves the
// channel links from an export queue override.
func TestExportQueueOverrideKeepsCriteriaUpdatesCompatible(t *testing.T) {
	cfg := instrumentedConfig(t)
	require.Nil(t, cfg.EBPF.GoChannelLinks)

	updater := discover.NewCriteriaUpdater(cfg)
	ctxInfo := &global.ContextInfo{}
	OverrideAppExportQueue(msg.NewQueue[[]request.Span]())(ctxInfo)
	WithCriteriaUpdater(updater)(ctxInfo)

	runCfg := configForExportQueueOverride(cfg, ctxInfo)
	require.NotNil(t, runCfg.EBPF.GoChannelLinks)
	require.True(t, *runCfg.EBPF.GoChannelLinks)
	require.Nil(t, cfg.EBPF.GoChannelLinks)

	// Why the caller's configuration must stay untouched: with a canceled context, Update returns
	// only after its compatibility checks pass, while a modified configuration is rejected first.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, updater.Update(ctx, cfg), context.Canceled)

	// what a modified caller configuration would look like: rejected
	modified := *cfg
	modified.EBPF.GoChannelLinks = runCfg.EBPF.GoChannelLinks
	require.ErrorContains(t, updater.Update(ctx, &modified), "restart OBI")
}

func instrumentedConfig(t *testing.T) *obi.Config {
	t.Helper()
	cfg, err := obi.LoadConfig(nil)
	require.NoError(t, err)
	cfg.Discovery.DefaultExcludeInstrument = nil
	require.NoError(t, yaml.Unmarshal([]byte("discovery:\n  instrument:\n    - name: backend\n      exe_path: /srv/backend\n"), cfg))
	return cfg
}
