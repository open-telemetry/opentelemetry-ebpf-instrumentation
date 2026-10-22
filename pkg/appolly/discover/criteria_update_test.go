// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func criteriaConfig(t *testing.T, definitions string) *obi.Config {
	t.Helper()
	cfg, err := obi.LoadConfig(nil)
	require.NoError(t, err)
	cfg.Discovery.DefaultExcludeInstrument = nil
	require.NoError(t, yaml.Unmarshal([]byte("discovery:\n  instrument:\n"+definitions), cfg))
	return cfg
}

func TestCriteriaUpdaterRejectsIncompatibleConfig(t *testing.T) {
	initial := criteriaConfig(t, "    - name: backend\n      exe_path: /srv/backend\n")
	tests := map[string]func(*obi.Config){
		"service name": func(c *obi.Config) { c.Discovery.Instrument[0].Name = "renamed" },
		"namespace":    func(c *obi.Config) { c.Discovery.Instrument[0].Namespace = "other" },
		"sampler": func(c *obi.Config) {
			c.Discovery.Instrument[0].SamplerConfig = &services.SamplerConfig{Name: services.SamplerAlwaysOff}
		},
		"exports": func(c *obi.Config) { c.Discovery.Instrument[0].ExportModes = services.NewExportModes() },
		"routes": func(c *obi.Config) {
			c.Discovery.Instrument[0].Routes = &services.CustomRoutesConfig{Incoming: []string{"/items/:id"}}
		},
		"exporter":       func(c *obi.Config) { c.Prometheus.Port = 9000 },
		"global sampler": func(c *obi.Config) { c.Traces.SamplerConfig.Name = services.SamplerAlwaysOff },
		"protocol":       func(c *obi.Config) { c.OTELMetrics.Instrumentations = nil },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			next := criteriaConfig(t, "    - name: backend\n      exe_path: /srv/backend\n")
			change(next)
			updater := NewCriteriaUpdater(initial)
			err := updater.Update(t.Context(), next)
			require.ErrorContains(t, err, "restart OBI")
		})
	}
}

func TestCriteriaRefreshRunningProcesses(t *testing.T) {
	original := processInfo
	t.Cleanup(func() { processInfo = original })
	processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
		parent := app.PID(0)
		if p.pid == 12 {
			parent = 11
		}
		return &services.ProcessInfo{Pid: p.pid, PPid: parent, ExePath: "/srv/app", OpenPorts: p.openPorts}, nil
	}
	initial := criteriaConfig(t, "    - name: app\n      open_ports: 8080\n")
	updater := NewCriteriaUpdater(initial)
	input := make(chan []Event[ProcessAttrs])
	output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	events := output.Subscribe()
	matcher := &Matcher{
		Log: slog.Default(), Criteria: FindingCriteria(initial),
		ProcessHistory: map[app.PID]ProcessMatch{}, Input: input, Output: output,
		CriteriaUpdates: updater.Updates(),
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); matcher.Run(ctx) }()
	input <- []Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 10, openPorts: []uint32{8080}}},
		{Type: EventCreated, Obj: ProcessAttrs{pid: 11, openPorts: []uint32{9090}}},
		{Type: EventCreated, Obj: ProcessAttrs{pid: 12}},
	}
	first := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, first, 1)
	require.Equal(t, app.PID(10), first[0].Obj.Process.Pid)

	next := criteriaConfig(t, "    - name: app\n      open_ports: 9090\n")
	require.NoError(t, updater.Update(ctx, next))
	refreshed := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, refreshed, 3)
	changes := map[app.PID]WatchEventType{}
	for _, ev := range refreshed {
		changes[ev.Obj.Process.Pid] = ev.Type
	}
	assert.Equal(t, map[app.PID]WatchEventType{10: EventDeleted, 11: EventCreated, 12: EventCreated}, changes)
	for _, ev := range refreshed {
		assert.Equal(t, "app", ev.Obj.Criteria[0].GetName())
	}

	// Repeated updates are harmless, and deleted observations cannot be resurrected.
	require.NoError(t, updater.Update(ctx, next))
	input <- []Event[ProcessAttrs]{{Type: EventDeleted, Obj: ProcessAttrs{pid: 11}}, {Type: EventDeleted, Obj: ProcessAttrs{pid: 12}}}
	require.Len(t, testutil.ReadChannel(t, events, time.Second), 2)
	require.NoError(t, updater.Update(ctx, initial))
	restored := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, restored, 1)
	assert.Equal(t, app.PID(10), restored[0].Obj.Process.Pid)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("matcher did not stop")
	}
}

func TestCriteriaRefreshRejectsRetainedServiceChange(t *testing.T) {
	original := processInfo
	t.Cleanup(func() { processInfo = original })
	processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
		return &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}, nil
	}
	initial := criteriaConfig(t, "    - name: first\n      open_ports: 8080\n    - name: second\n      open_ports: 9090\n")
	updater := NewCriteriaUpdater(initial)
	input := make(chan []Event[ProcessAttrs])
	output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	events := output.Subscribe()
	matcher := &Matcher{Log: slog.Default(), Criteria: FindingCriteria(initial), ProcessHistory: map[app.PID]ProcessMatch{}, Input: input, Output: output, CriteriaUpdates: updater.Updates()}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go matcher.Run(ctx)
	input <- []Event[ProcessAttrs]{{Type: EventCreated, Obj: ProcessAttrs{pid: 10, openPorts: []uint32{8080}}}}
	first := testutil.ReadChannel(t, events, time.Second)
	require.Equal(t, "first", first[0].Obj.Criteria[0].GetName())
	next := criteriaConfig(t, "    - name: first\n      open_ports: 9090\n    - name: second\n      open_ports: 8080\n")
	require.ErrorContains(t, updater.Update(ctx, next), "restart OBI")
	current, _ := updater.Updates().Current()
	require.True(t, current[0].GetOpenPorts().Matches(8080))
	// The rejected replacement must not emit deletions or alter subsequent matches.
	input <- []Event[ProcessAttrs]{{Type: EventCreated, Obj: ProcessAttrs{pid: 20, openPorts: []uint32{8080}}}}
	unchanged := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, unchanged, 1)
	require.Equal(t, EventCreated, unchanged[0].Type)
	require.Equal(t, "first", unchanged[0].Obj.Criteria[0].GetName())
}

func TestCriteriaUpdaterCancellation(t *testing.T) {
	cfg := criteriaConfig(t, "    - exe_path: /srv/app\n")
	updater := NewCriteriaUpdater(cfg)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, updater.Update(ctx, cfg), context.Canceled)
	updater.Updates().Stop()
	require.ErrorContains(t, updater.Update(t.Context(), cfg), "matcher stopped")
}

func TestCriteriaRescanPreservesProcessExits(t *testing.T) {
	acc := pollAccounter{
		cfg: &obi.Config{}, pids: map[app.PID]ProcessAttrs{}, pidPorts: map[pidPort]ProcessAttrs{},
		executableReady: func(app.PID) (string, bool) { return "/srv/app", true },
	}
	before := map[app.PID]ProcessAttrs{10: {pid: 10}, 20: {pid: 20, openPorts: []uint32{8080}}}
	require.Len(t, acc.snapshot(before), 2)
	acc.rescanProcesses()
	after := map[app.PID]ProcessAttrs{20: before[20]}
	events := acc.snapshot(after)
	changes := map[app.PID]WatchEventType{}
	for _, event := range events {
		changes[event.Obj.pid] = event.Type
	}
	require.Equal(t, map[app.PID]WatchEventType{10: EventDeleted, 20: EventCreated}, changes)
	require.Empty(t, acc.snapshot(after))
}

func TestCriteriaRefreshAddsDefinitionsAndExclusions(t *testing.T) {
	original := processInfo
	t.Cleanup(func() { processInfo = original })
	processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
		return &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}, nil
	}
	initial := criteriaConfig(t, "    - name: first\n      open_ports: 8080\n")
	updater := NewCriteriaUpdater(initial)
	input := make(chan []Event[ProcessAttrs])
	output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	events := output.Subscribe()
	matcher := &Matcher{Log: slog.Default(), Criteria: FindingCriteria(initial), ProcessHistory: map[app.PID]ProcessMatch{}, Input: input, Output: output, CriteriaUpdates: updater.Updates()}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go matcher.Run(ctx)
	input <- []Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 10, openPorts: []uint32{8080}}},
		{Type: EventCreated, Obj: ProcessAttrs{pid: 20, openPorts: []uint32{9090}}},
	}
	require.Len(t, testutil.ReadChannel(t, events, time.Second), 1)
	added := criteriaConfig(t, "    - name: second\n      open_ports: 9090\n    - name: first\n      open_ports: 8080\n")
	require.NoError(t, updater.Update(ctx, added))
	created := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, created, 1)
	require.Equal(t, app.PID(20), created[0].Obj.Process.Pid)
	require.Equal(t, "second", created[0].Obj.Criteria[0].GetName())

	excluded := criteriaConfig(t, "    - name: first\n      open_ports: 8080\n    - name: second\n      open_ports: 9090\n")
	excluded.Discovery.ExcludeInstrument = services.GlobDefinitionCriteria{{PIDs: []uint32{10}}}
	require.NoError(t, updater.Update(ctx, excluded))
	deleted := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, deleted, 1)
	require.Equal(t, EventDeleted, deleted[0].Type)
	require.Equal(t, app.PID(10), deleted[0].Obj.Process.Pid)

	require.NoError(t, updater.Update(ctx, initial))
	restored := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, restored, 2)
	changes := map[app.PID]WatchEventType{}
	for _, event := range restored {
		changes[event.Obj.Process.Pid] = event.Type
	}
	require.Equal(t, map[app.PID]WatchEventType{10: EventCreated, 20: EventDeleted}, changes)
	empty := criteriaConfig(t, "    []\n")
	require.NoError(t, updater.Update(ctx, empty))
	stopped := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, stopped, 1)
	require.Equal(t, EventDeleted, stopped[0].Type)
	require.Equal(t, app.PID(10), stopped[0].Obj.Process.Pid)
}

func TestCriteriaUpdaterRejectsSwappedNames(t *testing.T) {
	initial := criteriaConfig(t, "    - name: first\n      open_ports: 8080\n    - name: second\n      open_ports: 9090\n")
	next := criteriaConfig(t, "    - name: second\n      open_ports: 8080\n    - name: first\n      open_ports: 9090\n")
	require.ErrorContains(t, NewCriteriaUpdater(initial).Update(t.Context(), next), "restart OBI")
}

func TestCriteriaUpdaterRejectsNewPipelineFeatures(t *testing.T) {
	initial := criteriaConfig(t, "    - exe_path: /srv/app\n")
	initial.Metrics.Features = export.FeatureApplicationRED
	next := criteriaConfig(t, "    - exe_path: /srv/app\n    - exe_path: /srv/worker\n      metrics:\n        features: [application_runtime]\n")
	next.Metrics.Features = export.FeatureApplicationRED
	require.ErrorContains(t, NewCriteriaUpdater(initial).Update(t.Context(), next), "restart OBI")
}

func TestCriteriaUpdaterRejectsDynamicSelector(t *testing.T) {
	cfg := criteriaConfig(t, "    - exe_path: /srv/app\n")
	finder := NewProcessFinder(cfg, &global.ContextInfo{}, nil, nil, nil)
	_, err := finder.Start(t.Context(), WithCriteriaUpdater(NewCriteriaUpdater(cfg)), WithDynamicSelector(NewDynamicSelector()))
	require.ErrorContains(t, err, "cannot be combined")
}
