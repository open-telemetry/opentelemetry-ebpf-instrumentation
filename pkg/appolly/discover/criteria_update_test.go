// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"

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

func mockProcessPorts(t *testing.T, ports map[app.PID][]uint32) {
	t.Helper()
	original := processPorts
	t.Cleanup(func() { processPorts = original })
	processPorts = func(_ context.Context, pid app.PID) ([]uint32, error) {
		current, ok := ports[pid]
		if !ok {
			return nil, fmt.Errorf("unexpected port read for PID %d", pid)
		}
		return current, nil
	}
}

// New callback fields need an explicit refresh policy, even when defaults leave them nil.
func TestCriteriaUpdaterConfigCallbackInventory(t *testing.T) {
	var callbacks []string
	ancestors := map[reflect.Type]bool{}
	var visit func(reflect.Type, string)
	visit = func(typ reflect.Type, path string) {
		if ancestors[typ] {
			return
		}
		ancestors[typ] = true
		defer delete(ancestors, typ)

		switch typ.Kind() {
		case reflect.Func:
			callbacks = append(callbacks, path)
		case reflect.Struct:
			for field := range typ.Fields() {
				visit(field.Type, path+"."+field.Name)
			}
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			visit(typ.Elem(), path)
		}
	}
	visit(reflect.TypeFor[obi.Config](), "Config")

	require.ElementsMatch(t, []string{
		"Config.Traces.TracesExport",
		"Config.Traces.OTLPEndpointProvider",
		"Config.Traces.InjectHeaders",
		"Config.OTELMetrics.MetricsExport",
		"Config.OTELMetrics.OTLPEndpointProvider",
		"Config.OTELMetrics.InjectHeaders",
	}, callbacks, "new configuration callbacks need an explicit comparison policy and update tests")
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

func TestCriteriaUpdaterPreservesExportCallbacks(t *testing.T) {
	for _, signals := range []struct {
		name    string
		traces  bool
		metrics bool
	}{
		{name: "no callbacks"},
		{name: "traces", traces: true},
		{name: "metrics", metrics: true},
		{name: "traces and metrics", traces: true, metrics: true},
	} {
		t.Run(signals.name, func(t *testing.T) {
			initial := criteriaConfig(t, "    - open_ports: 8080\n")
			var tracesCalls, metricsCalls int
			if signals.traces {
				initial.Traces.TracesExport = func(context.Context, ptrace.Traces) error {
					tracesCalls++
					return nil
				}
			}
			if signals.metrics {
				initial.OTELMetrics.MetricsExport = func(context.Context, pmetric.Metrics) error {
					metricsCalls++
					return nil
				}
			}

			updater := NewCriteriaUpdater(initial)
			matcher := &Matcher{
				Log: slog.Default(), Criteria: FindingCriteria(initial),
				ProcessHistory:  map[app.PID]ProcessMatch{},
				Output:          msg.NewQueue[[]Event[ProcessMatch]](),
				CriteriaUpdates: updater.Updates(),
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			done := make(chan struct{})
			go func() { defer close(done); matcher.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				testutil.ReadChannel(t, done, time.Second)
			})

			// An unchanged config and a selection change both retain the same callbacks.
			require.NoError(t, updater.Update(ctx, initial))
			next := criteriaConfig(t, "    - open_ports: 9090\n")
			next.Traces.TracesExport = initial.Traces.TracesExport
			next.OTELMetrics.MetricsExport = initial.OTELMetrics.MetricsExport
			require.NoError(t, updater.Update(ctx, next))
			include, _ := updater.Updates().Current()
			require.True(t, include[0].GetOpenPorts().Matches(9090))

			// Reloaded declarative configuration does not contain the startup sinks.
			reloaded := criteriaConfig(t, "    - open_ports: 7070\n")
			require.NoError(t, updater.Update(ctx, reloaded))
			require.Nil(t, reloaded.Traces.TracesExport)
			require.Nil(t, reloaded.OTELMetrics.MetricsExport)

			replacement := criteriaConfig(t, "    - open_ports: 6060\n")
			replacement.Traces.TracesExport = func(context.Context, ptrace.Traces) error {
				t.Error("selection update replaced the startup trace sink")
				return nil
			}
			replacement.OTELMetrics.MetricsExport = func(context.Context, pmetric.Metrics) error {
				t.Error("selection update replaced the startup metrics sink")
				return nil
			}
			require.NoError(t, updater.Update(ctx, replacement))
			require.NotNil(t, replacement.Traces.TracesExport)
			require.NotNil(t, replacement.OTELMetrics.MetricsExport)

			changedExporter := *replacement
			changedExporter.Traces.TracesEndpoint = "http://localhost:4318"
			require.ErrorContains(t, updater.Update(ctx, &changedExporter), "restart OBI")
			changedExporter = *replacement
			changedExporter.OTELMetrics.MetricsEndpoint = "http://localhost:4318"
			require.ErrorContains(t, updater.Update(ctx, &changedExporter), "restart OBI")
			include, _ = updater.Updates().Current()
			require.True(t, include[0].GetOpenPorts().Matches(6060))

			if signals.traces {
				require.NotNil(t, initial.Traces.TracesExport)
				require.NoError(t, initial.Traces.TracesExport(ctx, ptrace.NewTraces()))
				require.Equal(t, 1, tracesCalls)
			} else {
				require.Nil(t, initial.Traces.TracesExport)
			}
			if signals.metrics {
				require.NotNil(t, initial.OTELMetrics.MetricsExport)
				require.NoError(t, initial.OTELMetrics.MetricsExport(ctx, pmetric.NewMetrics()))
				require.Equal(t, 1, metricsCalls)
			} else {
				require.Nil(t, initial.OTELMetrics.MetricsExport)
			}
		})
	}
}

func TestCriteriaUpdaterPreservesEndpointProviders(t *testing.T) {
	for _, signal := range []string{"traces", "metrics"} {
		t.Run(signal, func(t *testing.T) {
			setProvider := func(cfg *obi.Config, provider func() (string, bool)) {
				if signal == "traces" {
					cfg.Traces.OTLPEndpointProvider = provider
				} else {
					cfg.OTELMetrics.OTLPEndpointProvider = provider
				}
			}
			initial := criteriaConfig(t, "    - open_ports: 8080\n")
			var providerCalls int
			provider := func() (string, bool) {
				providerCalls++
				return "http://startup.example:4318", true
			}
			setProvider(initial, provider)
			updater := NewCriteriaUpdater(initial)
			matcher := &Matcher{
				Log: slog.Default(), Criteria: FindingCriteria(initial),
				ProcessHistory:  map[app.PID]ProcessMatch{},
				Output:          msg.NewQueue[[]Event[ProcessMatch]](),
				CriteriaUpdates: updater.Updates(),
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			done := make(chan struct{})
			go func() { defer close(done); matcher.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				testutil.ReadChannel(t, done, time.Second)
			})

			require.NoError(t, updater.Update(ctx, initial))
			next := criteriaConfig(t, "    - open_ports: 9090\n")
			setProvider(next, provider)
			require.NoError(t, updater.Update(ctx, next))
			include, _ := updater.Updates().Current()
			require.Len(t, include, 1)
			require.True(t, include[0].GetOpenPorts().Matches(9090))

			reloaded := criteriaConfig(t, "    - open_ports: 7070\n")
			require.NoError(t, updater.Update(ctx, reloaded))
			replacement := criteriaConfig(t, "    - open_ports: 6060\n")
			setProvider(replacement, func() (string, bool) {
				t.Error("selection refresh invoked a replacement endpoint provider")
				return "http://replacement.example:4318", false
			})
			require.NoError(t, updater.Update(ctx, replacement))
			require.Zero(t, providerCalls, "selection refresh must not evaluate endpoint providers")

			var endpoint string
			var common bool
			if signal == "traces" {
				require.NotNil(t, initial.Traces.OTLPEndpointProvider)
				require.NotNil(t, next.Traces.OTLPEndpointProvider)
				require.Nil(t, reloaded.Traces.OTLPEndpointProvider)
				require.NotNil(t, replacement.Traces.OTLPEndpointProvider)
				endpoint, common = initial.Traces.OTLPTracesEndpoint()
			} else {
				require.NotNil(t, initial.OTELMetrics.OTLPEndpointProvider)
				require.NotNil(t, next.OTELMetrics.OTLPEndpointProvider)
				require.Nil(t, reloaded.OTELMetrics.OTLPEndpointProvider)
				require.NotNil(t, replacement.OTELMetrics.OTLPEndpointProvider)
				endpoint, common = initial.OTELMetrics.OTLPMetricsEndpoint()
			}
			require.Equal(t, "http://startup.example:4318", endpoint)
			require.True(t, common)
			require.Equal(t, 1, providerCalls)
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

func TestCriteriaRefreshRemovesNowExcludedProcess(t *testing.T) {
	original := processInfo
	t.Cleanup(func() { processInfo = original })
	processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
		return &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}, nil
	}
	initial := criteriaConfig(t, "    - name: app\n      exe_path: /srv/app\n")
	updater := NewCriteriaUpdater(initial)
	input := make(chan []Event[ProcessAttrs])
	output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	events := output.Subscribe()
	matcher := &Matcher{Log: slog.Default(), Criteria: FindingCriteria(initial), ProcessHistory: map[app.PID]ProcessMatch{}, Input: input, Output: output, CriteriaUpdates: updater.Updates()}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); matcher.Run(ctx) }()

	// The process matches by executable before opening port 8080.
	input <- []Event[ProcessAttrs]{{Type: EventCreated, Obj: ProcessAttrs{pid: 10, openPorts: []uint32{}}}}
	first := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, first, 1)
	require.Equal(t, app.PID(10), first[0].Obj.Process.Pid)

	// Add an exclusion for port 8080. At refresh time the process has no open ports,
	// so the exclusion does not yet apply and the process is retained.
	next := criteriaConfig(t, "    - name: app\n      exe_path: /srv/app\n")
	next.Discovery.ExcludeInstrument = services.GlobDefinitionCriteria{{
		OpenPorts: services.IntEnum{Ranges: []services.IntRange{{Start: 8080, End: 0}}},
	}}
	require.NoError(t, updater.Update(ctx, next))

	// A rescan now discovers port 8080 on the same process. Re-notification must
	// reconcile the tracked process against the fresh attributes and remove it.
	input <- []Event[ProcessAttrs]{{Type: EventCreated, Obj: ProcessAttrs{pid: 10, openPorts: []uint32{8080}}}}
	removed := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, removed, 1)
	require.Equal(t, EventDeleted, removed[0].Type)
	require.Equal(t, app.PID(10), removed[0].Obj.Process.Pid)

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("matcher did not stop")
	}
}

func TestCriteriaRefreshUsesLastSuccessfulObservation(t *testing.T) {
	original := processInfo
	t.Cleanup(func() { processInfo = original })
	var readErr error
	processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
		if readErr != nil {
			return nil, readErr
		}
		proc := &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}
		if p.pid == 11 {
			proc.PPid = 10
		}
		return proc, nil
	}
	initial := criteriaConfig(t, "    - open_ports: 8080\n")
	output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	defer output.Close()
	events := output.Subscribe()
	matcher := &Matcher{
		Log: slog.Default(), Criteria: FindingCriteria(initial),
		ProcessHistory: map[app.PID]ProcessMatch{}, Output: output,
		observed: map[app.PID]observedProcess{},
	}
	require.Len(t, matcher.filter([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 10, openPorts: []uint32{8080}}},
		{Type: EventCreated, Obj: ProcessAttrs{pid: 11}},
		{Type: EventCreated, Obj: ProcessAttrs{pid: 20, openPorts: []uint32{9090}}},
	}), 2)
	refresh := func(cfg *obi.Config) {
		t.Helper()
		require.NoError(t, matcher.refresh(t.Context(), services.CriteriaUpdate{
			Context: t.Context(), Include: FindingCriteria(cfg), Exclude: ExcludingCriteria(cfg),
		}))
	}

	readErr = errors.New("temporary /proc read failure")
	refresh(initial)
	require.Contains(t, matcher.ProcessHistory, app.PID(10))
	require.Contains(t, matcher.ProcessHistory, app.PID(11))
	select {
	case unexpected := <-events:
		t.Fatalf("read failure changed instrumentation: %v", unexpected)
	default:
	}

	refresh(criteriaConfig(t, "    - open_ports: 8080\n    - open_ports: 9090\n"))
	created := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, created, 1)
	require.Equal(t, EventCreated, created[0].Type)
	require.Equal(t, app.PID(20), created[0].Obj.Process.Pid)

	// Config-driven removals must still apply while process reads are failing.
	refresh(criteriaConfig(t, "    - open_ports: 9090\n"))
	deleted := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, deleted, 2)
	deletedPIDs := make([]app.PID, 0, len(deleted))
	for _, event := range deleted {
		require.Equal(t, EventDeleted, event.Type)
		deletedPIDs = append(deletedPIDs, event.Obj.Process.Pid)
	}
	require.ElementsMatch(t, []app.PID{10, 11}, deletedPIDs)
	require.Contains(t, matcher.ProcessHistory, app.PID(20))

	rescan := []Event[ProcessAttrs]{{Type: EventCreated, Obj: ProcessAttrs{pid: 20, openPorts: []uint32{8080}}}}
	require.Empty(t, matcher.filter(rescan))
	require.Contains(t, matcher.ProcessHistory, app.PID(20))
	readErr = nil
	// Only a successful fresh observation can invalidate the cached port match.
	deleted = matcher.filter(rescan)
	require.Len(t, deleted, 1)
	require.Equal(t, EventDeleted, deleted[0].Type)
	require.Equal(t, app.PID(20), deleted[0].Obj.Process.Pid)
	require.Equal(t, []uint32{8080}, matcher.observed[20].process.OpenPorts)
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

func TestCriteriaRefreshChecksFreshPortsBeforeAcceptingServiceChange(t *testing.T) {
	for _, observedBeforeUpdate := range []bool{false, true} {
		t.Run(fmt.Sprintf("observed_before_update=%t", observedBeforeUpdate), func(t *testing.T) {
			listen := func() uint32 {
				t.Helper()
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, listener.Close()) })
				return uint32(listener.Addr().(*net.TCPAddr).Port)
			}
			firstPort := listen()
			pid := app.PID(os.Getpid())
			definitions := fmt.Sprintf("    - name: first\n      open_ports: %d\n", firstPort)
			initial := criteriaConfig(t, definitions)
			output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
			defer output.Close()
			events := output.Subscribe()
			matcher := &Matcher{
				Log: slog.Default(), Criteria: FindingCriteria(initial),
				ProcessHistory: map[app.PID]ProcessMatch{}, Output: output,
				observed: map[app.PID]observedProcess{},
			}
			require.Len(t, matcher.filter([]Event[ProcessAttrs]{
				{Type: EventCreated, Obj: ProcessAttrs{pid: pid, openPorts: []uint32{firstPort}}},
			}), 1)
			secondPort := listen()
			if observedBeforeUpdate {
				require.Empty(t, matcher.filter([]Event[ProcessAttrs]{
					{Type: EventCreated, Obj: ProcessAttrs{pid: pid, openPorts: []uint32{firstPort, secondPort}}},
				}))
			}
			before := matcher.observed[pid]
			next := criteriaConfig(t, definitions+fmt.Sprintf("    - name: second\n      open_ports: %d\n", secondPort))
			require.NoError(t, compatibleDefinitions(matcher.Criteria, FindingCriteria(next)))
			err := matcher.refresh(t.Context(), services.CriteriaUpdate{
				Context: t.Context(), Include: FindingCriteria(next), Exclude: ExcludingCriteria(next),
			})
			require.EqualError(t, err, fmt.Sprintf("service settings would change for PID %d; restart OBI to apply this configuration", pid))
			require.Equal(t, FindingCriteria(initial), matcher.Criteria)
			require.Equal(t, before, matcher.observed[pid], "a rejected update must not mutate the cached observation")
			require.Equal(t, "first", matchingSettings(matcher.ProcessHistory[pid].Criteria).name)
			select {
			case unexpected := <-events:
				t.Fatalf("rejected refresh changed instrumentation: %v", unexpected)
			default:
			}

			// The new port can also override an earlier rule back to the applied settings.
			compatible := criteriaConfig(t, definitions+fmt.Sprintf(
				"    - name: second\n      target_pids: [%d]\n    - name: first\n      open_ports: %d\n", pid, secondPort))
			require.NoError(t, matcher.refresh(t.Context(), services.CriteriaUpdate{
				Context: t.Context(), Include: FindingCriteria(compatible), Exclude: ExcludingCriteria(compatible),
			}))
			require.Equal(t, "first", matchingSettings(matcher.ProcessHistory[pid].Criteria).name)
		})
	}
}

func TestCriteriaRefreshPortReadFailureRetainsState(t *testing.T) {
	originalInfo, originalPorts := processInfo, processPorts
	t.Cleanup(func() { processInfo, processPorts = originalInfo, originalPorts })
	processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
		return &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}, nil
	}
	readErr := errors.New("temporary /proc read failure")
	var reads int
	ports := []uint32{8080, 9090}
	processPorts = func(_ context.Context, pid app.PID) ([]uint32, error) {
		reads++
		require.Equal(t, app.PID(10), pid)
		return ports, readErr
	}
	const definitions = "    - name: first\n      open_ports: 8080\n"
	initial := criteriaConfig(t, definitions)
	next := criteriaConfig(t, definitions+"    - name: second\n      open_ports: 9090\n")
	output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	defer output.Close()
	events := output.Subscribe()
	matcher := &Matcher{
		Log: slog.Default(), Criteria: FindingCriteria(initial),
		ProcessHistory: map[app.PID]ProcessMatch{}, Output: output,
		observed: map[app.PID]observedProcess{},
	}
	require.Len(t, matcher.filter([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 10, openPorts: []uint32{8080}}},
	}), 1)
	previousMatch, previousObservation := matcher.ProcessHistory[10], matcher.observed[10]
	update := services.CriteriaUpdate{Context: t.Context(), Include: FindingCriteria(next), Exclude: ExcludingCriteria(next)}
	require.ErrorIs(t, matcher.refresh(t.Context(), update), readErr)
	require.Equal(t, FindingCriteria(initial), matcher.Criteria)
	require.Equal(t, previousMatch, matcher.ProcessHistory[10])
	require.Equal(t, previousObservation, matcher.observed[10])

	readErr = nil
	require.ErrorContains(t, matcher.refresh(t.Context(), update), "service settings would change for PID 10")
	require.Equal(t, previousMatch, matcher.ProcessHistory[10])
	require.Equal(t, previousObservation, matcher.observed[10])

	ports = []uint32{8080}
	require.NoError(t, matcher.refresh(t.Context(), update))
	require.Equal(t, "first", matchingSettings(matcher.ProcessHistory[10].Criteria).name)
	require.Equal(t, 3, reads)
	// An unchanged rule that was never applied must not trigger another read or alter settings.
	require.NoError(t, matcher.refresh(t.Context(), update))
	require.Equal(t, 3, reads)
	select {
	case unexpected := <-events:
		t.Fatalf("port checks changed instrumentation: %v", unexpected)
	default:
	}
}

func TestCriteriaRefreshReportsStableConflictingPID(t *testing.T) {
	mockProcessPorts(t, map[app.PID][]uint32{1: {7070}, 10: {8080}, 40: {8080}, 90: {8080}})
	original := processInfo
	t.Cleanup(func() { processInfo = original })
	processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
		return &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}, nil
	}
	const definitions = "    - name: first\n      open_ports: 8080\n    - name: unchanged\n      open_ports: 7070\n"
	initial := criteriaConfig(t, definitions)
	next := criteriaConfig(t, definitions+"    - name: second\n      open_ports: 8080-8081\n")
	output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	defer output.Close()
	events := output.Subscribe()
	matcher := &Matcher{
		Log: slog.Default(), Criteria: FindingCriteria(initial),
		ProcessHistory: map[app.PID]ProcessMatch{}, Output: output,
		observed: map[app.PID]observedProcess{},
	}
	require.NoError(t, compatibleDefinitions(FindingCriteria(initial), FindingCriteria(next)))
	require.Len(t, matcher.filter([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 90, openPorts: []uint32{8080}}},
		{Type: EventCreated, Obj: ProcessAttrs{pid: 1, openPorts: []uint32{7070}}},
		{Type: EventCreated, Obj: ProcessAttrs{pid: 40, openPorts: []uint32{8080}}},
		{Type: EventCreated, Obj: ProcessAttrs{pid: 10, openPorts: []uint32{8080}}},
	}), 4)
	update := services.CriteriaUpdate{Context: t.Context(), Include: FindingCriteria(next), Exclude: ExcludingCriteria(next)}

	for _, tc := range []struct {
		pid app.PID
		err string
	}{
		{10, "service settings would change for PID 10; restart OBI to apply this configuration"},
		{40, "service settings would change for PID 40; restart OBI to apply this configuration"},
		{90, "service settings would change for PID 90; restart OBI to apply this configuration"},
	} {
		for range 32 {
			require.EqualError(t, matcher.refresh(t.Context(), update), tc.err)
		}
		require.Equal(t, "first", matchingSettings(matcher.ProcessHistory[tc.pid].Criteria).name)
		select {
		case unexpected := <-events:
			t.Fatalf("rejected refresh changed instrumentation: %v", unexpected)
		default:
		}
		require.Len(t, matcher.filter([]Event[ProcessAttrs]{{Type: EventDeleted, Obj: ProcessAttrs{pid: tc.pid}}}), 1)
	}

	require.NoError(t, matcher.refresh(t.Context(), update))
	require.Len(t, matcher.ProcessHistory, 1)
	require.Contains(t, matcher.ProcessHistory, app.PID(1))
}

func TestCriteriaUpdaterRepeatedMatcherShutdown(t *testing.T) {
	cfg := criteriaConfig(t, "    - exe_path: /srv/app\n")
	updater := NewCriteriaUpdater(cfg)
	for range 2 {
		input := make(chan []Event[ProcessAttrs])
		close(input)
		matcher := &Matcher{
			Log: slog.Default(), Criteria: FindingCriteria(cfg),
			ProcessHistory: map[app.PID]ProcessMatch{}, Input: input,
			Output:          msg.NewQueue[[]Event[ProcessMatch]](),
			CriteriaUpdates: updater.Updates(),
		}
		require.NotPanics(t, func() { matcher.Run(t.Context()) })
	}
	require.ErrorContains(t, updater.Update(t.Context(), cfg), "matcher stopped")
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

func TestCriteriaUpdaterDeadlineDuringReconciliation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		original := processInfo
		t.Cleanup(func() { processInfo = original })
		processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
			return &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app"}, nil
		}
		initial := criteriaConfig(t, "    - exe_path: /srv/app\n")
		updater := NewCriteriaUpdater(initial)
		input := make(chan []Event[ProcessAttrs])
		output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(0))
		events := output.Subscribe()
		matcher := &Matcher{
			Log: slog.Default(), Criteria: FindingCriteria(initial),
			ProcessHistory: map[app.PID]ProcessMatch{}, Input: input, Output: output,
			CriteriaUpdates: updater.Updates(),
		}
		pipelineCtx, stop := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { defer close(done); matcher.Run(pipelineCtx) }()
		t.Cleanup(func() {
			stop()
			testutil.ReadChannel(t, done, time.Second)
		})

		input <- []Event[ProcessAttrs]{{Type: EventCreated, Obj: ProcessAttrs{pid: 10}}}
		require.Len(t, testutil.ReadChannel(t, events, time.Second), 1)
		empty := criteriaConfig(t, "    []\n")
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- updater.Update(ctx, empty) }()

		// The matcher has applied the change but cannot send its deletion event yet.
		synctest.Wait()
		require.Empty(t, matcher.ProcessHistory)
		require.NoError(t, ctx.Err())
		time.Sleep(time.Second)
		require.ErrorIs(t, testutil.ReadChannel(t, result, time.Second), context.DeadlineExceeded)

		// A subsequent caller can acquire the updater mutex and honor cancellation
		// even while the matcher is still blocked on the first update's output.
		canceledCtx, cancelNext := context.WithCancel(t.Context())
		cancelNext()
		go func() { result <- updater.Update(canceledCtx, initial) }()
		require.ErrorIs(t, testutil.ReadChannel(t, result, time.Second), context.Canceled)

		// Cancellation did not roll back the update; it can still be acknowledged.
		deleted := testutil.ReadChannel(t, events, time.Second)
		require.Len(t, deleted, 1)
		require.Equal(t, EventDeleted, deleted[0].Type)
		require.Equal(t, app.PID(10), deleted[0].Obj.Process.Pid)
		synctest.Wait()
		criteria, _ := updater.Updates().Current()
		require.Empty(t, criteria)

		go func() { result <- updater.Update(t.Context(), initial) }()
		created := testutil.ReadChannel(t, events, time.Second)
		require.Len(t, created, 1)
		require.Equal(t, EventCreated, created[0].Type)
		require.Equal(t, app.PID(10), created[0].Obj.Process.Pid)
		require.NoError(t, testutil.ReadChannel(t, result, time.Second))
	})
}

func TestCriteriaRescanPreservesProcessExits(t *testing.T) {
	acc := pollAccounter{
		cfg: &obi.Config{}, pids: map[app.PID]ProcessAttrs{}, pidPorts: map[pidPort]ProcessAttrs{},
		executableReady: func(app.PID) (string, bool) { return "/srv/app", true },
	}
	before := map[app.PID]ProcessAttrs{10: {pid: 10}, 20: {pid: 20, openPorts: []uint32{8080}}}
	require.Len(t, acc.snapshot(before, false), 2)
	acc.rescanProcesses()
	fetchPorts, forceRescan := acc.pollRequirements()
	require.True(t, fetchPorts)
	after := map[app.PID]ProcessAttrs{20: before[20]}
	events := acc.snapshot(after, forceRescan)
	changes := map[app.PID]WatchEventType{}
	for _, event := range events {
		changes[event.Obj.pid] = event.Type
	}
	require.Equal(t, map[app.PID]WatchEventType{10: EventDeleted, 20: EventCreated}, changes)
	require.Empty(t, acc.snapshot(after, false))
}

func TestCriteriaRefreshRescanReconcilesTrackedProcess(t *testing.T) {
	for _, tc := range []struct {
		name          string
		previousPorts []uint32
		include       string
		exclude       string
	}{
		{
			name:    "new exclusion matches fresh ports",
			include: "    - exe_path: /srv/app\n",
			exclude: "discovery:\n  exclude_instrument:\n    - open_ports: 8080\n",
		},
		{
			name:          "new inclusion no longer matches fresh ports",
			previousPorts: []uint32{9090},
			include:       "    - open_ports: 9090\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := processInfo
			t.Cleanup(func() { processInfo = original })
			processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
				return &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}, nil
			}

			initial := criteriaConfig(t, "    - exe_path: /srv/app\n")
			output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
			defer output.Close()
			events := output.Subscribe()
			matcher := &Matcher{
				Log: slog.Default(), Criteria: FindingCriteria(initial),
				ProcessHistory: map[app.PID]ProcessMatch{}, Output: output,
				observed: map[app.PID]observedProcess{},
			}
			acc := pollAccounter{
				cfg: initial, pids: map[app.PID]ProcessAttrs{}, pidPorts: map[pidPort]ProcessAttrs{},
				executableReady: func(app.PID) (string, bool) { return "/srv/app", true },
			}
			before := map[app.PID]ProcessAttrs{
				10: {pid: 10, openPorts: tc.previousPorts},
				20: {pid: 20, openPorts: tc.previousPorts},
			}
			require.Len(t, matcher.filter(acc.snapshot(before, false)), 2)

			next := criteriaConfig(t, tc.include)
			require.NoError(t, yaml.Unmarshal([]byte(tc.exclude), next))
			// The refresh is accepted before the watcher has fetched the newly opened port.
			require.NoError(t, matcher.refresh(t.Context(), services.CriteriaUpdate{
				Context: t.Context(), Include: FindingCriteria(next), Exclude: ExcludingCriteria(next),
			}))
			retained := matcher.ProcessHistory[20]
			require.Contains(t, matcher.ProcessHistory, app.PID(10))
			require.Equal(t, tc.previousPorts, matcher.observed[10].process.OpenPorts)
			select {
			case unexpected := <-events:
				t.Fatalf("refresh changed targets before the port rescan: %v", unexpected)
			default:
			}

			acc.rescanProcesses()
			fetchPorts, forceRescan := acc.pollRequirements()
			require.True(t, fetchPorts)
			after := map[app.PID]ProcessAttrs{10: {pid: 10, openPorts: []uint32{8080}}, 20: before[20]}
			changes := matcher.filter(acc.snapshot(after, forceRescan))
			require.Len(t, changes, 1)
			require.Equal(t, EventDeleted, changes[0].Type)
			require.Equal(t, app.PID(10), changes[0].Obj.Process.Pid)
			require.NotContains(t, matcher.ProcessHistory, app.PID(10))
			require.Equal(t, retained, matcher.ProcessHistory[20])
			require.Equal(t, []uint32{8080}, matcher.observed[10].process.OpenPorts)

			acc.rescanProcesses()
			fetchPorts, forceRescan = acc.pollRequirements()
			require.True(t, fetchPorts)
			require.Empty(t, matcher.filter(acc.snapshot(after, forceRescan)))

			// Deselection must retain the observation so a later update can select the live PID again.
			require.NoError(t, matcher.refresh(t.Context(), services.CriteriaUpdate{
				Context: t.Context(), Include: FindingCriteria(initial), Exclude: ExcludingCriteria(initial),
			}))
			reselected := testutil.ReadChannel(t, events, time.Second)
			require.Len(t, reselected, 1)
			require.Equal(t, EventCreated, reselected[0].Type)
			require.Equal(t, app.PID(10), reselected[0].Obj.Process.Pid)
		})
	}
}

func TestCriteriaRefreshRetainsEstablishedPortMatch(t *testing.T) {
	for _, closeBeforeUpdate := range []bool{false, true} {
		name := "port closes after update"
		if closeBeforeUpdate {
			name = "port closes before update"
		}
		t.Run(name, func(t *testing.T) {
			original := processInfo
			t.Cleanup(func() { processInfo = original })
			processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
				return &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}, nil
			}
			initial := criteriaConfig(t, "    - open_ports: 8080\n")
			output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
			defer output.Close()
			events := output.Subscribe()
			matcher := &Matcher{
				Log: slog.Default(), Criteria: FindingCriteria(initial),
				ProcessHistory: map[app.PID]ProcessMatch{}, Output: output,
				observed: map[app.PID]observedProcess{},
			}
			acc := pollAccounter{
				cfg: initial, pids: map[app.PID]ProcessAttrs{}, pidPorts: map[pidPort]ProcessAttrs{},
				executableReady: func(app.PID) (string, bool) { return "/srv/app", true },
			}
			rescan := func(ports ...uint32) []Event[ProcessMatch] {
				acc.rescanProcesses()
				fetchPorts, forceRescan := acc.pollRequirements()
				require.True(t, fetchPorts)
				return matcher.filter(acc.snapshot(map[app.PID]ProcessAttrs{10: {pid: 10, openPorts: ports}}, forceRescan))
			}
			refresh := func(cfg *obi.Config) {
				t.Helper()
				require.NoError(t, matcher.refresh(t.Context(), services.CriteriaUpdate{
					Context: t.Context(), Include: FindingCriteria(cfg), Exclude: ExcludingCriteria(cfg),
				}))
			}
			assertNoEvents := func() {
				t.Helper()
				select {
				case unexpected := <-events:
					t.Fatalf("unexpected instrumentation change: %v", unexpected)
				default:
				}
			}
			require.Len(t, rescan(8080), 1)
			if closeBeforeUpdate {
				require.Empty(t, rescan(), "closing the selection port must not remove an established match")
			}

			unrelated := criteriaConfig(t, "    - exe_path: /srv/other\n    - open_ports: 8080\n")
			refresh(unrelated)
			assertNoEvents()
			for range 2 {
				require.Empty(t, rescan(), "an unchanged include rule must retain its established match")
				require.Contains(t, matcher.ProcessHistory, app.PID(10))
				require.Empty(t, matcher.observed[10].process.OpenPorts, "observations must still reflect current ports")
				refresh(unrelated)
				assertNoEvents()
			}

			// Removing the matching rule must still detach the process.
			refresh(criteriaConfig(t, "    - exe_path: /srv/other\n"))
			deleted := testutil.ReadChannel(t, events, time.Second)
			require.Len(t, deleted, 1)
			require.Equal(t, EventDeleted, deleted[0].Type)
			require.NotContains(t, matcher.ProcessHistory, app.PID(10))

			// Re-adding a removed rule requires a new observation of its port.
			refresh(initial)
			assertNoEvents()
			require.Empty(t, rescan())
			require.Len(t, rescan(8080), 1)
			deleted = matcher.filter(acc.snapshot(map[app.PID]ProcessAttrs{}, false))
			require.Len(t, deleted, 1)
			require.Equal(t, EventDeleted, deleted[0].Type)
			require.Empty(t, rescan(), "a reused PID must not inherit the exited process's match")
		})
	}
}

func TestCriteriaRefreshDoesNotAdoptUnappliedMatches(t *testing.T) {
	for _, closePort := range []bool{false, true} {
		name := "new port stays open"
		if closePort {
			name = "new port closes"
		}
		t.Run(name, func(t *testing.T) {
			original := processInfo
			t.Cleanup(func() { processInfo = original })
			processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
				return &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}, nil
			}
			const definitions = "    - name: first\n      open_ports: 8080\n    - name: second\n      open_ports: 9090\n"
			initial := criteriaConfig(t, definitions)
			output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
			defer output.Close()
			events := output.Subscribe()
			matcher := &Matcher{
				Log: slog.Default(), Criteria: FindingCriteria(initial),
				ProcessHistory: map[app.PID]ProcessMatch{}, Output: output,
				observed: map[app.PID]observedProcess{},
			}
			emit := func(pid app.PID, ports ...uint32) []Event[ProcessMatch] {
				return matcher.filter([]Event[ProcessAttrs]{{Type: EventCreated, Obj: ProcessAttrs{pid: pid, openPorts: ports}}})
			}
			refresh := func(cfg *obi.Config) error {
				return matcher.refresh(t.Context(), services.CriteriaUpdate{
					Context: t.Context(), Include: FindingCriteria(cfg), Exclude: ExcludingCriteria(cfg),
				})
			}
			require.Len(t, emit(10, 8080), 1)
			applied := matcher.ProcessHistory[10].Criteria
			require.Empty(t, emit(10, 8080, 9090))
			require.Equal(t, applied, matcher.ProcessHistory[10].Criteria)
			assert.Equal(t, applied, matcher.observed[10].confirmedCriteria)
			if closePort {
				require.Empty(t, emit(10, 8080))
			}

			for _, cfg := range []*obi.Config{
				initial,
				criteriaConfig(t, "    - exe_path: /srv/other\n"+definitions),
			} {
				require.NoError(t, refresh(cfg))
				require.Equal(t, applied, matcher.ProcessHistory[10].Criteria)
				require.Equal(t, applied, matcher.observed[10].confirmedCriteria)
				select {
				case unexpected := <-events:
					t.Fatalf("unrelated refresh changed instrumentation: %v", unexpected)
				default:
				}
				ports := []uint32{8080, 9090}
				if closePort {
					ports = []uint32{8080}
				}
				require.Empty(t, emit(10, ports...))
				require.Equal(t, applied, matcher.observed[10].confirmedCriteria)
			}

			// Added and edited rules still undergo the applied service-settings checks.
			for _, cfg := range []*obi.Config{
				criteriaConfig(t, definitions+"    - name: third\n      exe_path: /srv/app\n"),
				criteriaConfig(t, "    - name: first\n      open_ports: 8080\n    - name: second\n      exe_path: /srv/app\n"),
			} {
				require.ErrorContains(t, refresh(cfg), "service settings would change for PID 10")
			}
			require.Equal(t, applied, matcher.ProcessHistory[10].Criteria)
			created := emit(20, 9090)
			require.Len(t, created, 1)
			require.Equal(t, "second", matchingSettings(created[0].Obj.Criteria).name)

			require.NoError(t, refresh(criteriaConfig(t, "    []\n")))
			deleted := testutil.ReadChannel(t, events, time.Second)
			require.Len(t, deleted, 2)
			for _, event := range deleted {
				require.Equal(t, EventDeleted, event.Type)
			}
		})
	}
}

func TestCriteriaRescanRetainsParentMatch(t *testing.T) {
	original := processInfo
	t.Cleanup(func() { processInfo = original })
	processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
		proc := &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}
		if p.pid == 20 {
			proc.PPid = 10
		}
		return proc, nil
	}
	cfg := criteriaConfig(t, "    - open_ports: 9090\n")
	matcher := &Matcher{
		Log: slog.Default(), Criteria: FindingCriteria(cfg),
		ProcessHistory: map[app.PID]ProcessMatch{}, observed: map[app.PID]observedProcess{},
	}
	require.Len(t, matcher.filter([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 10, openPorts: []uint32{9090}}},
		{Type: EventCreated, Obj: ProcessAttrs{pid: 20}},
	}), 2)
	retained := matcher.ProcessHistory[20]

	// The child's own ports do not match, but its parent still selects it.
	require.Empty(t, matcher.filter([]Event[ProcessAttrs]{
		{Type: EventCreated, Obj: ProcessAttrs{pid: 20, openPorts: []uint32{8080}}},
	}))
	require.Equal(t, retained, matcher.ProcessHistory[20])
	require.Equal(t, []uint32{8080}, matcher.observed[20].process.OpenPorts)
}

func TestCriteriaRefreshRetainsOrphanedChild(t *testing.T) {
	for _, notification := range []string{"new port", "rescan"} {
		for _, removal := range []string{"include removed", "child excluded", "child exited"} {
			t.Run(notification+"/"+removal, func(t *testing.T) {
				original := processInfo
				t.Cleanup(func() { processInfo = original })
				parent := app.PID(10)
				processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
					proc := &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}
					if p.pid == 20 {
						proc.PPid = parent
					}
					return proc, nil
				}
				initial := criteriaConfig(t, "    - name: backend\n      open_ports: 9090\n")
				output := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
				defer output.Close()
				events := output.Subscribe()
				matcher := &Matcher{
					Log: slog.Default(), Criteria: FindingCriteria(initial),
					LogEnricherCriteria: FindingCriteria(initial),
					ProcessHistory:      map[app.PID]ProcessMatch{}, Output: output,
					observed: map[app.PID]observedProcess{},
				}
				acc := pollAccounter{
					cfg: initial, pids: map[app.PID]ProcessAttrs{}, pidPorts: map[pidPort]ProcessAttrs{},
					executableReady: func(app.PID) (string, bool) { return "/srv/app", true },
				}
				processes := map[app.PID]ProcessAttrs{10: {pid: 10, openPorts: []uint32{9090}}}
				require.Len(t, matcher.filter(acc.snapshot(processes, false)), 1)
				processes[20] = ProcessAttrs{pid: 20}
				created := matcher.filter(acc.snapshot(processes, false))
				require.Len(t, created, 1)
				require.Equal(t, app.PID(20), created[0].Obj.Process.Pid)
				require.True(t, created[0].Obj.LogEnricherEnabled())

				refresh := func(cfg *obi.Config) {
					t.Helper()
					require.NoError(t, matcher.refresh(t.Context(), services.CriteriaUpdate{
						Context: t.Context(), Include: FindingCriteria(cfg), Exclude: ExcludingCriteria(cfg),
					}))
				}
				assertNoEvents := func() {
					t.Helper()
					select {
					case unexpected := <-events:
						t.Fatalf("unexpected instrumentation change: %v", unexpected)
					default:
					}
				}

				// No configuration update precedes orphaning or the first re-emission.
				parent = 1
				delete(processes, 10)
				deleted := matcher.filter(acc.snapshot(processes, false))
				require.Len(t, deleted, 1)
				require.Equal(t, EventDeleted, deleted[0].Type)
				require.Equal(t, app.PID(10), deleted[0].Obj.Process.Pid)
				forceRescan := false
				if notification == "new port" {
					processes[20] = ProcessAttrs{pid: 20, openPorts: []uint32{8080}}
				} else {
					acc.rescanProcesses()
					var fetchPorts bool
					fetchPorts, forceRescan = acc.pollRequirements()
					require.True(t, fetchPorts)
				}
				require.Empty(t, matcher.filter(acc.snapshot(processes, forceRescan)))
				require.Contains(t, matcher.ProcessHistory, app.PID(20))
				require.Equal(t, app.PID(1), matcher.observed[20].process.PPid)

				for _, cfg := range []*obi.Config{
					initial,
					criteriaConfig(t, "    - exe_path: /srv/other\n    - name: backend\n      open_ports: 9090\n"),
				} {
					refresh(cfg)
					assertNoEvents()
					require.Contains(t, matcher.ProcessHistory, app.PID(20))
					require.True(t, matcher.ProcessHistory[20].LogEnricherEnabled())
				}

				switch removal {
				case "include removed":
					refresh(criteriaConfig(t, "    []\n"))
					deleted = testutil.ReadChannel(t, events, time.Second)
				case "child excluded":
					excluded := criteriaConfig(t, "    - name: backend\n      open_ports: 9090\n")
					excluded.Discovery.ExcludeInstrument = services.GlobDefinitionCriteria{{PIDs: []uint32{20}}}
					refresh(excluded)
					deleted = testutil.ReadChannel(t, events, time.Second)
				case "child exited":
					deleted = matcher.filter(acc.snapshot(map[app.PID]ProcessAttrs{}, false))
				}
				require.Len(t, deleted, 1)
				require.Equal(t, EventDeleted, deleted[0].Type)
				require.Equal(t, app.PID(20), deleted[0].Obj.Process.Pid)
				require.NotContains(t, matcher.ProcessHistory, app.PID(20))

				refresh(initial)
				assertNoEvents()
				require.Empty(t, matcher.filter(acc.snapshot(processes, true)), "an orphan or reused PID must not inherit a removed match")
			})
		}
	}
}

func TestCriteriaRefreshAddsDefinitionsAndExclusions(t *testing.T) {
	mockProcessPorts(t, map[app.PID][]uint32{10: {8080}, 20: {9090}})
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

func TestCriteriaRefreshAcceptsExplicitDefaultSettings(t *testing.T) {
	mockProcessPorts(t, map[app.PID][]uint32{10: {8080}, 20: {9090}})
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

	// The v2 converter makes defaults explicit on every include rule once another rule is refined.
	refined := criteriaConfig(t, "    - name: first\n      open_ports: 8080\n    - name: second\n      open_ports: 9090\n      exports: [traces]\n")
	allSignals := services.NewExportModes()
	allSignals.AllowTraces()
	allSignals.AllowMetrics()
	allSignals.AllowLogs()
	refined.Discovery.Instrument[0].ExportModes = allSignals
	refined.Discovery.Instrument[0].Routes = &services.CustomRoutesConfig{}
	require.NoError(t, updater.Update(ctx, refined))
	created := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, created, 1)
	require.Equal(t, EventCreated, created[0].Type)
	require.Equal(t, app.PID(20), created[0].Obj.Process.Pid)

	require.NoError(t, updater.Update(ctx, initial))
	deleted := testutil.ReadChannel(t, events, time.Second)
	require.Len(t, deleted, 1)
	require.Equal(t, EventDeleted, deleted[0].Type)
	require.Equal(t, app.PID(20), deleted[0].Obj.Process.Pid)
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
