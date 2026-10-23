// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/obi"
)

// CriteriaUpdater replaces discovery predicates without restarting the instrumentation pipeline.
// Pass it to instrumenter.WithCriteriaUpdater. Configurations must not be mutated after submission.
type CriteriaUpdater struct {
	mu          sync.Mutex
	fixedConfig obi.Config
	features    export.Features
	updates     *services.CriteriaUpdates
}

func NewCriteriaUpdater(cfg *obi.Config) *CriteriaUpdater {
	return &CriteriaUpdater{
		fixedConfig: withoutSelectionAndSinks(cfg),
		features:    cfg.JoinMetricsConfig().Features,
		updates: services.NewCriteriaUpdates(
			refreshableCriteria(cfg),
			ExcludingCriteria(cfg),
		),
	}
}

func (u *CriteriaUpdater) Updates() *services.CriteriaUpdates { return u.updates }

// Update waits until the matcher applies the replacement, or rejects an incompatible change.
func (u *CriteriaUpdater) Update(ctx context.Context, cfg *obi.Config) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if !reflect.DeepEqual(u.fixedConfig, withoutSelectionAndSinks(cfg)) {
		return errors.New("only discovery selection criteria can be refreshed; restart OBI to apply other configuration changes")
	}

	if cfg.JoinMetricsConfig().Features&^(u.features|export.FeatureEmpty) != 0 {
		return errors.New("new metric features require pipeline initialization; restart OBI to apply this configuration")
	}

	if err := cfg.Discovery.Validate(); err != nil {
		return err
	}

	include, exclude := refreshableCriteria(cfg), ExcludingCriteria(cfg)
	current, _ := u.updates.Current()
	if err := compatibleDefinitions(current, include); err != nil {
		return err
	}

	return u.updates.Replace(ctx, include, exclude)
}

func withoutSelectionAndSinks(cfg *obi.Config) obi.Config {
	fixed := *cfg
	fixed.Traces.TracesExport = nil
	fixed.OTELMetrics.MetricsExport = nil
	fixed.Port = services.IntEnum{}
	fixed.TargetPIDs = services.IntEnum{}
	fixed.Exec = services.RegexpAttr{}
	fixed.AutoTargetExe = services.GlobAttr{}
	fixed.AutoTargetLanguage = services.GlobAttr{}
	fixed.Discovery.Instrument = nil
	fixed.Discovery.Services = nil
	fixed.Discovery.ExcludeInstrument = nil
	fixed.Discovery.ExcludeServices = nil
	fixed.Discovery.DefaultExcludeInstrument = nil
	fixed.Discovery.DefaultExcludeServices = nil
	return fixed
}

type selectorSettings struct {
	name      string
	namespace string
	exports   services.ExportModes
	sampler   *services.SamplerConfig
	routes    *services.CustomRoutesConfig
	metrics   perapp.SvcMetricsConfig
}

func settingsFor(s services.Selector) selectorSettings {
	return selectorSettings{
		name:      s.GetName(),
		namespace: s.GetNamespace(),
		exports:   s.GetExportModes(),
		sampler:   s.GetSamplerConfig(),
		routes:    s.GetRoutesConfig(),
		metrics:   s.MetricsConfig(),
	}
}

func matchingSettings(criteria []services.Selector) selectorSettings {
	var settings selectorSettings
	for _, criterion := range criteria {
		next := settingsFor(criterion)
		if next.name != "" {
			settings.name = next.name
		}

		if next.namespace != "" {
			settings.namespace = next.namespace
		}

		if next.exports != services.ExportModeUnset {
			settings.exports = next.exports
		}

		if next.sampler != nil {
			settings.sampler = next.sampler
		}

		if next.routes != nil {
			settings.routes = next.routes
		}

		settings.metrics = next.metrics
	}
	return settings
}

type observedProcess struct {
	attrs   ProcessAttrs
	process *services.ProcessInfo
}

// refresh rematches observed processes and rejects changes to retained services before emitting events.
func (m *Matcher) refresh(ctx context.Context, update services.CriteriaUpdate) error {
	if err := update.Context.Err(); err != nil {
		return err
	}

	next := *m
	next.Criteria = update.Include
	next.ExcludeCriteria = update.Exclude
	next.ProcessHistory = map[app.PID]ProcessMatch{}
	visited := map[app.PID]bool{}

	for pid := range m.observed {
		next.rematch(pid, visited)
	}

	var events []Event[ProcessMatch]
	for pid, previous := range m.ProcessHistory {
		replacement, retained := next.ProcessHistory[pid]
		if retained {
			matchingSettings := reflect.DeepEqual(matchingSettings(previous.Criteria), matchingSettings(replacement.Criteria))
			if !matchingSettings ||
				previous.LogEnricherEnabled() != replacement.LogEnricherEnabled() {
				return fmt.Errorf("service settings would change for PID %d; restart OBI to apply this configuration", pid)
			}
			continue
		}

		events = append(events, Event[ProcessMatch]{Type: EventDeleted, Obj: previous})
	}

	for pid, match := range next.ProcessHistory {
		if _, retained := m.ProcessHistory[pid]; !retained {
			events = append(events, Event[ProcessMatch]{Type: EventCreated, Obj: match})
		}
	}

	if err := update.Context.Err(); err != nil {
		return err
	}

	m.Criteria = next.Criteria
	m.ExcludeCriteria = next.ExcludeCriteria
	m.ProcessHistory = next.ProcessHistory

	if len(events) > 0 {
		m.Output.SendCtx(ctx, events)
	}

	return nil
}

func (m *Matcher) rematch(pid app.PID, visiting map[app.PID]bool) {
	if m.alreadyMatched(pid) || visiting[pid] {
		return
	}

	observed, ok := m.observed[pid]
	if !ok {
		return
	}

	visiting[pid] = true
	m.rematch(observed.process.PPid, visiting)

	// Re-fetch fresh process information so a port/executable change that
	// happened without a new creation event is reflected at refresh time.
	proc, err := processInfo(observed.attrs)
	if err != nil {
		m.Log.Debug("can't refresh information for process", "pid", observed.attrs.pid, "error", err)
		return
	}
	observed.process = proc
	m.observed[pid] = observed
	m.filterCreated(observed.attrs)
}

func refreshableCriteria(cfg *obi.Config) []services.Selector {
	if !cfg.Enabled(obi.FeatureAppO11y) {
		return nil
	}

	return FindingCriteria(cfg)
}

// Definitions may be added, removed or reordered, but existing service settings cannot be replaced.
func compatibleDefinitions(current, next []services.Selector) error {
	if !definitionsKeepSettings(current, next) {
		return errors.New("service settings changed in discovery definitions; restart OBI to apply this configuration")
	}

	byPredicate := map[string][]selectorSettings{}
	for _, previous := range current {
		key, err := predicateKey(previous)
		if err != nil {
			return err
		}
		byPredicate[key] = append(byPredicate[key], settingsFor(previous))
	}

	for _, candidate := range next {
		key, err := predicateKey(candidate)
		if err != nil {
			return err
		}

		previous, exists := byPredicate[key]
		if !exists {
			continue
		}

		found := false
		for _, settings := range previous {
			if reflect.DeepEqual(settings, settingsFor(candidate)) {
				found = true
				break
			}
		}

		if !found {
			return errors.New("service settings changed for an existing discovery predicate; restart OBI to apply this configuration")
		}
	}

	return nil
}

func predicateKey(selector services.Selector) (string, error) {
	var predicates any
	switch value := selector.(type) {
	case *services.GlobAttributes:
		match := *value
		match.Name = ""
		match.Namespace = ""
		match.ExportModes = services.ExportModeUnset
		match.SamplerConfig = nil
		match.Routes = nil
		match.Metrics = perapp.SvcMetricsConfig{}
		predicates = match
	case *services.RegexSelector:
		match := *value
		match.Name = ""
		match.Namespace = ""
		match.ExportModes = services.ExportModeUnset
		match.SamplerConfig = nil
		match.Routes = nil
		match.Metrics = perapp.SvcMetricsConfig{}
		predicates = match
	default:
		return "", errors.New("unsupported discovery selector for config refresh; restart OBI")
	}

	data, err := yaml.Marshal(predicates)
	return string(data), err
}

func definitionsKeepSettings(current, next []services.Selector) bool {
	remaining := append([]services.Selector(nil), current...)
	added := 0

	for _, candidate := range next {
		matched := -1

		for i, previous := range remaining {
			if reflect.DeepEqual(settingsFor(previous), settingsFor(candidate)) {
				matched = i
				break
			}
		}

		if matched < 0 {
			added++
			continue
		}

		remaining = append(remaining[:matched], remaining[matched+1:]...)
	}

	return len(remaining) == 0 || added == 0
}
