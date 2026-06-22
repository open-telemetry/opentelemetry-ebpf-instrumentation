// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"iter"
	"maps"
	"slices"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/selection"
)

type dynamicPIDSignal uint8

const (
	signalTraces dynamicPIDSignal = 1 << iota
	signalAppMetrics
	signalNetworkMetrics
	signalStatsMetrics
)

const (
	appSignalMask dynamicPIDSignal = signalTraces | signalAppMetrics
	allSignalMask dynamicPIDSignal = appSignalMask | signalNetworkMetrics | signalStatsMetrics
)

// TODO: support per-signal attribute overrides; attributes are currently shared across all signals.

type dynamicPIDAttributes struct {
	serviceName        string
	serviceNamespace   string
	resourceAttributes map[string]string
}

type dynamicPIDRecord struct {
	signals dynamicPIDSignal
	attrs   dynamicPIDAttributes
}

type dynamicPIDNotifier struct {
	addedCh   chan []app.PID
	removedCh chan []app.PID

	addedPending []app.PID
	addedMu      sync.Mutex
	addedCond    *sync.Cond

	removedPending []app.PID
	removedMu      sync.Mutex
	removedCond    *sync.Cond
}

func newDynamicPIDNotifier() *dynamicPIDNotifier {
	n := &dynamicPIDNotifier{
		addedCh:   make(chan []app.PID, 1),
		removedCh: make(chan []app.PID, 1),
	}
	n.addedCond = sync.NewCond(&n.addedMu)
	n.removedCond = sync.NewCond(&n.removedMu)
	go n.drainAdded()
	go n.drainRemoved()
	return n
}

func (n *dynamicPIDNotifier) notifyAdded(pids []app.PID) {
	if len(pids) == 0 {
		return
	}
	n.addedMu.Lock()
	n.addedPending = append(n.addedPending, pids...)
	n.addedCond.Signal()
	n.addedMu.Unlock()
}

func (n *dynamicPIDNotifier) notifyRemoved(pids []app.PID) {
	if len(pids) == 0 {
		return
	}
	n.removedMu.Lock()
	n.removedPending = append(n.removedPending, pids...)
	n.removedCond.Signal()
	n.removedMu.Unlock()
}

func (n *dynamicPIDNotifier) drainAdded() {
	for {
		n.addedMu.Lock()
		for len(n.addedPending) == 0 {
			n.addedCond.Wait()
		}
		batch := append([]app.PID(nil), n.addedPending...)
		n.addedPending = n.addedPending[:0]
		n.addedMu.Unlock()
		n.addedCh <- batch
	}
}

func (n *dynamicPIDNotifier) drainRemoved() {
	for {
		n.removedMu.Lock()
		for len(n.removedPending) == 0 {
			n.removedCond.Wait()
		}
		batch := append([]app.PID(nil), n.removedPending...)
		n.removedPending = n.removedPending[:0]
		n.removedMu.Unlock()
		n.removedCh <- batch
	}
}

type dynamicPIDSignalView struct {
	parent   *DynamicPIDSelector
	mask     dynamicPIDSignal
	notifier *dynamicPIDNotifier
}

func (v *dynamicPIDSignalView) AddPIDs(pids ...uint32) {
	v.parent.addSignals(v.mask, nil, pids...)
}

func (v *dynamicPIDSignalView) AddPID(pid uint32, opts selection.DynamicPIDOptions) {
	v.parent.addSignals(v.mask, &opts, pid)
}

func (v *dynamicPIDSignalView) RemovePIDs(pids ...uint32) {
	v.parent.removeSignals(v.mask, pids...)
}

func (v *dynamicPIDSignalView) GetPIDs() ([]app.PID, bool) {
	return v.parent.getPIDs(v.mask)
}

func (v *dynamicPIDSignalView) IncludesPID(pid app.PID) bool {
	return v.parent.includesPID(v.mask, pid)
}

func (v *dynamicPIDSignalView) AddedPIDsNotify() <-chan []app.PID {
	return v.notifier.addedCh
}

func (v *dynamicPIDSignalView) RemovedNotify() <-chan []app.PID {
	return v.notifier.removedCh
}

// SelectorForPID returns a services.Selector for pid when it is in this view, carrying the
// PID's shared service name and resource attributes.
func (v *dynamicPIDSignalView) SelectorForPID(pid app.PID) services.Selector {
	if !v.IncludesPID(pid) {
		return nil
	}
	return v.parent.selectorForPID(pid)
}

// AsSelector returns a services.Selector that matches when the process PID is in this dynamic view.
func (v *dynamicPIDSignalView) AsSelector() services.Selector {
	return &dynamicPIDCriteriaAdapter{view: v}
}

// DynamicPIDSelector holds one runtime selector object with per-signal PID views. The root Add/Remove
// methods preserve legacy behavior by applying to all supported signals.
type DynamicPIDSelector struct {
	mu    sync.RWMutex
	byPID map[app.PID]dynamicPIDRecord

	rootView           dynamicPIDSignalView
	tracesView         dynamicPIDSignalView
	appMetricsView     dynamicPIDSignalView
	networkMetricsView dynamicPIDSignalView
	statsMetricsView   dynamicPIDSignalView
	appSignalsView     dynamicPIDSignalView
}

var _ selection.MultiSignalPIDSelector = (*DynamicPIDSelector)(nil)

func newDynamicPIDSignalView(parent *DynamicPIDSelector, mask dynamicPIDSignal) dynamicPIDSignalView {
	return dynamicPIDSignalView{
		parent:   parent,
		mask:     mask,
		notifier: newDynamicPIDNotifier(),
	}
}

// NewDynamicPIDSelector creates a new selector whose root Add/Remove methods apply to all signals.
func NewDynamicPIDSelector() *DynamicPIDSelector {
	d := &DynamicPIDSelector{
		byPID: map[app.PID]dynamicPIDRecord{},
	}
	d.rootView = newDynamicPIDSignalView(d, allSignalMask)
	d.tracesView = newDynamicPIDSignalView(d, signalTraces)
	d.appMetricsView = newDynamicPIDSignalView(d, signalAppMetrics)
	d.networkMetricsView = newDynamicPIDSignalView(d, signalNetworkMetrics)
	d.statsMetricsView = newDynamicPIDSignalView(d, signalStatsMetrics)
	d.appSignalsView = newDynamicPIDSignalView(d, appSignalMask)
	return d
}

func (d *DynamicPIDSelector) views() []*dynamicPIDSignalView {
	return []*dynamicPIDSignalView{
		&d.rootView,
		&d.tracesView,
		&d.appMetricsView,
		&d.networkMetricsView,
		&d.statsMetricsView,
		&d.appSignalsView,
	}
}

func (d *DynamicPIDSelector) addSignals(mask dynamicPIDSignal, opts *selection.DynamicPIDOptions, pids ...uint32) {
	if len(pids) == 0 {
		return
	}
	addedByView := map[*dynamicPIDSignalView][]app.PID{}

	d.mu.Lock()
	for _, rawPID := range pids {
		pid := app.PID(rawPID)
		rec := d.byPID[pid]
		oldMask := rec.signals

		if opts != nil {
			rec.attrs = attrsFromOptions(*opts)
		}

		newMask := oldMask | mask
		if newMask == oldMask {
			if opts != nil {
				d.byPID[pid] = rec
			}
			continue
		}
		rec.signals = newMask
		d.byPID[pid] = rec

		for _, view := range d.views() {
			if !view.contains(oldMask) && view.contains(newMask) {
				addedByView[view] = append(addedByView[view], pid)
			}
		}
	}
	d.mu.Unlock()

	for view, batch := range addedByView {
		view.notifier.notifyAdded(batch)
	}
}

func (d *DynamicPIDSelector) removeSignals(mask dynamicPIDSignal, pids ...uint32) {
	if len(pids) == 0 {
		return
	}
	removedByView := map[*dynamicPIDSignalView][]app.PID{}

	d.mu.Lock()
	for _, rawPID := range pids {
		pid := app.PID(rawPID)
		rec, ok := d.byPID[pid]
		if !ok {
			continue
		}
		oldMask := rec.signals
		newMask := oldMask &^ mask
		if newMask == oldMask {
			continue
		}
		if newMask == 0 {
			delete(d.byPID, pid)
		} else {
			rec.signals = newMask
			d.byPID[pid] = rec
		}
		for _, view := range d.views() {
			if view.contains(oldMask) && !view.contains(newMask) {
				removedByView[view] = append(removedByView[view], pid)
			}
		}
	}
	d.mu.Unlock()

	for view, batch := range removedByView {
		view.notifier.notifyRemoved(batch)
	}
}

func (d *DynamicPIDSelector) getPIDs(mask dynamicPIDSignal) ([]app.PID, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.byPID) == 0 {
		return nil, false
	}
	out := make([]app.PID, 0, len(d.byPID))
	for pid, rec := range d.byPID {
		if rec.signals&mask != 0 {
			out = append(out, pid)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	slices.Sort(out)
	return out, true
}

func (d *DynamicPIDSelector) includesPID(mask dynamicPIDSignal, pid app.PID) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.byPID[pid].signals&mask != 0
}

func (d *DynamicPIDSelector) selectorForPID(pid app.PID) services.Selector {
	d.mu.RLock()
	rec, ok := d.byPID[pid]
	d.mu.RUnlock()
	if !ok {
		return nil
	}
	return newDynamicPIDCriteriaAdapter(pid, rec.attrs)
}

// GetPID returns the shared attributes for a tracked PID.
func (d *DynamicPIDSelector) GetPID(pid uint32) (selection.DynamicPIDEntry, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rec, ok := d.byPID[app.PID(pid)]
	if !ok {
		return selection.DynamicPIDEntry{}, false
	}
	return entryFromRecord(app.PID(pid), rec.attrs), true
}

// SetPID updates shared attributes for a PID that is already tracked by the selector.
func (d *DynamicPIDSelector) SetPID(entry selection.DynamicPIDEntry) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.byPID[entry.PID]; !ok {
		return false
	}
	d.byPID[entry.PID] = dynamicPIDRecord{
		signals: d.byPID[entry.PID].signals,
		attrs:   attrsFromEntry(entry),
	}
	return true
}

func (v *dynamicPIDSignalView) contains(mask dynamicPIDSignal) bool {
	return mask&v.mask != 0
}

// AddPID adds a PID to all supported signals with optional shared attributes.
func (d *DynamicPIDSelector) AddPID(pid uint32, opts selection.DynamicPIDOptions) {
	d.rootView.AddPID(pid, opts)
}

// AddPIDs adds PIDs to all supported signals (legacy root behavior).
func (d *DynamicPIDSelector) AddPIDs(pids ...uint32) {
	d.rootView.AddPIDs(pids...)
}

// RemovePIDs removes PIDs from all supported signals (legacy root behavior).
func (d *DynamicPIDSelector) RemovePIDs(pids ...uint32) {
	d.rootView.RemovePIDs(pids...)
}

// GetPIDs returns PIDs selected for any supported signal.
func (d *DynamicPIDSelector) GetPIDs() ([]app.PID, bool) {
	return d.rootView.GetPIDs()
}

// IncludesPID reports whether pid is selected for any supported signal.
func (d *DynamicPIDSelector) IncludesPID(pid app.PID) bool {
	return d.rootView.IncludesPID(pid)
}

// AddedPIDsNotify returns the channel on which PIDs are sent when they enter the root view.
func (d *DynamicPIDSelector) AddedPIDsNotify() <-chan []app.PID {
	return d.rootView.AddedPIDsNotify()
}

// RemovedNotify returns the channel on which PIDs are sent when they leave the root view.
func (d *DynamicPIDSelector) RemovedNotify() <-chan []app.PID {
	return d.rootView.RemovedNotify()
}

// Traces returns the mutable selector view for trace signals.
func (d *DynamicPIDSelector) Traces() selection.MutablePIDSelector {
	return &d.tracesView
}

// AppMetrics returns the mutable selector view for application metrics signals.
func (d *DynamicPIDSelector) AppMetrics() selection.MutablePIDSelector {
	return &d.appMetricsView
}

// NetworkMetrics returns the mutable selector view for network metrics signals.
func (d *DynamicPIDSelector) NetworkMetrics() selection.MutablePIDSelector {
	return &d.networkMetricsView
}

// StatsMetrics returns the mutable selector view for stats metrics signals.
func (d *DynamicPIDSelector) StatsMetrics() selection.MutablePIDSelector {
	return &d.statsMetricsView
}

func (d *DynamicPIDSelector) appSignals() *dynamicPIDSignalView {
	return &d.appSignalsView
}

// AsSelector preserves the legacy root-selector behavior.
func (d *DynamicPIDSelector) AsSelector() services.Selector {
	return d.rootView.AsSelector()
}

// ResourceAttributesFromSelector returns resource attributes configured on a dynamic PID
// selector criteria, or nil when the selector is not from DynamicPIDSelector.
func ResourceAttributesFromSelector(selector services.Selector) map[attr.Name]string {
	adapter, ok := selector.(*dynamicPIDCriteriaAdapter)
	if !ok || len(adapter.attrs.resourceAttributes) == 0 {
		return nil
	}
	out := make(map[attr.Name]string, len(adapter.attrs.resourceAttributes))
	for k, v := range adapter.attrs.resourceAttributes {
		out[attr.Name(k)] = v
	}
	return out
}

// dynamicPIDCriteriaAdapter implements services.Selector for a dynamically selected PID.
type dynamicPIDCriteriaAdapter struct {
	pid   app.PID
	attrs dynamicPIDAttributes
	view  *dynamicPIDSignalView
}

func newDynamicPIDCriteriaAdapter(pid app.PID, attrs dynamicPIDAttributes) *dynamicPIDCriteriaAdapter {
	return &dynamicPIDCriteriaAdapter{pid: pid, attrs: cloneAttrs(attrs)}
}

func (a *dynamicPIDCriteriaAdapter) GetName() string      { return a.attrs.serviceName }
func (a *dynamicPIDCriteriaAdapter) GetNamespace() string { return a.attrs.serviceNamespace }
func (a *dynamicPIDCriteriaAdapter) GetPath() services.StringMatcher {
	return &emptyMatcher{}
}
func (a *dynamicPIDCriteriaAdapter) GetPathRegexp() services.StringMatcher { return &emptyMatcher{} }
func (a *dynamicPIDCriteriaAdapter) GetOpenPorts() *services.IntEnum       { return &services.IntEnum{} }
func (a *dynamicPIDCriteriaAdapter) GetLanguages() services.StringMatcher  { return &emptyMatcher{} }
func (a *dynamicPIDCriteriaAdapter) GetPIDs() ([]app.PID, bool) {
	if a.view != nil {
		return a.view.GetPIDs()
	}
	return []app.PID{a.pid}, true
}
func (a *dynamicPIDCriteriaAdapter) GetCmdArgs() services.StringMatcher { return &emptyMatcher{} }
func (a *dynamicPIDCriteriaAdapter) IsContainersOnly() bool             { return false }
func (a *dynamicPIDCriteriaAdapter) RangeMetadata() iter.Seq2[string, services.StringMatcher] {
	return emptyMetadataSeq2
}

func (a *dynamicPIDCriteriaAdapter) RangePodLabels() iter.Seq2[string, services.StringMatcher] {
	return emptyMetadataSeq2
}

func (a *dynamicPIDCriteriaAdapter) RangePodAnnotations() iter.Seq2[string, services.StringMatcher] {
	return emptyMetadataSeq2
}

func (a *dynamicPIDCriteriaAdapter) GetExportModes() services.ExportModes {
	return services.ExportModeUnset
}

func (a *dynamicPIDCriteriaAdapter) GetSamplerConfig() *services.SamplerConfig { return nil }
func (a *dynamicPIDCriteriaAdapter) GetRoutesConfig() *services.CustomRoutesConfig {
	return nil
}

func (a *dynamicPIDCriteriaAdapter) MetricsConfig() perapp.SvcMetricsConfig {
	return perapp.SvcMetricsConfig{}
}

type emptyMatcher struct{}

func (emptyMatcher) IsSet() bool               { return false }
func (emptyMatcher) MatchString(_ string) bool { return false }

func emptyMetadataSeq2(_ func(string, services.StringMatcher) bool) {}

func attrsFromOptions(opts selection.DynamicPIDOptions) dynamicPIDAttributes {
	return dynamicPIDAttributes{
		serviceName:        opts.ServiceName,
		serviceNamespace:   opts.ServiceNamespace,
		resourceAttributes: maps.Clone(opts.ResourceAttributes),
	}
}

func attrsFromEntry(entry selection.DynamicPIDEntry) dynamicPIDAttributes {
	return dynamicPIDAttributes{
		serviceName:        entry.ServiceName,
		serviceNamespace:   entry.ServiceNamespace,
		resourceAttributes: maps.Clone(entry.ResourceAttributes),
	}
}

func entryFromRecord(pid app.PID, attrs dynamicPIDAttributes) selection.DynamicPIDEntry {
	return selection.DynamicPIDEntry{
		PID:                pid,
		ServiceName:        attrs.serviceName,
		ServiceNamespace:   attrs.serviceNamespace,
		ResourceAttributes: maps.Clone(attrs.resourceAttributes),
	}
}

func cloneAttrs(attrs dynamicPIDAttributes) dynamicPIDAttributes {
	return dynamicPIDAttributes{
		serviceName:        attrs.serviceName,
		serviceNamespace:   attrs.serviceNamespace,
		resourceAttributes: maps.Clone(attrs.resourceAttributes),
	}
}
