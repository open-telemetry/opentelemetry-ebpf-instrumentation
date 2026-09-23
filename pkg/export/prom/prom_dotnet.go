// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type dotnetRuntimeMetricsCollector struct {
	collections             *Expirer[prometheus.Counter]
	processMemoryWorkingSet *Expirer[prometheus.Gauge]
	gcCommittedMemory       *Expirer[prometheus.Gauge]
	threadPoolThreadCount   *Expirer[prometheus.Gauge]
	threadPoolQueueLength   *Expirer[prometheus.Gauge]
	timerCount              *Expirer[prometheus.Gauge]
	assemblyCount           *Expirer[prometheus.Gauge]
	baseLabelIndexes        []int
	valuesMu                sync.Mutex
	values                  map[dotnetRuntimeCounterKey]uint64
	currentValues           map[app.PID]dotnetRuntimeCurrentValues
	clock                   expire.Clock
	ttl                     time.Duration
}

type dotnetRuntimeCurrentValues struct {
	generation uint64
	lastSeen   time.Time
	labels     []string
	values     runtimemetrics.DotnetRuntimeMetricSnapshot
}

type dotnetRuntimeCounterKey struct {
	pid        app.PID
	generation uint64
	labels     string
	baseLabels string
}

func (c *dotnetRuntimeMetricsCollector) delete(values []string) {
	if c.collections == nil {
		return
	}
	c.valuesMu.Lock()
	defer c.valuesMu.Unlock()
	labels := make([]string, 0, len(c.baseLabelIndexes)+1)
	for _, index := range c.baseLabelIndexes {
		labels = append(labels, values[index])
	}
	baseLabels := runtimeMetricLabelTuple(labels)
	labels = append(labels, "")
	for generation := range runtimemetrics.DotnetGCGenerationCount {
		labels[len(labels)-1] = fmt.Sprintf("gen%d", generation)
		c.collections.DeleteLabelValues(labels...)
	}
	for key := range c.values {
		if key.baseLabels == baseLabels {
			delete(c.values, key)
		}
	}
	for pid, current := range c.currentValues {
		if runtimeMetricLabelTuple(current.labels) == baseLabels {
			delete(c.currentValues, pid)
		}
	}
	c.setCurrentMetrics(labels[:len(labels)-1])
}

func (r *metricsReporter) collectDotnetRuntimeMetrics(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	c := &r.dotnetRuntimeMetrics
	if c.collections == nil || snapshot.Dotnet == nil {
		return
	}
	c.valuesMu.Lock()
	defer c.valuesMu.Unlock()
	if snapshot.Removed {
		if previous, exists := c.currentValues[snapshot.PID]; exists && previous.generation == snapshot.Generation {
			delete(c.currentValues, snapshot.PID)
			c.setCurrentMetrics(previous.labels)
		}
		for key := range c.values {
			if key.pid == snapshot.PID && key.generation == snapshot.Generation {
				delete(c.values, key)
			}
		}
		return
	}
	if c.values == nil {
		c.values = make(map[dotnetRuntimeCounterKey]uint64)
	}
	for key := range c.values {
		if key.pid == snapshot.PID && key.generation != snapshot.Generation {
			delete(c.values, key)
		}
	}
	base := r.labelValuesTargetInfo(&snapshot.Service)
	labels := make([]string, 0, len(c.baseLabelIndexes)+1)
	for _, index := range c.baseLabelIndexes {
		labels = append(labels, base[index])
	}
	if c.currentValues == nil {
		c.currentValues = make(map[app.PID]dotnetRuntimeCurrentValues)
	}
	previous, existed := c.currentValues[snapshot.PID]
	c.currentValues[snapshot.PID] = dotnetRuntimeCurrentValues{
		generation: snapshot.Generation,
		lastSeen:   c.clock(),
		labels:     append([]string(nil), labels...),
		values:     *snapshot.Dotnet,
	}
	if existed && runtimeMetricLabelTuple(previous.labels) != runtimeMetricLabelTuple(labels) {
		c.setCurrentMetrics(previous.labels)
	}
	c.setCurrentMetrics(labels)
	labels = append(labels, "")
	for generation, value := range snapshot.Dotnet.GCCollections {
		if value == nil {
			continue
		}
		labels[len(labels)-1] = fmt.Sprintf("gen%d", generation)
		key := dotnetRuntimeCounterKey{
			pid: snapshot.PID, generation: snapshot.Generation, labels: runtimeMetricLabelTuple(labels),
			baseLabels: runtimeMetricLabelTuple(labels[:len(labels)-1]),
		}
		previous, exists := c.values[key]
		entry := c.collections.WithLabelValues(labels...)
		if !exists || *value < previous {
			entry.Metric.Add(float64(*value))
		} else if *value > previous {
			entry.Metric.Add(float64(*value - previous))
		}
		c.values[key] = *value
	}
}

func (c *dotnetRuntimeMetricsCollector) expireCurrentMetrics() {
	if c.ttl == 0 {
		return
	}
	c.valuesMu.Lock()
	defer c.valuesMu.Unlock()
	now := c.clock()
	expiredLabels := make(map[string][]string)
	for pid, current := range c.currentValues {
		if now.Sub(current.lastSeen) > c.ttl {
			delete(c.currentValues, pid)
			expiredLabels[runtimeMetricLabelTuple(current.labels)] = current.labels
		}
	}
	for _, labels := range expiredLabels {
		c.setCurrentMetrics(labels)
	}
}

func (c *dotnetRuntimeMetricsCollector) setCurrentMetrics(labels []string) {
	key := runtimeMetricLabelTuple(labels)
	for _, current := range []struct {
		metric *Expirer[prometheus.Gauge]
		value  func(*runtimemetrics.DotnetRuntimeMetricSnapshot) *int64
	}{
		{c.processMemoryWorkingSet, func(v *runtimemetrics.DotnetRuntimeMetricSnapshot) *int64 { return v.ProcessMemoryWorkingSet }},
		{c.gcCommittedMemory, func(v *runtimemetrics.DotnetRuntimeMetricSnapshot) *int64 { return v.GCCommittedMemory }},
		{c.threadPoolThreadCount, func(v *runtimemetrics.DotnetRuntimeMetricSnapshot) *int64 { return v.ThreadPoolThreadCount }},
		{c.threadPoolQueueLength, func(v *runtimemetrics.DotnetRuntimeMetricSnapshot) *int64 { return v.ThreadPoolQueueLength }},
		{c.timerCount, func(v *runtimemetrics.DotnetRuntimeMetricSnapshot) *int64 { return v.TimerCount }},
		{c.assemblyCount, func(v *runtimemetrics.DotnetRuntimeMetricSnapshot) *int64 { return v.AssemblyCount }},
	} {
		var total float64
		available := false
		for _, entry := range c.currentValues {
			if runtimeMetricLabelTuple(entry.labels) != key {
				continue
			}
			if value := current.value(&entry.values); value != nil {
				total += float64(*value)
				available = true
			}
		}
		if available {
			current.metric.WithLabelValues(labels...).Metric.Set(total)
		} else {
			current.metric.DeleteLabelValues(labels...)
		}
	}
}

func newDotnetRuntimeMetricsCollector(runtimeLabelNames []string, clock expire.Clock, ttl time.Duration) dotnetRuntimeMetricsCollector {
	labels := make([]string, 0, len(runtimeLabelNames)+1)
	baseLabelIndexes := make([]int, 0, len(runtimeLabelNames))
	for index, name := range runtimeLabelNames {
		if name == attr.DotnetGCHeapGeneration.Prom() {
			continue
		}
		labels = append(labels, name)
		baseLabelIndexes = append(baseLabelIndexes, index)
	}
	baseLabels := labels
	labels = append(labels, attr.DotnetGCHeapGeneration.Prom())
	return dotnetRuntimeMetricsCollector{
		collections: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.DotnetGCCollections.Prom,
			Help: "The number of garbage collections since the collector baseline, exclusive per generation.",
		}, labels).MetricVec, clock, ttl),
		processMemoryWorkingSet: newRuntimeGauge(attributes.DotnetProcessMemoryWorkingSet.Prom,
			"Current physical memory mapped to the .NET process in bytes.", baseLabels, clock, ttl),
		gcCommittedMemory: newRuntimeGauge(attributes.DotnetGCCommittedMemory.Prom,
			"Committed .NET GC memory at the latest collection in bytes.", baseLabels, clock, ttl),
		threadPoolThreadCount: newRuntimeGauge(attributes.DotnetThreadPoolThreadCount.Prom,
			"Current number of .NET thread-pool threads.", baseLabels, clock, ttl),
		threadPoolQueueLength: newRuntimeGauge(attributes.DotnetThreadPoolQueueLength.Prom,
			"Current number of queued .NET thread-pool work items.", baseLabels, clock, ttl),
		timerCount: newRuntimeGauge(attributes.DotnetTimerCount.Prom,
			"Current number of active .NET timers.", baseLabels, clock, ttl),
		assemblyCount: newRuntimeGauge(attributes.DotnetAssemblyCount.Prom,
			"Current number of loaded .NET assemblies.", baseLabels, clock, ttl),
		baseLabelIndexes: baseLabelIndexes,
		clock:            clock,
		ttl:              ttl,
	}
}
