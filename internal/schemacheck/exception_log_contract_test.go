// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/exceptions"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const exceptionEvent = "exception"

func exportedExceptionLogs(t *testing.T, events []exceptions.Event) plog.Logs {
	t.Helper()

	received := make(chan plog.Logs, 1)
	cfg := otelcfg.LogsConfig{
		BatchMaxSize: len(events),
		QueueSize:    2 * len(events),
		BatchTimeout: time.Hour,
		LogsExport: func(_ context.Context, l plog.Logs) error {
			received <- l
			return nil
		},
	}
	input := msg.NewQueue[[]exceptions.Event]()
	run, err := otel.ExceptionLogsReceiver(&global.ContextInfo{}, cfg, nil, input)(t.Context())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); run(ctx) }()
	defer func() { cancel(); <-done }()

	input.Send(events)
	select {
	case logs := <-received:
		require.Equal(t, len(events), logs.LogRecordCount())
		return logs
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the exception logs receiver exported nothing")
		return plog.Logs{}
	}
}

func liveCheckAttributes(attrs pcommon.Map) []liveCheckAttribute {
	out := []liveCheckAttribute{}
	for key, value := range attrs.All() {
		out = append(out, liveCheckAttribute{Name: key, Value: value.AsRaw()})
	}
	return out
}

func liveCheckLogSamples(logs plog.Logs) (records, resources []any) {
	for _, rl := range logs.ResourceLogs().All() {
		resources = append(resources, map[string]any{"resource": map[string]any{
			"attributes": liveCheckAttributes(rl.Resource().Attributes()),
		}})
		for _, sl := range rl.ScopeLogs().All() {
			for _, record := range sl.LogRecords().All() {
				records = append(records, map[string]any{"log": map[string]any{
					"event_name":      record.EventName(),
					"severity_number": int32(record.SeverityNumber()),
					"severity_text":   record.SeverityText(),
					"attributes":      liveCheckAttributes(record.Attributes()),
				}})
			}
		}
	}
	return records, resources
}

func exceptionEventFixtures() []exceptions.Event {
	modes := services.NewExportModes()
	modes.AllowLogs()
	service := svc.Attrs{
		UID:         svc.UID{Name: "checkout", Instance: "instance-1"},
		SDKLanguage: svc.InstrumentableGolang,
		Exceptions:  services.ExceptionsConfig{Enabled: true},
		ExportModes: modes,
	}
	event := func(typ, message, stacktrace string) exceptions.Event {
		return exceptions.Event{
			Service: service, Timestamp: time.Unix(100, 0), ObservedTimestamp: time.Unix(101, 0), SeverityNumber: 17,
			Type: typ, Message: message, Stacktrace: stacktrace,
		}
	}
	return []exceptions.Event{
		event("go.panic", "runtime error: index out of range [5] with length 3", "main.handler\n\t/app/main.go:12"),
		event("go.error", "", "main.handler\n\t/app/main.go:20"),
		event("", "boom", ""),
	}
}

func TestExceptionEventIsImportedFromUpstream(t *testing.T) {
	obi := resolveRegistry(t)

	var found []resolvedSignal
	for _, e := range obi.Registry.Events {
		if e.metricName(t) == exceptionEvent {
			found = append(found, e)
		}
	}
	require.Len(t, found, 1, "the registry must declare the %q event exactly once", exceptionEvent)
	assert.False(t, found[0].Provenance.local(),
		"the %q event must be imported unchanged from the upstream registry, not redefined", exceptionEvent)
}

func TestEmittedExceptionLogsMatchTheExceptionEvent(t *testing.T) {
	events := exceptionEventFixtures()
	logs := exportedExceptionLogs(t, events)
	records, resources := liveCheckLogSamples(logs)
	require.NotEmpty(t, resources)

	for _, r := range records {
		assert.Equal(t, exceptionEvent, r.(map[string]any)["log"].(map[string]any)["event_name"])
	}

	samples := slices.Concat(records, resources)
	report := compactReport(t, samples)
	assert.Equal(t, map[string]int{exceptionEvent: len(events)}, report.MatchedSignals)
	assert.Empty(t, report.Unmatched)
	for _, f := range report.Findings {
		assert.NotEqualf(t, "violation", f.Level, "[%s] %s on %v", f.Type, f.Message, f.Signals)
	}

	var keys struct {
		SignalAttributes map[string][]string `json:"signal_attributes"`
	}
	require.NoError(t, json.Unmarshal(rawCompactReport(t, samples), &keys))

	declared := map[string]struct{}{}
	for _, e := range resolveRegistry(t).Registry.Events {
		if e.metricName(t) == exceptionEvent {
			for _, a := range e.Attributes {
				declared[a.Key] = struct{}{}
			}
		}
	}
	require.NotEmpty(t, keys.SignalAttributes[exceptionEvent])
	for _, key := range keys.SignalAttributes[exceptionEvent] {
		assert.Containsf(t, declared, key, "exception logs carry %q, which the %q event does not declare", key, exceptionEvent)
	}
}

func TestCompactReportFailsOnUndeclaredExceptionLogAttribute(t *testing.T) {
	report := compactReport(t, []any{map[string]any{"log": map[string]any{
		"event_name": exceptionEvent,
		"attributes": []liveCheckAttribute{
			{Name: "exception.type", Value: "go.panic"},
			{Name: "http.route", Value: "/users"},
		},
	}}})

	assert.Equal(t, map[string]int{exceptionEvent: 1}, report.MatchedSignals)
	assert.Contains(t, unexpectedKeys(report, "log"), "http.route")
	assert.Positive(t, report.Statistics.AdviceLevelCounts["violation"])
}
