// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
)

func TestExceptionTypeLabels(t *testing.T) {
	var types exceptionTypes
	for i := range maximumExceptionTypes {
		name := "Failure" + strconv.Itoa(i)
		label, err := types.labelFor(name)
		require.NoError(t, err)
		require.Equal(t, name, label)
	}
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"Failure0", "Failure0"},
		{"NewFailure", exceptionTypeOther},
		{strings.Repeat("x", maximumExceptionTypeBytes+1), exceptionTypeOther},
		{exceptionTypeOther, exceptionTypeOther},
	} {
		label, err := types.labelFor(tc.raw)
		require.NoError(t, err)
		require.Equal(t, tc.want, label)
	}
	require.Len(t, types.names, maximumExceptionTypes)
	_, err := types.labelFor("")
	require.ErrorContains(t, err, "empty name")

	var fresh exceptionTypes
	label, err := fresh.labelFor(strings.Repeat("x", maximumExceptionTypeBytes+1))
	require.NoError(t, err)
	require.Equal(t, exceptionTypeOther, label)
	require.Empty(t, fresh.names)
	name := strings.Repeat("x", maximumExceptionTypeBytes)
	label, err = fresh.labelFor(name)
	require.NoError(t, err)
	require.Equal(t, name, label)
	require.Len(t, fresh.names, 1)
}

func TestExceptionTypeLabelsPreserveSuppliedName(t *testing.T) {
	var types exceptionTypes
	for _, name := range []string{"Failure`1", "Failure.With.Dot", "Failure+Nested", "Failure[Suffix]"} {
		label, err := types.labelFor(name)
		require.NoError(t, err)
		require.Equal(t, name, label)
	}
}

func TestExceptionMetricDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name        string
		event       string
		values      map[string]any
		warning     string
		unavailable bool
		wantError   bool
	}{
		{name: "another owner", event: "MultipleSessionsNotSupportedError", values: map[string]any{"runningSessionId": "other"}, warning: "another diagnostics client owns the Meter subscription", unavailable: true},
		{name: "same owner", event: "MultipleSessionsNotSupportedError", values: map[string]any{"runningSessionId": "ours"}},
		{name: "missing owner", event: "MultipleSessionsNotSupportedError", wantError: true},
		{name: "foreign error", event: "Error", values: map[string]any{"sessionId": "other"}},
		{name: "missing session", event: "Error"},
		{name: "series limit", event: "TimeSeriesLimitReached", values: map[string]any{"sessionId": "ours"}, warning: "runtime exception time-series limit reached; additional types are omitted"},
		{name: "runtime error", event: "Error", values: map[string]any{"sessionId": "ours"}, warning: "runtime Meter collection failed", unavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event, err := decodeExceptionMetric(tc.event, tc.values, "ours")
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, netTraceRuntimeEvent{
				exceptionWarning: tc.warning, exceptionsUnavailable: tc.unavailable,
			}, event)
		})
	}
}

func TestExceptionMetricDelta(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rate      any
		count     uint64
		empty     bool
		wantError bool
	}{
		{name: "interval count", rate: "3", count: 3},
		{name: "zero", rate: "0"},
		{name: "exponent", rate: "1e3", count: 1000},
		{name: "empty interval", rate: "", empty: true},
		{name: "missing", wantError: true},
		{name: "wrong type", rate: 3, wantError: true},
		{name: "malformed", rate: "invalid", wantError: true},
		{name: "negative", rate: "-1", wantError: true},
		{name: "fraction", rate: "1.5", wantError: true},
		{name: "nan", rate: "NaN", wantError: true},
		{name: "infinity", rate: "+Inf", wantError: true},
		{name: "overflow", rate: "9223372036854775808", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event, err := decodeExceptionMetric("CounterRateValuePublished", map[string]any{
				"sessionId": "ours", "meterName": "System.Runtime",
				"instrumentName": "dotnet.exceptions", "tags": "error.type=Failure`1",
				"rate": tc.rate,
			}, "ours")
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			want := netTraceRuntimeEvent{}
			if !tc.empty {
				want.exceptionType = "Failure`1"
				want.exceptionCount = tc.count
			}
			require.Equal(t, want, event)
		})
	}
}

func TestExceptionMetricSelection(t *testing.T) {
	for _, tc := range []struct {
		field     string
		value     any
		wantError bool
	}{
		{field: "sessionId", value: "other"},
		{field: "sessionId", value: nil},
		{field: "meterName", value: "Other.Meter"},
		{field: "instrumentName", value: "other.counter"},
		{field: "tags", value: "", wantError: true},
		{field: "tags", value: "error.type=", wantError: true},
		{field: "tags", value: "other=Failure", wantError: true},
		{field: "tags", value: 42, wantError: true},
	} {
		values := map[string]any{
			"sessionId": "ours", "meterName": "System.Runtime",
			"instrumentName": "dotnet.exceptions", "tags": "error.type=Failure", "rate": "2",
		}
		values[tc.field] = tc.value
		event, err := decodeExceptionMetric("CounterRateValuePublished", values, "ours")
		if tc.wantError {
			require.Error(t, err, "%s=%v", tc.field, tc.value)
		} else {
			require.NoError(t, err)
			require.Empty(t, event)
		}
	}
}

func TestExceptionMeterRecordedTraces(t *testing.T) {
	for _, version := range []string{"9", "10"} {
		for _, sessionID := range []string{"test-session", "other-session", ""} {
			t.Run(version+"/"+sessionID, func(t *testing.T) {
				trace, err := os.Open("testdata/exceptions-net" + version + ".nettrace")
				require.NoError(t, err)
				defer trace.Close()
				counts := map[string]uint64{}
				require.NoError(t, readRuntimeEvents(trace, 1, sessionID, func(event netTraceRuntimeEvent) error {
					require.NotEmpty(t, event.exceptionType)
					counts[event.exceptionType] += event.exceptionCount
					return nil
				}))
				if sessionID != "test-session" {
					require.Empty(t, counts)
					return
				}
				require.Equal(t, map[string]uint64{"Pr5Caught": 1, "Pr5Rethrown": 2, "Pr5ExplicitRethrow": 2, "Pr5Dispatch": 2, "Pr5Generic`1": 1, "Pr5Nested": 1, "Pr5Background": 1}, counts)
			})
		}
	}
}

func TestIsCLRExceptionThrown(t *testing.T) {
	header := netTraceMetadataHeader{
		ProviderName: "Microsoft-Windows-DotNETRuntime", EventID: 80, Version: 1,
	}
	require.True(t, isCLRExceptionThrown(header))
	for _, other := range []netTraceMetadataHeader{
		{ProviderName: "System.Runtime", EventID: 80, Version: 1},
		{ProviderName: header.ProviderName, EventID: 81, Version: 1},
		{ProviderName: header.ProviderName, EventID: 80, Version: 2},
	} {
		require.False(t, isCLRExceptionThrown(other))
	}
}

func clrExceptionPayload(name string, pointerSize int32) []byte {
	var payload []byte
	for _, value := range []string{name, "test message"} {
		for _, unit := range utf16.Encode([]rune(value + "\x00")) {
			payload = binary.LittleEndian.AppendUint16(payload, unit)
		}
	}
	return append(payload, make([]byte, int(pointerSize)+4+2+2)...)
}

func TestDecodeCLRExceptionType(t *testing.T) {
	for _, pointerSize := range []int32{4, 8} {
		payload := clrExceptionPayload("Example.Outer+Inner", pointerSize)
		name, err := decodeCLRExceptionType(bytes.NewReader(payload), pointerSize)
		require.NoError(t, err)
		require.Equal(t, "Example.Outer+Inner", name)
		for size := range len(payload) {
			_, err := decodeCLRExceptionType(bytes.NewReader(payload[:size]), pointerSize)
			require.Error(t, err)
		}
		_, err = decodeCLRExceptionType(bytes.NewReader(append(payload, 0)), pointerSize)
		require.Error(t, err)
	}
	_, err := decodeCLRExceptionType(bytes.NewReader(nil), 3)
	require.Error(t, err)
	_, err = decodeCLRExceptionType(bytes.NewReader(clrExceptionPayload("", 8)), 8)
	require.ErrorContains(t, err, "ExceptionType")
}

func TestShortCLRExceptionType(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"System.InvalidOperationException", "InvalidOperationException"},
		{"Contoso.Failure`1[System.String]", "Failure`1"},
		{"Failure[System.String]", "Failure"},
		{"Failure", "Failure"},
		{"Contoso.Échec", "Échec"},
		{"Contoso.Outer+Inner", "Inner"},
		{"", ""},
		{"Contoso.", ""},
	} {
		t.Run(tc.input, func(t *testing.T) {
			require.Equal(t, tc.want, shortCLRExceptionType(tc.input))
		})
	}
}

func TestCLRExceptionRecordedTrace(t *testing.T) {
	trace, err := os.Open("testdata/exceptions-net8.nettrace")
	require.NoError(t, err)
	defer trace.Close()
	counts := map[string]uint64{}
	require.NoError(t, readRuntimeEvents(trace, 1, "", func(event netTraceRuntimeEvent) error {
		if event.exceptionType != "" {
			counts[shortCLRExceptionType(event.exceptionType)]++
		}
		return nil
	}))
	require.Equal(t, map[string]uint64{"Pr5Caught": 1, "Pr5Rethrown": 2, "Pr5ExplicitRethrow": 2, "Pr5Dispatch": 2, "Pr5Generic`1": 1, "Pr5Nested": 1, "Pr5Background": 1}, counts)
}
