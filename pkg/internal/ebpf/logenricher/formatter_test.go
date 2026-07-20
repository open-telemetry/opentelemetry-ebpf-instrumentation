// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package logenricher

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	testTraceID       = "00112233445566778899aabbccddeeff"
	testSpanID        = "0011223344556677"
	testContextFields = "trace_id=" + testTraceID + " span_id=" + testSpanID
)

func TestLogFormatterPlainTextPlacement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		placement config.LogEnricherPlacement
		input     string
		want      string
	}{
		{
			name:      "suffix",
			placement: config.LogEnricherPlacementSuffix,
			input:     "request failed\n",
			want:      "request failed " + testContextFields + "\n",
		},
		{
			name:      "prefix",
			placement: config.LogEnricherPlacementPrefix,
			input:     "request failed\n",
			want:      testContextFields + " request failed\n",
		},
		{
			name:      "unterminated suffix",
			placement: config.LogEnricherPlacementSuffix,
			input:     "request failed",
			want:      "request failed " + testContextFields,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := obi.DefaultConfig.EBPF.LogEnricher
			cfg.PlainText.Placement = test.placement
			formatter := newLogFormatter(cfg)

			got, err := formatter.format([]byte(test.input), testTraceID, testSpanID, true)
			require.NoError(t, err)
			require.Equal(t, test.want, string(got))
		})
	}
}

func TestLogFormatterUsesSuppliedContext(t *testing.T) {
	t.Parallel()

	const (
		traceID = "ffeeddccbbaa99887766554433221100"
		spanID  = "ffeeddccbbaa9988"
	)

	formatter := newLogFormatter(obi.DefaultConfig.EBPF.LogEnricher)

	withSpan, err := formatter.format([]byte("with span\n"), traceID, spanID, true)
	require.NoError(t, err)
	require.Equal(t, "with span trace_id="+traceID+" span_id="+spanID+"\n", string(withSpan))

	withoutSpan, err := formatter.format([]byte("without span\n"), traceID, spanID, false)
	require.NoError(t, err)
	require.Equal(t, "without span trace_id="+traceID+"\n", string(withoutSpan))
}

func TestLogFormatterPlainTextMultiline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		multiline config.LogEnricherMultiline
		input     string
		want      string
	}{
		{
			name:      "first LF",
			multiline: config.LogEnricherMultilineFirstLine,
			input:     "\nfirst\n\nlast",
			want:      "\nfirst " + testContextFields + "\n\nlast",
		},
		{
			name:      "last LF",
			multiline: config.LogEnricherMultilineLastLine,
			input:     "\nfirst\n\nlast",
			want:      "\nfirst\n\nlast " + testContextFields,
		},
		{
			name:      "each LF",
			multiline: config.LogEnricherMultilineEachLine,
			input:     "\nfirst\n\nlast",
			want:      "\nfirst " + testContextFields + "\n\nlast " + testContextFields,
		},
		{
			name:      "first CRLF",
			multiline: config.LogEnricherMultilineFirstLine,
			input:     "\r\nfirst\r\n\r\nlast",
			want:      "\r\nfirst " + testContextFields + "\r\n\r\nlast",
		},
		{
			name:      "last CRLF",
			multiline: config.LogEnricherMultilineLastLine,
			input:     "\r\nfirst\r\n\r\nlast",
			want:      "\r\nfirst\r\n\r\nlast " + testContextFields,
		},
		{
			name:      "each CRLF",
			multiline: config.LogEnricherMultilineEachLine,
			input:     "\r\nfirst\r\n\r\nlast",
			want:      "\r\nfirst " + testContextFields + "\r\n\r\nlast " + testContextFields,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := obi.DefaultConfig.EBPF.LogEnricher
			cfg.PlainText.Multiline = test.multiline
			formatter := newLogFormatter(cfg)

			got := formatter.formatPlainText([]byte(test.input), testTraceID, testSpanID, true)
			require.Equal(t, test.want, string(got))
		})
	}
}

func TestLogFormatterPlainTextPreservesExistingFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		includeSpan bool
		want        string
	}{
		{
			name:        "both fields",
			input:       "request trace_id=sdk-trace span_id=sdk-span\n",
			includeSpan: true,
			want:        "request trace_id=sdk-trace span_id=sdk-span\n",
		},
		{
			name:        "trace field",
			input:       "request trace_id=sdk-trace\n",
			includeSpan: true,
			want:        "request trace_id=sdk-trace span_id=" + testSpanID + "\n",
		},
		{
			name:        "span field",
			input:       "request span_id=sdk-span\n",
			includeSpan: true,
			want:        "request span_id=sdk-span trace_id=" + testTraceID + "\n",
		},
		{
			name:        "exact token boundaries",
			input:       "xtrace_id=one trace_id_suffix=two\n",
			includeSpan: true,
			want:        "xtrace_id=one trace_id_suffix=two " + testContextFields + "\n",
		},
		{
			name:        "ASCII whitespace boundary",
			input:       "request\ttrace_id=sdk-trace\n",
			includeSpan: true,
			want:        "request\ttrace_id=sdk-trace span_id=" + testSpanID + "\n",
		},
		{
			name:        "trace only preserves SDK span",
			input:       "request span_id=sdk-span\n",
			includeSpan: false,
			want:        "request span_id=sdk-span trace_id=" + testTraceID + "\n",
		},
		{
			name:        "trace only omits generated span",
			input:       "request\n",
			includeSpan: false,
			want:        "request trace_id=" + testTraceID + "\n",
		},
	}

	formatter := newLogFormatter(obi.DefaultConfig.EBPF.LogEnricher)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := formatter.formatPlainText([]byte(test.input), testTraceID, testSpanID, test.includeSpan)
			require.Equal(t, test.want, string(got))
		})
	}
}

func TestLogFormatterPlainTextDisabled(t *testing.T) {
	t.Parallel()

	cfg := obi.DefaultConfig.EBPF.LogEnricher
	cfg.PlainText.Enabled = false
	formatter := newLogFormatter(cfg)

	plainText, err := formatter.format([]byte("request failed\n"), testTraceID, testSpanID, true)
	require.NoError(t, err)
	require.Equal(t, "request failed\n", string(plainText))

	jsonLog, err := formatter.format([]byte(`{"message":"request failed"}`), testTraceID, testSpanID, true)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(jsonLog, &fields))
	require.Equal(t, testTraceID, fields["trace_id"])
	require.Equal(t, testSpanID, fields["span_id"])
}

func TestLogFormatterCustomFieldNames(t *testing.T) {
	t.Parallel()

	cfg := obi.DefaultConfig.EBPF.LogEnricher
	cfg.FieldNames = config.LogEnricherFieldNames{TraceID: "trace.id", SpanID: "span.id"}
	formatter := newLogFormatter(cfg)

	jsonLog, err := formatter.format(
		[]byte(`{"message":"request failed","trace.id":"sdk-trace"}`),
		testTraceID,
		testSpanID,
		true,
	)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(jsonLog, &fields))
	require.Equal(t, "sdk-trace", fields["trace.id"])
	require.Equal(t, testSpanID, fields["span.id"])
	assert.NotContains(t, fields, "trace_id")
	assert.NotContains(t, fields, "span_id")

	plainText, err := formatter.format([]byte("request trace.id=sdk-trace\n"), testTraceID, testSpanID, true)
	require.NoError(t, err)
	require.Equal(t, "request trace.id=sdk-trace span.id="+testSpanID+"\n", string(plainText))
}

func TestLogFormatterMixedJSONAndPlainText(t *testing.T) {
	t.Parallel()

	formatter := newLogFormatter(obi.DefaultConfig.EBPF.LogEnricher)

	jsonLog, err := formatter.format([]byte(`{"message":"first"}`), testTraceID, testSpanID, true)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(jsonLog, &fields))
	require.Equal(t, testTraceID, fields["trace_id"])

	plainText, err := formatter.format([]byte("second\n"), testTraceID, testSpanID, true)
	require.NoError(t, err)
	require.Equal(t, "second "+testContextFields+"\n", string(plainText))
}

func TestLogFormatterEnrichesNDJSON(t *testing.T) {
	t.Parallel()

	formatter := newLogFormatter(obi.DefaultConfig.EBPF.LogEnricher)
	got, err := formatter.format(
		[]byte("{\"message\":\"first\"}\r\n{\"message\":\"second\"}\r\n"),
		testTraceID,
		testSpanID,
		true,
	)
	require.NoError(t, err)

	lines := bytes.Split(got, []byte("\r\n"))
	require.Len(t, lines, 3)
	require.Empty(t, lines[2])

	for _, line := range lines[:2] {
		var fields map[string]any
		require.NoError(t, json.Unmarshal(line, &fields))
		require.Equal(t, testTraceID, fields["trace_id"])
		require.Equal(t, testSpanID, fields["span_id"])
	}
}

func TestLogFormatterPreservesNDJSONNonObjectRecords(t *testing.T) {
	t.Parallel()

	formatter := newLogFormatter(obi.DefaultConfig.EBPF.LogEnricher)
	got, err := formatter.format(
		[]byte("{\"message\":\"first\"}\n42\n"),
		testTraceID,
		testSpanID,
		true,
	)
	require.NoError(t, err)

	lines := bytes.Split(got, []byte("\n"))
	require.Len(t, lines, 3)
	require.Equal(t, []byte("42"), lines[1])

	var fields map[string]any
	require.NoError(t, json.Unmarshal(lines[0], &fields))
	require.Equal(t, testTraceID, fields["trace_id"])
	require.Equal(t, testSpanID, fields["span_id"])
}

func TestLogFormatterPreservesNonObjectJSON(t *testing.T) {
	t.Parallel()

	formatter := newLogFormatter(obi.DefaultConfig.EBPF.LogEnricher)
	for _, input := range []string{
		`[{"message":"request failed"}]` + "\n",
		`"request failed"` + "\n",
		"42\n",
		"1e1000\n",
		"true\n",
		"null\n",
		`{"number":1e1000}` + "\n",
	} {
		got, err := formatter.format([]byte(input), testTraceID, testSpanID, true)
		require.NoError(t, err)
		require.Equal(t, input, string(got))
	}
}

func TestLogFormatterWhitespaceOnlyLineIsNonempty(t *testing.T) {
	t.Parallel()

	formatter := newLogFormatter(obi.DefaultConfig.EBPF.LogEnricher)
	got := formatter.formatPlainText([]byte(" \nmessage\n"), testTraceID, testSpanID, true)
	require.Equal(t, "  "+testContextFields+"\nmessage\n", string(got))
}

var (
	benchmarkFormattedLog []byte
	benchmarkFormatErr    error
)

func BenchmarkPlainTextFormatter8KiBSingleLine(b *testing.B) {
	formatter := newLogFormatter(obi.DefaultConfig.EBPF.LogEnricher)
	input := bytes.Repeat([]byte{'x'}, 8*1024)
	b.ReportAllocs()

	for b.Loop() {
		benchmarkFormattedLog, benchmarkFormatErr = formatter.format(input, testTraceID, testSpanID, true)
	}
	if benchmarkFormatErr != nil {
		b.Fatal(benchmarkFormatErr)
	}
}

func BenchmarkPlainTextFormatter8KiBManyLines(b *testing.B) {
	cfg := obi.DefaultConfig.EBPF.LogEnricher
	cfg.PlainText.Multiline = config.LogEnricherMultilineEachLine
	formatter := newLogFormatter(cfg)
	input := bytes.Repeat([]byte("x\n"), 4*1024)
	b.ReportAllocs()

	for b.Loop() {
		benchmarkFormattedLog, benchmarkFormatErr = formatter.format(input, testTraceID, testSpanID, true)
	}
	if benchmarkFormatErr != nil {
		b.Fatal(benchmarkFormatErr)
	}
}
