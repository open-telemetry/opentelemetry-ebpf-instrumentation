// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/internal/test/weavercheck"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/metadata"
)

const liveCheckTimeout = 3 * time.Minute

var defaultSpanOptional = []attr.Name{
	attr.NetworkPeerAddress,
	attr.NetworkPeerPort,
	attr.NetworkProtocolVersion,
	attr.ErrorType,
}

// matchOnlySpanCases complete emittedSpanCases so that every span definition
// has a span to match: live-check pairs them by matcher, which this test
// checks, while the exact attribute set of these is not pinned.
func matchOnlySpanCases() []emittedSpanCase {
	return []emittedSpanCase{
		{
			// A REPLY OBI could not pair with its CALL names no procedure.
			name:     "onc rpc reply without its call",
			spanType: "obi.rpc.onc_rpc.client",
			span: &request.Span{
				Type:     request.EventTypeSunRPCClient,
				Method:   request.SunRPCSyntheticReplyMethod,
				Path:     "sunrpc",
				Host:     "10.0.0.1",
				HostPort: 2049,
			},
		},
		{
			// An IPv6 address joined with a port is bracketed, as in a URL.
			name:     "elasticsearch client over ipv6",
			spanType: "obi.elasticsearch.client",
			span: &request.Span{
				Type:         request.EventTypeHTTPClient,
				SubType:      request.HTTPSubtypeElasticsearch,
				Method:       "POST",
				Path:         "/_bulk",
				Host:         "2001:db8::1",
				HostPort:     9200,
				Status:       200,
				ProtoVersion: request.ProtoVersionHTTP11,
				Elasticsearch: &request.Elasticsearch{
					DBSystemName:    "elasticsearch",
					DBOperationName: "bulk",
				},
			},
		},
		{
			name:     "elasticsearch client without a port",
			spanType: "obi.elasticsearch.client",
			span: &request.Span{
				Type:         request.EventTypeHTTPClient,
				SubType:      request.HTTPSubtypeElasticsearch,
				Method:       "POST",
				Path:         "/_bulk",
				Host:         "10.0.0.1",
				HostName:     "es-1",
				Status:       200,
				ProtoVersion: request.ProtoVersionHTTP11,
				Elasticsearch: &request.Elasticsearch{
					DBSystemName:    "elasticsearch",
					DBOperationName: "bulk",
				},
			},
		},
		{
			name:     "aws sns publish",
			spanType: "obi.aws.sns.client",
			span: &request.Span{
				Type:         request.EventTypeHTTPClient,
				SubType:      request.HTTPSubtypeAWSSNS,
				Host:         "10.0.0.1",
				HostPort:     443,
				Status:       200,
				ProtoVersion: request.ProtoVersionHTTP11,
				AWS: &request.AWS{SNS: request.AWSSNS{
					Meta:          request.AWSMeta{RequestID: "req-3", Region: "us-east-1"},
					OperationName: "Publish",
					OperationType: "send",
					Destination:   "my-topic",
					TopicARN:      "arn:aws:sns:us-east-1:1:my-topic",
					MessageID:     "msg-2",
				}},
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "redis client",
			spanType: "obi.db.client",
			span: &request.Span{
				Type:     request.EventTypeRedisClient,
				Method:   "GET",
				Path:     "GET my-key",
				Host:     "10.0.0.1",
				HostPort: 6379,
				Peer:     "10.0.0.2",
				PeerPort: 54321,
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "redis server",
			spanType: "obi.db.server",
			span: &request.Span{
				Type:     request.EventTypeRedisServer,
				Method:   "SET",
				Host:     "10.0.0.1",
				HostPort: 6379,
				Peer:     "10.0.0.2",
				PeerPort: 54321,
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "dns",
			spanType: "obi.dns",
			span: &request.Span{
				Type:      request.EventTypeDNS,
				Method:    "A",
				Path:      "example.com",
				Statement: "93.184.216.34",
				Host:      "10.0.0.2",
				HostPort:  53,
				Peer:      "10.0.0.53",
			},
			optional: append([]attr.Name{attr.DNSQuestionName}, defaultSpanOptional...),
		},
		{
			name:     "failed connect",
			spanType: "obi.failed_connect",
			span: &request.Span{
				Type:     request.EventTypeFailedConnect,
				Host:     "10.0.0.1",
				HostPort: 8080,
				Peer:     "10.0.0.2",
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "failed connect without a peer address",
			spanType: "obi.failed_connect",
			span: &request.Span{
				Type:     request.EventTypeFailedConnect,
				Host:     "10.0.0.1",
				HostPort: 8080,
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "gen_ai inference client",
			spanType: "obi.gen_ai.inference.client",
			span: &request.Span{
				Type:     request.EventTypeHTTPClient,
				SubType:  request.HTTPSubtypeOpenAI,
				Host:     "10.0.0.1",
				HostPort: 443,
				Status:   200,
				GenAI: &request.GenAI{OpenAI: &request.VendorOpenAI{
					OperationName: "chat.completion",
					ResponseModel: "gpt-4o-2024-08-06",
					ID:            "chatcmpl-1",
					Request:       request.OpenAIInput{Model: "gpt-4o"},
				}},
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "gen_ai embeddings client",
			spanType: "obi.gen_ai.embeddings.client",
			span: &request.Span{
				Type:     request.EventTypeHTTPClient,
				SubType:  request.HTTPSubtypeEmbedding,
				Host:     "10.0.0.1",
				HostPort: 443,
				Status:   200,
				GenAI: &request.GenAI{Embedding: &request.VendorEmbedding{
					Provider: "voyage",
					Model:    "voyage-3",
					Input:    request.EmbeddingRequest{Model: "voyage-3"},
				}},
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "gen_ai retrieval client",
			spanType: "obi.gen_ai.retrieval.client",
			span: &request.Span{
				Type:     request.EventTypeHTTPClient,
				SubType:  request.HTTPSubtypeRetrieval,
				Host:     "10.0.0.1",
				HostPort: 443,
				Status:   200,
				GenAI: &request.GenAI{Retrieval: &request.VendorRetrieval{
					Provider: "pinecone",
					Input:    request.RetrievalRequest{Namespace: "docs", TopK: 5},
				}},
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "gen_ai rerank client",
			spanType: "obi.gen_ai.rerank.client",
			span: &request.Span{
				Type:     request.EventTypeHTTPClient,
				SubType:  request.HTTPSubtypeRerank,
				Host:     "10.0.0.1",
				HostPort: 443,
				Status:   200,
				GenAI: &request.GenAI{Rerank: &request.VendorRerank{
					Provider: "cohere",
					Input:    request.RerankRequest{Model: "rerank-v3.5", TopN: 3},
				}},
			},
			optional: defaultSpanOptional,
		},
		{
			name:     "mcp client",
			spanType: "obi.mcp.client",
			span: &request.Span{
				Type:     request.EventTypeHTTPClient,
				SubType:  request.HTTPSubtypeMCP,
				Host:     "10.0.0.1",
				HostPort: 8000,
				Status:   200,
				GenAI: &request.GenAI{MCP: &request.MCPCall{
					Method:      request.MCPMethodToolsCall,
					ToolName:    "search",
					SessionID:   "s-1",
					ProtocolVer: "2025-06-18",
					RequestID:   "1",
				}},
			},
			optional: defaultSpanOptional,
		},
	}
}

type liveCheckAttribute struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

type liveCheckSpan struct {
	Name       string               `json:"name"`
	Kind       string               `json:"kind"`
	Attributes []liveCheckAttribute `json:"attributes"`
}

type liveCheckSample struct {
	Span liveCheckSpan `json:"span"`
}

// exportedSpan renders a span through the trace exporter and returns it as a
// live-check sample: the name, kind and attributes OTLP carries.
func exportedSpan(t *testing.T, span *request.Span, optional []attr.Name) liveCheckSample {
	t.Helper()

	selected := make(map[attr.Name]struct{}, len(optional))
	for _, name := range optional {
		selected[name] = struct{}{}
	}

	cache := expirable.NewLRU[svc.UID, []attribute.KeyValue](1, nil, time.Minute)
	traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, nil, &metadata.NodeMeta{},
		[]tracesgen.TraceSpanAndAttributes{{Span: span, Attributes: tracesgen.TraceAttributesSelector(span, selected)}},
		"obi")
	require.Equal(t, 1, traces.SpanCount(), "the exporter should produce exactly one span")

	return liveCheckSampleOf(traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0))
}

// exportedRequestPhases renders a server span whose request waited before it
// was processed and returns the "in queue" and "processing" children the
// exporter adds under it.
func exportedRequestPhases(t *testing.T) []liveCheckSample {
	t.Helper()

	start := time.Now()
	span := &request.Span{
		Type:         request.EventTypeHTTP,
		Method:       "GET",
		Path:         "/users",
		Host:         "10.0.0.1",
		HostPort:     8080,
		Status:       200,
		RequestStart: start.UnixNano(),
		Start:        start.Add(time.Millisecond).UnixNano(),
		End:          start.Add(2 * time.Millisecond).UnixNano(),
	}

	cache := expirable.NewLRU[svc.UID, []attribute.KeyValue](1, nil, time.Minute)
	traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, nil, &metadata.NodeMeta{},
		[]tracesgen.TraceSpanAndAttributes{{Span: span, Attributes: tracesgen.TraceAttributesSelector(span, nil)}},
		"obi")

	spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	var phases []liveCheckSample
	for i := range spans.Len() {
		if s := spans.At(i); s.Kind() == ptrace.SpanKindInternal {
			phases = append(phases, liveCheckSampleOf(s))
		}
	}
	require.Len(t, phases, 2, "the exporter should add an in-queue and a processing span")
	return phases
}

func liveCheckSampleOf(exported ptrace.Span) liveCheckSample {
	sample := liveCheckSpan{
		Name:       exported.Name(),
		Kind:       strings.ToLower(exported.Kind().String()),
		Attributes: []liveCheckAttribute{},
	}
	for key, value := range exported.Attributes().All() {
		sample.Attributes = append(sample.Attributes, liveCheckAttribute{Name: key, Value: value.AsRaw()})
	}
	return liveCheckSample{Span: sample}
}

type liveCheckFinding struct {
	ID      string `json:"id"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type liveCheckResult struct {
	AllAdvice []liveCheckFinding `json:"all_advice"`
	MatchInfo *struct {
		Signal  string `json:"signal"`
		Entries []struct {
			Matcher string `json:"matcher"`
			Ignored bool   `json:"ignored"`
		} `json:"entries"`
	} `json:"match_info"`
}

type liveCheckReport struct {
	Samples []struct {
		Span *struct {
			Name             string          `json:"name"`
			LiveCheckResult  liveCheckResult `json:"live_check_result"`
			AttributeResults []struct {
				Name            string          `json:"name"`
				LiveCheckResult liveCheckResult `json:"live_check_result"`
			} `json:"attributes"`
		} `json:"span"`
	} `json:"samples"`
}

// liveCheck feeds the samples to `weaver registry live-check`, configured by
// schemas/obi/.weaver.toml, and returns its JSON report.
func liveCheck(t *testing.T, samples []liveCheckSample) liveCheckReport {
	t.Helper()
	ociBin := requireWeaverRuntime(t)

	input, err := json.Marshal(samples)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), liveCheckTimeout)
	defer cancel()

	cmd := weaverCommand(ctx, t, ociBin,
		"registry", "live-check", "--registry", "/obi-registry",
		"--input-source", "stdin", "--input-format", "json",
		"--format", "json", "--no-stream")
	cmd.Stdin = bytes.NewReader(input)

	// live-check exits non-zero when it reports a violation, which the
	// assertions below surface in detail; only a missing report is fatal here.
	out, runErr := cmd.Output()
	var report liveCheckReport
	if jsonErr := json.Unmarshal(out, &report); jsonErr != nil {
		var stderr []byte
		if exitErr, ok := errors.AsType[*exec.ExitError](runErr); ok {
			stderr = exitErr.Stderr
		}
		require.NoErrorf(t, jsonErr, "weaver live-check produced no parseable report (run error: %v)\n%s", runErr, stderr)
	}
	return report
}

// Live-check pairs a span with its span definition only through the matchers
// in schemas/obi/.weaver.toml. Every span the exporter builds must be paired by
// exactly one matcher with the definition that describes it, with the kind that
// definition declares and a name its templates render, and must raise no
// violation.
func TestEmittedSpansMatchTheirDeclaredSpan(t *testing.T) {
	cases := append(emittedSpanCases(), matchOnlySpanCases()...)

	samples := make([]liveCheckSample, 0, len(cases))
	spanTypes := make([]string, 0, len(cases))
	names := make([]string, 0, len(cases))
	for _, tc := range cases {
		samples = append(samples, exportedSpan(t, tc.span, tc.optional))
		spanTypes = append(spanTypes, tc.spanType)
		names = append(names, tc.name)
	}
	for _, phase := range exportedRequestPhases(t) {
		samples = append(samples, phase)
		spanTypes = append(spanTypes, "obi.request.phase")
		names = append(names, "request phase "+phase.Span.Name)
	}

	report := liveCheck(t, samples)
	require.Len(t, report.Samples, len(samples), "live-check should report one sample per span")

	covered := map[string]struct{}{}
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			span := report.Samples[i].Span
			require.NotNil(t, span, "sample %d is not a span", i)
			result := span.LiveCheckResult
			require.NotNil(t, result.MatchInfo, "span %q has no match info", span.Name)

			assert.Equalf(t, spanTypes[i], result.MatchInfo.Signal,
				"span %q was compared with %q", span.Name, result.MatchInfo.Signal)
			assert.Lenf(t, result.MatchInfo.Entries, 1,
				"span %q should be selected by exactly one matcher, got %+v", span.Name, result.MatchInfo.Entries)

			findings := result.AllAdvice
			for _, a := range span.AttributeResults {
				findings = append(findings, a.LiveCheckResult.AllAdvice...)
			}
			for _, f := range findings {
				assert.NotContainsf(t, []string{"kind_mismatch", "span_name_mismatch"}, f.ID,
					"span %q: %s", span.Name, f.Message)
				assert.NotEqualf(t, "violation", f.Level, "span %q: [%s] %s", span.Name, f.ID, f.Message)
			}
			covered[spanTypes[i]] = struct{}{}
		})
	}

	for _, f := range registryFiles(t) {
		for _, s := range f.Spans {
			assert.Containsf(t, covered, s.Type, "no span case covers span definition %q", s.Type)
		}
	}
}

// compactReport runs live-check over the samples with the compact report
// template the integration suites read, and parses it as weavercheck does.
func compactReport(t *testing.T, samples []any) *weavercheck.Report {
	t.Helper()
	ociBin := requireWeaverRuntime(t)

	input, err := json.Marshal(samples)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), liveCheckTimeout)
	defer cancel()

	cmd := weaverCommand(ctx, t, ociBin,
		"registry", "live-check", "--registry", "/obi-registry",
		"--input-source", "stdin", "--input-format", "json",
		"--format", "compact", "--templates", "/obi-registry/.live_check_templates", "--no-stream")
	cmd.Stdin = bytes.NewReader(input)
	// live-check exits non-zero when it reports a violation.
	out, _ := cmd.Output()

	report, err := weavercheck.Parse(out)
	require.NoError(t, err, "compact report: %s", out)
	// Validate fails when the template sees fewer violations than weaver
	// counted; against a real report the two must agree.
	assert.Equal(t, report.Statistics.AdviceLevelCounts["violation"], report.ViolationsSeen,
		"violations the template saw")
	return report
}

// unexpectedKeys returns the attribute keys of the unexpected_attribute
// findings left in the report, for the given signal type.
func unexpectedKeys(report *weavercheck.Report, signalType string) []string {
	var keys []string
	for _, f := range report.Findings {
		if f.Type != "unexpected_attribute" {
			continue
		}
		for _, signal := range f.Signals {
			if strings.HasPrefix(signal, signalType+":") {
				if _, after, ok := strings.Cut(f.Message, "'"); ok {
					key, _, _ := strings.Cut(after, "'")
					keys = append(keys, key)
				}
				break
			}
		}
	}
	return keys
}

// An OBI-built span no definition describes is reported as unmatched, which
// weavercheck fails on; an application-authored span is not.
func TestCompactReportListsUndeclaredSpans(t *testing.T) {
	report := compactReport(t, []any{
		liveCheckSample{Span: liveCheckSpan{Name: "undeclared", Kind: "internal", Attributes: []liveCheckAttribute{
			{Name: "server.port", Value: 8080},
		}}},
		liveCheckSample{Span: liveCheckSpan{Name: "app span", Kind: "internal", Attributes: []liveCheckAttribute{
			{Name: "obitest.user", Value: "u"},
		}}},
	})
	require.Len(t, report.Unmatched, 1, "unmatched groups: %+v", report.Unmatched)
	assert.Equal(t, []string{"undeclared"}, report.Unmatched[0].Names)
}

// The compact template drops two kinds of unexpected_attribute: the resource
// attributes OBI copies onto metric data points, and exception.message on an
// application span OBI relays. Both still fail anywhere else.
func TestCompactReportUnexpectedAttributeExceptions(t *testing.T) {
	dns := func(extra liveCheckAttribute) liveCheckSample {
		return liveCheckSample{Span: liveCheckSpan{Name: "A example.com", Kind: "internal", Attributes: []liveCheckAttribute{
			{Name: "dns.question.name", Value: "example.com"},
			{Name: "server.port", Value: 53},
			extra,
		}}}
	}
	metric := map[string]any{"metric": map[string]any{
		"name": "http.server.request.duration", "instrument": "histogram", "unit": "s",
		"data_points": []map[string]any{{
			"attributes": []liveCheckAttribute{
				{Name: "http.request.method", Value: "GET"},
				{Name: "service.name", Value: "svc"},
				{Name: "network.protocol.name", Value: "http"},
			},
			"count": 1, "sum": 0.1, "bucket_counts": []int{1}, "explicit_bounds": []float64{},
		}},
	}}

	report := compactReport(t, []any{
		dns(liveCheckAttribute{Name: "service.name", Value: "svc"}),
		dns(liveCheckAttribute{Name: "exception.message", Value: "boom"}),
		liveCheckSample{Span: liveCheckSpan{Name: "app span", Kind: "internal", Attributes: []liveCheckAttribute{
			{Name: "exception.message", Value: "boom"},
		}}},
		metric,
	})

	assert.ElementsMatch(t, []string{"service.name", "exception.message"}, unexpectedKeys(report, "span"),
		"service.name and exception.message on an OBI span still fail")
	assert.Equal(t, []string{"network.protocol.name"}, unexpectedKeys(report, "metric"),
		"service.name on a metric data point is dropped")

	for _, f := range report.Findings {
		if f.Type == "unexpected_attribute" && strings.Contains(f.Message, "'exception.message'") {
			assert.Equal(t, 1, f.Count, "exception.message on the application span is dropped: %+v", f)
		}
	}
}
