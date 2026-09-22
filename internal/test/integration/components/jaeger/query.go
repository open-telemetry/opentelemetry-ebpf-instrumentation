// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jaeger // import "go.opentelemetry.io/obi/internal/test/integration/components/jaeger"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

const (
	defaultLookback              = time.Hour
	serviceNameKey               = "service.name"
	legacyRequiredTimeRangeError = "query.start_time_min and query.start_time_max are required"
)

type v3Response struct {
	Result json.RawMessage `json:"result"`
}

// Get queries Jaeger v3 while returning the legacy response shape used by the
// integration-test assertions.
func Get(legacyURL string) (*http.Response, error) {
	v3URL, err := queryV3URL(legacyURL, time.Now())
	if err != nil {
		return nil, err
	}

	resp, err := doGet(v3URL)
	if err != nil {
		return nil, err
	}

	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}

	// Some fixtures still use Jaeger 1.60, whose v3 gateway only accepts
	// snake_case query parameters. Retry those through its legacy API.
	if resp.StatusCode == http.StatusBadRequest && bytes.Contains(body, []byte(legacyRequiredTimeRangeError)) {
		return doGet(legacyURL)
	}
	if resp.StatusCode == http.StatusNotFound {
		return legacyResponse(resp, []byte(`{"data":[]}`)), nil
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}

	legacyBody, err := convertV3Body(body)
	if err != nil {
		return nil, fmt.Errorf("converting Jaeger v3 response: %w", err)
	}
	return legacyResponse(resp, legacyBody), nil
}

func doGet(rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func legacyResponse(resp *http.Response, body []byte) *http.Response {
	resp.StatusCode = http.StatusOK
	resp.Status = fmt.Sprintf("%d %s", http.StatusOK, http.StatusText(http.StatusOK))
	resp.Header.Set("Content-Type", "application/json")
	resp.ContentLength = int64(len(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp
}

func queryV3URL(legacyURL string, now time.Time) (string, error) {
	u, err := url.Parse(legacyURL)
	if err != nil {
		return "", err
	}

	const legacyPath = "/api/traces"
	pathIndex := strings.LastIndex(u.Path, legacyPath)
	if pathIndex < 0 {
		return "", fmt.Errorf("unsupported Jaeger query path %q", u.Path)
	}
	basePath := u.Path[:pathIndex]
	traceID := strings.TrimPrefix(u.Path[pathIndex+len(legacyPath):], "/")
	legacyQuery := u.Query()
	if traceID == "" {
		traceID = legacyQuery.Get("traceID")
	}
	if traceID != "" {
		u.Path = basePath + "/api/v3/traces/" + traceID
		u.RawQuery = ""
		return u.String(), nil
	}

	startTime, endTime, err := legacyTimeRange(legacyQuery, now)
	if err != nil {
		return "", err
	}

	v3Query := url.Values{
		"query.startTimeMin": {startTime.Format(time.RFC3339Nano)},
		"query.startTimeMax": {endTime.Format(time.RFC3339Nano)},
	}
	copyQueryParam(legacyQuery, v3Query, "service", "query.serviceName")
	copyQueryParam(legacyQuery, v3Query, "operation", "query.operationName")
	copyQueryParam(legacyQuery, v3Query, "limit", "query.searchDepth")
	copyQueryParam(legacyQuery, v3Query, "minDuration", "query.durationMin")
	copyQueryParam(legacyQuery, v3Query, "maxDuration", "query.durationMax")
	copyQueryParam(legacyQuery, v3Query, "tags", "query.attributes")

	u.Path = basePath + "/api/v3/traces"
	u.RawQuery = v3Query.Encode()
	return u.String(), nil
}

func copyQueryParam(from, to url.Values, oldName, newName string) {
	if value := from.Get(oldName); value != "" {
		to.Set(newName, value)
	}
}

func legacyTimeRange(query url.Values, now time.Time) (time.Time, time.Time, error) {
	endTime := now.UTC()
	if value := query.Get("end"); value != "" {
		micros, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parsing Jaeger end time: %w", err)
		}
		endTime = time.UnixMicro(micros).UTC()
	}

	if value := query.Get("start"); value != "" {
		micros, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parsing Jaeger start time: %w", err)
		}
		return time.UnixMicro(micros).UTC(), endTime, nil
	}

	lookback := defaultLookback
	if value := query.Get("lookback"); value != "" {
		var err error
		lookback, err = time.ParseDuration(value)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parsing Jaeger lookback: %w", err)
		}
	}
	return endTime.Add(-lookback), endTime, nil
}

func convertV3Body(body []byte) ([]byte, error) {
	var response v3Response
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	if len(response.Result) == 0 {
		return nil, errors.New("missing result")
	}

	traces, err := new(ptrace.JSONUnmarshaler).UnmarshalTraces(response.Result)
	if err != nil {
		return nil, err
	}
	return json.Marshal(toLegacyTraces(traces))
}

func toLegacyTraces(traces ptrace.Traces) TracesQuery {
	byTraceID := map[string]*Trace{}
	var orderedTraces []*Trace
	resources := traces.ResourceSpans()
	for resourceIndex := 0; resourceIndex < resources.Len(); resourceIndex++ {
		resourceSpans := resources.At(resourceIndex)
		processID := fmt.Sprintf("p%d", resourceIndex+1)
		process := toLegacyProcess(resourceSpans.Resource())
		scopes := resourceSpans.ScopeSpans()
		for scopeIndex := 0; scopeIndex < scopes.Len(); scopeIndex++ {
			scopeSpans := scopes.At(scopeIndex)
			spans := scopeSpans.Spans()
			for spanIndex := 0; spanIndex < spans.Len(); spanIndex++ {
				otelSpan := spans.At(spanIndex)
				traceID := otelSpan.TraceID().String()
				trace := byTraceID[traceID]
				if trace == nil {
					trace = &Trace{TraceID: traceID, Processes: map[string]Process{}}
					byTraceID[traceID] = trace
					orderedTraces = append(orderedTraces, trace)
				}
				trace.Processes[processID] = process
				trace.Spans = append(trace.Spans, toLegacySpan(otelSpan, scopeSpans.Scope(), processID))
			}
		}
	}

	query := TracesQuery{Data: make([]Trace, 0, len(orderedTraces))}
	for _, trace := range orderedTraces {
		query.Data = append(query.Data, *trace)
	}
	return query
}

func toLegacyProcess(resource pcommon.Resource) Process {
	process := Process{}
	for key, value := range resource.Attributes().All() {
		if key == serviceNameKey {
			process.ServiceName = value.AsString()
			continue
		}
		process.Tags = append(process.Tags, toLegacyTag(key, value))
	}
	return process
}

func toLegacySpan(span ptrace.Span, scope pcommon.InstrumentationScope, processID string) Span {
	legacySpan := Span{
		TraceID:       span.TraceID().String(),
		SpanID:        span.SpanID().String(),
		OperationName: span.Name(),
		StartTime:     int64(span.StartTimestamp()) / int64(time.Microsecond),
		Duration:      int64(span.EndTimestamp()-span.StartTimestamp()) / int64(time.Microsecond),
		ProcessID:     processID,
	}
	if parentID := span.ParentSpanID(); !parentID.IsEmpty() {
		legacySpan.References = append(legacySpan.References, Reference{
			RefType: "CHILD_OF",
			TraceID: legacySpan.TraceID,
			SpanID:  parentID.String(),
		})
	}
	for linkIndex := 0; linkIndex < span.Links().Len(); linkIndex++ {
		link := span.Links().At(linkIndex)
		legacySpan.References = append(legacySpan.References, Reference{
			RefType: "FOLLOWS_FROM",
			TraceID: link.TraceID().String(),
			SpanID:  link.SpanID().String(),
		})
	}
	if scope.Name() != "" {
		legacySpan.Tags = append(legacySpan.Tags, Tag{Key: "otel.scope.name", Type: "string", Value: scope.Name()})
	}
	if scope.Version() != "" {
		legacySpan.Tags = append(legacySpan.Tags, Tag{Key: "otel.scope.version", Type: "string", Value: scope.Version()})
	}
	for key, value := range span.Attributes().All() {
		legacySpan.Tags = append(legacySpan.Tags, toLegacyTag(key, value))
	}
	if kind := spanKind(span.Kind()); kind != "" {
		legacySpan.Tags = append(legacySpan.Tags, Tag{Key: "span.kind", Type: "string", Value: kind})
	}
	legacySpan.Tags = append(legacySpan.Tags, statusTags(span.Status())...)
	legacySpan.Logs = toLegacyLogs(span.Events())
	return legacySpan
}

func spanKind(kind ptrace.SpanKind) string {
	switch kind {
	case ptrace.SpanKindInternal:
		return "internal"
	case ptrace.SpanKindServer:
		return "server"
	case ptrace.SpanKindClient:
		return "client"
	case ptrace.SpanKindProducer:
		return "producer"
	case ptrace.SpanKindConsumer:
		return "consumer"
	default:
		return ""
	}
}

func statusTags(status ptrace.Status) []Tag {
	var tags []Tag
	switch status.Code() {
	case ptrace.StatusCodeError:
		tags = append(tags,
			Tag{Key: "otel.status_code", Type: "string", Value: "ERROR"},
			Tag{Key: "error", Type: "bool", Value: true},
		)
	case ptrace.StatusCodeOk:
		tags = append(tags, Tag{Key: "otel.status_code", Type: "string", Value: "OK"})
	}
	if status.Message() != "" {
		tags = append(tags, Tag{Key: "otel.status_description", Type: "string", Value: status.Message()})
	}
	return tags
}

func toLegacyLogs(events ptrace.SpanEventSlice) []Log {
	logs := make([]Log, 0, events.Len())
	for eventIndex := 0; eventIndex < events.Len(); eventIndex++ {
		event := events.At(eventIndex)
		log := Log{Timestamp: int64(event.Timestamp()) / int64(time.Microsecond)}
		if _, exists := event.Attributes().Get("event"); event.Name() != "" && !exists {
			log.Fields = append(log.Fields, Tag{Key: "event", Type: "string", Value: event.Name()})
		}
		for key, value := range event.Attributes().All() {
			log.Fields = append(log.Fields, toLegacyTag(key, value))
		}
		logs = append(logs, log)
	}
	return logs
}

func toLegacyTag(key string, value pcommon.Value) Tag {
	tag := Tag{Key: key}
	switch value.Type() {
	case pcommon.ValueTypeBool:
		tag.Type, tag.Value = "bool", value.Bool()
	case pcommon.ValueTypeInt:
		tag.Type, tag.Value = "int64", value.Int()
	case pcommon.ValueTypeDouble:
		tag.Type, tag.Value = "float64", value.Double()
	case pcommon.ValueTypeBytes:
		tag.Type, tag.Value = "binary", value.AsString()
	default:
		tag.Type, tag.Value = "string", value.AsString()
	}
	return tag
}
