// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

var jsonBestEffort = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	// modelSearchWindow limits extraction for top-level request model
	// fields to the start of the request payload.
	modelSearchWindow = 200
	// responseHeaderSearchWindow limits extraction for top-level response
	// fields (id, model, object) to the start of the response payload.
	responseHeaderSearchWindow = 800
)

// extractJSONStringField returns the string value for a top-level JSON field.
// window limits the search range; 0 searches the full body.
func extractJSONStringField(body []byte, field string, window int) string {
	if len(body) == 0 {
		return ""
	}
	search := body
	if window > 0 && len(search) > window {
		search = search[:window]
	}

	dec := json.NewDecoder(bytes.NewReader(search))
	root, err := dec.Token()
	if err != nil || root != json.Delim('{') {
		return ""
	}

	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return ""
		}
		key, ok := keyToken.(string)
		if !ok {
			return ""
		}

		if key != field {
			if err := skipJSONValue(dec); err != nil {
				return ""
			}
			continue
		}

		value, err := dec.Token()
		if err != nil {
			return ""
		}
		if value, ok := value.(string); ok {
			return strings.TrimSpace(value)
		}
		return ""
	}

	return ""
}

func skipJSONValue(dec *json.Decoder) error {
	value, err := dec.Token()
	if err != nil {
		return err
	}

	delim, ok := value.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		for dec.More() {
			if _, err := dec.Token(); err != nil {
				return err
			}
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
	default:
		return nil
	}

	_, err = dec.Token()
	return err
}

// extractModelField searches the top-level model field in the captured body.
// Used only when jsoniter could not reach model before truncation.
func extractModelField(body []byte) string {
	return extractJSONStringField(body, "model", 0)
}

// unmarshalJSONBestEffort unmarshals body into v using json-iterator, which
// populates fields seen before truncation even when the JSON is incomplete.
func unmarshalJSONBestEffort(body []byte, v any) {
	if len(body) == 0 {
		return
	}
	_ = jsonBestEffort.Unmarshal(body, v)
}

func readHTTPRequestBody(component string, req *http.Request, baseSpan *request.Span, emptyLogAttrs ...any) ([]byte, bool) {
	if req == nil || req.Body == nil {
		return nil, true
	}
	body, err := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	if err == nil {
		return body, true
	}
	if len(body) == 0 {
		if len(emptyLogAttrs) > 0 {
			slog.Debug(component+": request body is empty", emptyLogAttrs...)
		}
		return nil, false
	}
	logTruncatedRequestBody(component, err, len(body), req, baseSpan)
	return body, true
}

func readHTTPResponseBody(component string, resp *http.Response, baseSpan *request.Span, emptyLogAttrs ...any) ([]byte, bool) {
	body, err := getResponseBody(resp)
	if err == nil {
		return body, true
	}
	if len(body) == 0 {
		if len(emptyLogAttrs) > 0 {
			slog.Debug(component+": response body is empty", emptyLogAttrs...)
		}
		return nil, false
	}
	logTruncatedResponseBody(component, err, len(body), resp, baseSpan)
	return body, true
}

// readHTTPRequestBodyLenient reads the request body without aborting when the
// read fails with no bytes — used when classification already succeeded.
func readHTTPRequestBodyLenient(component string, req *http.Request, baseSpan *request.Span, logAttrs ...any) []byte {
	if req == nil || req.Body == nil {
		return nil
	}
	body, err := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	if err == nil {
		return body
	}
	if len(body) == 0 {
		logAttrs = append(logAttrs, "error", err)
		slog.Debug(component+": failed to read request body, continuing without it", logAttrs...)
		return nil
	}
	logTruncatedRequestBody(component, err, len(body), req, baseSpan)
	return body
}

// readHTTPResponseBodyLenient reads the response body without aborting when
// the read fails with no bytes.
func readHTTPResponseBodyLenient(component string, resp *http.Response, baseSpan *request.Span, logAttrs ...any) []byte {
	body, err := getResponseBody(resp)
	if err == nil {
		return body
	}
	if len(body) == 0 {
		logAttrs = append(logAttrs, "error", err)
		slog.Debug(component+": failed to read response body, continuing without it", logAttrs...)
		return nil
	}
	logTruncatedResponseBody(component, err, len(body), resp, baseSpan)
	return body
}

func logTruncatedRequestBody(component string, err error, got int, req *http.Request, baseSpan *request.Span) {
	slog.Debug(component+": truncated request body, continuing with partial data",
		"error", err,
		"bytes", got,
		"contentLength", req.ContentLength,
		"spanContentLength", baseSpan.ContentLength,
	)
}

func logTruncatedResponseBody(component string, err error, got int, resp *http.Response, baseSpan *request.Span) {
	slog.Debug(component+": truncated response body, continuing with partial data",
		"error", err,
		"bytes", got,
		"contentLength", resp.ContentLength,
		"spanResponseLength", baseSpan.ResponseLength,
	)
}

// extractJSONRawField extracts a top-level JSON array or object value for
// the given field name using bracket matching. This is a fallback for when
// json.Unmarshal fails on truncated JSON but the target field's value is
// complete within the captured bytes.
//
// The scan is depth-aware: the key is only matched when we are at the
// top-level object (depth == 1) and not currently inside a JSON string,
// which avoids false positives from occurrences nested in strings or
// inner objects.
func extractJSONRawField(body []byte, field string) json.RawMessage {
	keyBytes := []byte(`"` + field + `"`)

	depth := 0
	inString := false
	escaped := false

	for i := 0; i < len(body); i++ {
		ch := body[i]
		if escaped {
			escaped = false
			continue
		}
		if inString {
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}

		if ch == '"' {
			if depth == 1 && i+len(keyBytes) <= len(body) && bytes.Equal(body[i:i+len(keyBytes)], keyBytes) {
				return extractJSONRawValue(body, i+len(keyBytes))
			}
			inString = true
			continue
		}

		switch ch {
		case '{', '[':
			depth++
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}

	return nil
}

// extractJSONRawValue extracts the JSON object or array value starting after
// the position of a matched key. It skips whitespace and the colon
// separator, then uses bracket matching (with string/escape awareness) to
// find the matching closing bracket. Returns nil for scalar values or when
// the value is truncated.
func extractJSONRawValue(body []byte, start int) json.RawMessage {
	pos := start
	for pos < len(body) && (body[pos] == ' ' || body[pos] == '\t' || body[pos] == '\n' || body[pos] == '\r' || body[pos] == ':') {
		pos++
	}
	if pos >= len(body) {
		return nil
	}

	open := body[pos]
	var closeBracket byte
	switch open {
	case '[':
		closeBracket = ']'
	case '{':
		closeBracket = '}'
	default:
		return nil
	}

	depth := 0
	inString := false
	escaped := false
	for j := pos; j < len(body); j++ {
		ch := body[j]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch ch {
		case open:
			depth++
		case closeBracket:
			depth--
			if depth == 0 {
				return json.RawMessage(body[pos : j+1])
			}
		}
	}

	return nil
}

func parseOpenAIInput(body []byte) request.OpenAIInput {
	var parsed request.OpenAIInput
	unmarshalJSONBestEffort(body, &parsed)
	if parsed.Model == "" {
		parsed.Model = extractModelField(body)
	}
	return parsed
}

func parseVendorOpenAI(body []byte) request.VendorOpenAI {
	var parsed request.VendorOpenAI
	unmarshalJSONBestEffort(body, &parsed)
	if parsed.ID == "" {
		parsed.ID = extractJSONStringField(body, "id", responseHeaderSearchWindow)
	}
	if parsed.ResponseModel == "" {
		parsed.ResponseModel = extractJSONStringField(body, "model", responseHeaderSearchWindow)
	}
	if parsed.OperationName == "" {
		parsed.OperationName = extractJSONStringField(body, "object", responseHeaderSearchWindow)
	}
	return parsed
}

func parseAnthropicRequest(body []byte) request.AnthropicRequest {
	var parsed request.AnthropicRequest
	unmarshalJSONBestEffort(body, &parsed)
	if parsed.Model == "" {
		parsed.Model = extractModelField(body)
	}
	return parsed
}

func parseAnthropicResponse(body []byte) request.AnthropicResponse {
	var parsed request.AnthropicResponse
	unmarshalJSONBestEffort(body, &parsed)
	if parsed.ID == "" {
		parsed.ID = extractJSONStringField(body, "id", responseHeaderSearchWindow)
	}
	if parsed.Model == "" {
		parsed.Model = extractJSONStringField(body, "model", responseHeaderSearchWindow)
	}
	if parsed.Type == "" {
		parsed.Type = extractJSONStringField(body, "type", responseHeaderSearchWindow)
	}
	return parsed
}

func parseEmbeddingRequest(body []byte) request.EmbeddingRequest {
	var parsed request.EmbeddingRequest
	unmarshalJSONBestEffort(body, &parsed)
	if parsed.Model == "" {
		parsed.Model = extractModelField(body)
	}
	return parsed
}

// unmarshalJSON is a thin wrapper for callers that only need a success flag.
func unmarshalJSON(body []byte, v any) bool {
	if len(body) == 0 {
		return false
	}
	return jsonBestEffort.Unmarshal(body, v) == nil
}
