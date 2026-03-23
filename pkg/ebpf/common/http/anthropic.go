// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func AnthropicSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {

	fmt.Printf("==== REQUEST ====\n")
	for k, v := range req.Header {
		fmt.Printf("%s: %s\n", k, v)
	}

	reqB1, err := io.ReadAll(req.Body)
	if err != nil {
		return *baseSpan, false
	}
	a := io.NopCloser(bytes.NewBuffer(reqB1))

	fmt.Printf("%v\n", a)

	fmt.Printf("==== RESPONSE ====\n")
	for k, v := range resp.Header {
		fmt.Printf("%s: %s\n", k, v)
	}

	respB1, err := getResponseBody(resp)
	if err != nil && len(respB1) == 0 {
		return *baseSpan, false
	}

	fmt.Printf("%s\n", string(respB1))

	// Check any of the well known response headers that Anthropic would use
	isAnthropic := false
	for _, header := range []string{
		"Anthropic-Organization-Id",
		"Anthropic-Ratelimit-Input-Tokens-Remaining",
		"Anthropic-Ratelimit-Output-Tokens-Limit",
		"Anthropic-Ratelimit-Input-Tokens-Limit",
		"Anthropic-Ratelimit-Requests-Limit",
	} {
		if val := resp.Header.Get(header); val != "" {
			isAnthropic = true
			break
		}
	}

	if !isAnthropic {
		return *baseSpan, false
	}

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return *baseSpan, false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	respB, err := getResponseBody(resp)
	if err != nil && len(respB) == 0 {
		return *baseSpan, false
	}

	slog.Debug("Anthropic", "request", string(reqB), "response", string(respB))

	var parsedRequest request.AnthropicRequest
	if err := json.Unmarshal(reqB, &parsedRequest); err != nil {
		slog.Debug("failed to parse OpenAI request", "error", err)
	}

	var parsedResponse request.AnthropicResponse
	if err := json.Unmarshal(respB, &parsedResponse); err != nil {
		slog.Debug("failed to parse OpenAI response", "error", err)
	}

	baseSpan.SubType = request.HTTPSubtypeAnthropic
	baseSpan.GenAI.Anthropic = &request.VendorAnthropic{
		Input:  parsedRequest,
		Output: parsedResponse,
	}

	return *baseSpan, true
}
