// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type jsonRPCRequest struct {
	JsonRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id"`
}

type jsonRPCResponse struct {
	JsonRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   *jsonRPCError   `json:"error"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const jsonRPCVersion = "2.0"
const jsonRPCContentType = "application/json-rpc"

func JsonRPCSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req.Method != http.MethodPost {
		return *baseSpan, false
	}

	// Fast path: check Content-Type header
	detected := strings.Contains(req.Header.Get("Content-Type"), jsonRPCContentType)

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return *baseSpan, false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	rpcReq, err := parseJsonRPCRequest(reqB, detected)
	if err != nil {
		return *baseSpan, false
	}

	result := &request.JsonRPC{
		Method:  rpcReq.Method,
		Version: rpcReq.JsonRPC,
	}

	if len(rpcReq.ID) > 0 && string(rpcReq.ID) != "null" {
		result.RequestID = string(rpcReq.ID)
	}

	// Parse response for error information
	if resp != nil && resp.Body != nil {
		respB, err := io.ReadAll(resp.Body)
		if err == nil {
			resp.Body = io.NopCloser(bytes.NewBuffer(respB))
			parseJsonRPCResponse(respB, result)
		}
	}

	baseSpan.SubType = request.HTTPSubtypeJsonRPC
	baseSpan.JsonRPC = result

	return *baseSpan, true
}

// parseJsonRPCRequest tries to parse the body as a JSON-RPC request.
// Returns the first request and any error.
// TODO: for batch requests, emit a span per request instead of only the first.
func parseJsonRPCRequest(data []byte, headerDetected bool) (jsonRPCRequest, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return jsonRPCRequest{}, fmt.Errorf("empty body")
	}

	// Try single request first (most common case)
	if data[0] == '{' {
		var req jsonRPCRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return jsonRPCRequest{}, fmt.Errorf("invalid JSON: %w", err)
		}
		if req.JsonRPC != jsonRPCVersion && !headerDetected {
			return jsonRPCRequest{}, fmt.Errorf("not a JSON-RPC request")
		}
		if req.Method == "" {
			return jsonRPCRequest{}, fmt.Errorf("missing method field")
		}
		return req, nil
	}

	// Try batch request — currently only extracts the first request.
	if data[0] == '[' {
		var batch []jsonRPCRequest
		if err := json.Unmarshal(data, &batch); err != nil {
			return jsonRPCRequest{}, fmt.Errorf("invalid JSON batch: %w", err)
		}
		if len(batch) == 0 {
			return jsonRPCRequest{}, fmt.Errorf("empty batch")
		}
		first := batch[0]
		if first.JsonRPC != jsonRPCVersion && !headerDetected {
			return jsonRPCRequest{}, fmt.Errorf("not a JSON-RPC batch")
		}
		if first.Method == "" {
			return jsonRPCRequest{}, fmt.Errorf("missing method field in batch")
		}
		return first, nil
	}

	return jsonRPCRequest{}, fmt.Errorf("unexpected JSON token")
}

func parseJsonRPCResponse(data []byte, result *request.JsonRPC) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return
	}

	var resp jsonRPCResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return
	}

	if resp.Error != nil {
		result.ErrorCode = resp.Error.Code
		result.ErrorMessage = resp.Error.Message
	}
}
