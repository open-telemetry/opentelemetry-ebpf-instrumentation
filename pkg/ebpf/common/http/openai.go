// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func OpenAISpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if req.Method != http.MethodPost {
		return *baseSpan, false
	}

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return *baseSpan, false
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	fmt.Printf("REQUEST\n")
	// Print response headers
	for key, values := range req.Header {
		for _, v := range values {
			fmt.Printf("header: %s: %s\n", key, v)
		}
	}

	fmt.Printf("%s\n", req.Body)

	fmt.Printf("\n\n\nRESPONSE\n")

	// Print response headers
	for key, values := range resp.Header {
		for _, v := range values {
			fmt.Printf("header: %s: %s\n", key, v)
		}
	}

	// Read response body (must restore it for downstream use)
	respB, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error response parsing %w", err)
		return *baseSpan, false
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(respB))

	// http.ReadResponse does NOT auto-decompress Content-Encoding: gzip
	// (only http.Transport does). Decompress manually if needed.
	bodyToPrint := respB
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, gerr := gzip.NewReader(bytes.NewReader(respB))
		if gerr == nil {
			decompressed, gerr := io.ReadAll(gr)
			_ = gr.Close()
			if gerr == nil {
				bodyToPrint = decompressed
			}
		}
	}
	fmt.Printf("response: %s\n", bodyToPrint)
	return *baseSpan, false
}
