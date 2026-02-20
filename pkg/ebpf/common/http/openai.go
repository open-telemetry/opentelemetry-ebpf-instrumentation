// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func OpenAISpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
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

	respB, err := getResponseBody(resp)
	if err != nil && len(respB) == 0 {
		fmt.Printf("Error response parsing %v", err)
		return *baseSpan, false
	}

	fmt.Printf("response (body_err=%v): %s\n", err, string(respB))
	return *baseSpan, false
}
