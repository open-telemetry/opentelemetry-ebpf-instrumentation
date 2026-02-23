// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
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

	// Check any of the well known response headers that OpenAI would use
	isOpenAI := false
	for _, header := range []string{"Openai-Version", "Openai-Organization", "Openai-Project", "Openai-Processing-Ms"} {
		if _, ok := resp.Header[header]; ok {
			isOpenAI = true
			break
		}
	}

	if !isOpenAI {
		return *baseSpan, false
	}

	respB, err := getResponseBody(resp)
	if err != nil && len(respB) == 0 {
		fmt.Printf("Error response parsing %v", err)
		return *baseSpan, false
	}

	fmt.Printf("****Request:\n%s\n", string(reqB))
	fmt.Printf("****Response:\n%s\n", string(respB))

	var parsedRequest request.OpenAIInput
	_ = json.Unmarshal(reqB, &parsedRequest)

	var parsedResponse request.OpenAI
	_ = json.Unmarshal(respB, &parsedResponse)

	parsedResponse.Request = parsedRequest

	baseSpan.SubType = request.HTTPSubtypeOpenAI
	baseSpan.OpenAI = &parsedResponse

	return *baseSpan, true
}
