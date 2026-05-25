// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/json"
	"unsafe"

	trace2 "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

type genAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// genAIChoice mirrors the OpenAI Chat Completions choice wire format so that
// downstream normalization (normalizeOpenAIChoices) can extract role,
// content and finish_reason from VendorOpenAI.Choices.
type genAIChoice struct {
	Index        int          `json:"index"`
	Message      genAIMessage `json:"message"`
	FinishReason string       `json:"finish_reason,omitempty"`
}

func openAIRoleString(role uint8) string {
	switch role {
	case 1:
		return "system"
	case 2:
		return "assistant"
	case 3:
		return "developer"
	case 4:
		return "tool"
	case 5:
		return "function"
	default:
		return "user"
	}
}

// marshalGenAIMessages serializes a single role/content pair as the flat
// OpenAI Chat Completions request messages array used by VendorOpenAI's
// Request.Messages field (consumed by normalizeOpenAIMessages).
func marshalGenAIMessages(role, content string) json.RawMessage {
	if content == "" {
		return nil
	}
	data, err := json.Marshal([]genAIMessage{{Role: role, Content: content}})
	if err != nil {
		return nil
	}
	return json.RawMessage(data)
}

// marshalGenAIChoices serializes the assistant response as an OpenAI Chat
// Completions choices array so that normalizeOpenAIChoices can map the
// message/finish_reason into the semconv output messages schema.
func marshalGenAIChoices(role, content, finishReason string) json.RawMessage {
	if content == "" {
		return nil
	}
	data, err := json.Marshal([]genAIChoice{{
		Index:        0,
		Message:      genAIMessage{Role: role, Content: content},
		FinishReason: finishReason,
	}})
	if err != nil {
		return nil
	}
	return json.RawMessage(data)
}

// ReadGoOpenAIRequestIntoSpan parses a raw ring buffer record containing an
// openai_go_req_t event (EVENT_GO_OPENAI) and converts it into an OBI Span.
// The returned span uses EventTypeHTTPClient with HTTPSubtypeOpenAI so that
// the existing tracesgen.go export logic emits the correct GenAI attributes.
func ReadGoOpenAIRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoOpenAIInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	reqModel := cstr(event.RequestModel[:])
	respModel := cstr(event.ResponseModel[:])
	respID := cstr(event.ResponseId[:])

	inputContent := cstr(event.InputMessageContent[:])
	outputContent := cstr(event.OutputMessageContent[:])

	inputMessages := marshalGenAIMessages(openAIRoleString(event.InputMessageRole), inputContent)
	// Chat Completion responses always carry the assistant role; the BPF
	// program does not capture finish_reason, so default to "stop" which is
	// the only terminal reason emitted for non-streamed completions.
	outputChoices := marshalGenAIChoices("assistant", outputContent, "stop")

	peer, host := (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()

	return request.Span{
		Type:         request.EventTypeHTTPClient,
		SubType:      request.HTTPSubtypeOpenAI,
		Method:       "POST",
		Status:       200,
		RequestStart: int64(event.StartMonotimeNs),
		Start:        int64(event.StartMonotimeNs),
		End:          int64(event.EndMonotimeNs),
		TraceID:      trace2.TraceID(event.Tp.TraceId),
		SpanID:       trace2.SpanID(event.Tp.SpanId),
		ParentSpanID: trace2.SpanID(event.Tp.ParentId),
		TraceFlags:   event.Tp.Flags,
		Peer:         peer,
		PeerPort:     int(event.Conn.S_port),
		Host:         host,
		HostPort:     int(event.Conn.D_port),
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
		GenAI: &request.GenAI{
			OpenAI: &request.VendorOpenAI{
				OperationName: "chat.completion",
				ID:            respID,
				ResponseModel: respModel,
				Request: request.OpenAIInput{
					Model:    reqModel,
					Messages: inputMessages,
				},
				Choices: outputChoices,
				Usage: request.OpenAIUsage{
					PromptTokens:     int(event.PromptTokens),
					CompletionTokens: int(event.CompletionTokens),
				},
			},
		},
	}, false, nil
}
