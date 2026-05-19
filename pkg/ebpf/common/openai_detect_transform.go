// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/json"
	"structs"

	trace2 "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

// openaiGoReqT mirrors the C struct openai_go_req_t defined in
// bpf/common/common.h. The layout must be kept in sync with the C definition.
//
//	typedef struct openai_go_req {
//	    u8 type;
//	    u8 _pad[7];
//	    u64 start_monotime_ns;
//	    u64 end_monotime_ns;
//	    pid_info pid;
//	    u8 _pad2[4];
//	    tp_info_t tp;
//	    unsigned char request_model[64];
//	    unsigned char response_model[64];
//	    unsigned char response_id[64];
//	    s64 prompt_tokens;
//	    s64 completion_tokens;
//	    unsigned char input_message_content[256];
//	    unsigned char output_message_content[256];
//	    u8 input_message_role;
//	    u8 _pad3[7];
//	} openai_go_req_t;
type openaiGoReqT struct {
	_               structs.HostLayout
	Type            uint8
	Pad             [7]uint8
	StartMonotimeNs uint64
	EndMonotimeNs   uint64
	Pid             struct {
		_       structs.HostLayout
		HostPid uint32
		UserPid uint32
		Ns      uint32
	}
	Pad2 [4]uint8
	Tp   struct {
		_        structs.HostLayout
		TraceID  [16]uint8
		SpanID   [8]uint8
		ParentID [8]uint8
		TS       uint64
		Flags    uint8
		Pad      [7]uint8
	}
	RequestModel         [64]uint8
	ResponseModel        [64]uint8
	ResponseID           [64]uint8
	PromptTokens         int64
	CompletionTokens     int64
	InputMessageContent  [256]uint8
	OutputMessageContent [256]uint8
	InputMessageRole     uint8
	Pad3                 [7]uint8
}

type genAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
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

// ReadGoOpenAIRequestIntoSpan parses a raw ring buffer record containing an
// openai_go_req_t event (EVENT_GO_OPENAI) and converts it into an OBI Span.
// The returned span uses EventTypeHTTPClient with HTTPSubtypeOpenAI so that
// the existing tracesgen.go export logic emits the correct GenAI attributes.
func ReadGoOpenAIRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[openaiGoReqT](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	reqModel := cstr(event.RequestModel[:])
	respModel := cstr(event.ResponseModel[:])
	respID := cstr(event.ResponseID[:])

	inputContent := cstr(event.InputMessageContent[:])
	outputContent := cstr(event.OutputMessageContent[:])

	inputMessages := marshalGenAIMessages(openAIRoleString(event.InputMessageRole), inputContent)
	outputChoices := marshalGenAIMessages("assistant", outputContent)

	return request.Span{
		Type:         request.EventTypeHTTPClient,
		SubType:      request.HTTPSubtypeOpenAI,
		Method:       "POST",
		Status:       200,
		RequestStart: int64(event.StartMonotimeNs),
		Start:        int64(event.StartMonotimeNs),
		End:          int64(event.EndMonotimeNs),
		TraceID:      trace2.TraceID(event.Tp.TraceID),
		SpanID:       trace2.SpanID(event.Tp.SpanID),
		ParentSpanID: trace2.SpanID(event.Tp.ParentID),
		TraceFlags:   event.Tp.Flags,
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
