// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestParseAWSSQS(t *testing.T) {
	tests := []struct {
		name    string
		req     *http.Request
		resp    *http.Response
		want    request.AWSSQS
		wantErr bool
	}{
		{
			name: "valid SendMessage request and response",
			req: func() *http.Request {
				body := `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/123456789012/test-queue"}`
				r, _ := http.NewRequest(http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", io.NopCloser(strings.NewReader(body)))
				r.Header.Set("x-amz-target", "AmazonSQS.SendMessage")
				return r
			}(),
			resp: func() *http.Response {
				body := `{"MessageId":"abc123"}`
				r := &http.Response{
					Body: io.NopCloser(strings.NewReader(body)),
				}
				r.Header = http.Header{}
				r.Header.Set("x-amz-request-id", "reqid123")
				return r
			}(),
			want: request.AWSSQS{
				Meta: request.AWSMeta{
					Region:    "us-east-1",
					RequestID: "reqid123",
				},
				OperationName: "SendMessage",
				OperationType: "send",
				MessageID:     "abc123",
				QueueURL:      "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue",
				Destination:   "test-queue",
			},
			wantErr: false,
		},
		{
			name: "missing x-amz-target header",
			req: func() *http.Request {
				body := `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/123456789012/test-queue"}`
				r, _ := http.NewRequest(http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", io.NopCloser(strings.NewReader(body)))
				return r
			}(),
			resp: func() *http.Response {
				body := `{"MessageId":"abc123"}`
				r := &http.Response{
					Body: io.NopCloser(strings.NewReader(body)),
				}
				r.Header = http.Header{}
				r.Header.Set("x-amz-request-id", "reqid123")
				return r
			}(),
			want:    request.AWSSQS{},
			wantErr: true,
		},
		{
			name: "invalid request body JSON",
			req: func() *http.Request {
				body := `not-json`
				r, _ := http.NewRequest(http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", io.NopCloser(strings.NewReader(body)))
				r.Header.Set("x-amz-target", "AmazonSQS.SendMessage")
				return r
			}(),
			resp: func() *http.Response {
				body := `{"MessageId":"abc123"}`
				r := &http.Response{
					Body: io.NopCloser(strings.NewReader(body)),
				}
				r.Header = http.Header{}
				r.Header.Set("x-amz-request-id", "reqid123")
				return r
			}(),
			want: request.AWSSQS{
				Meta: request.AWSMeta{
					Region:    "us-east-1",
					RequestID: "reqid123",
				},
				OperationName: "SendMessage",
				OperationType: "send",
				MessageID:     "abc123",
				QueueURL:      "",
				Destination:   "",
			},
			wantErr: false,
		},
		{
			name: "invalid response body JSON",
			req: func() *http.Request {
				body := `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/123456789012/test-queue"}`
				r, _ := http.NewRequest(http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", io.NopCloser(strings.NewReader(body)))
				r.Header.Set("x-amz-target", "AmazonSQS.SendMessage")
				return r
			}(),
			resp: func() *http.Response {
				body := `not-json`
				r := &http.Response{
					Body: io.NopCloser(strings.NewReader(body)),
				}
				r.Header = http.Header{}
				r.Header.Set("x-amz-request-id", "reqid123")
				return r
			}(),
			want: request.AWSSQS{
				Meta: request.AWSMeta{
					Region:    "us-east-1",
					RequestID: "reqid123",
				},
				OperationName: "SendMessage",
				OperationType: "send",
				MessageID:     "",
				QueueURL:      "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue",
				Destination:   "test-queue",
			},
			wantErr: false,
		},
		{
			name: "missing QueueUrl and MessageId",
			req: func() *http.Request {
				body := `{}`
				r, _ := http.NewRequest(http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", io.NopCloser(strings.NewReader(body)))
				r.Header.Set("x-amz-target", "AmazonSQS.ReceiveMessage")
				return r
			}(),
			resp: func() *http.Response {
				body := `{}`
				r := &http.Response{
					Body: io.NopCloser(strings.NewReader(body)),
				}
				r.Header = http.Header{}
				r.Header.Set("x-amz-request-id", "reqid123")
				return r
			}(),
			want: request.AWSSQS{
				Meta: request.AWSMeta{
					Region:    "us-east-1",
					RequestID: "reqid123",
				},
				OperationName: "ReceiveMessage",
				OperationType: "receive",
				MessageID:     "",
				QueueURL:      "",
				Destination:   "",
			},
			wantErr: false,
		},
		{
			name: "unknown operation type",
			req: func() *http.Request {
				body := `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/123456789012/test-queue"}`
				r, _ := http.NewRequest(http.MethodPost, "https://sqs.us-east-1.amazonaws.com/", io.NopCloser(strings.NewReader(body)))
				r.Header.Set("x-amz-target", "AmazonSQS.UnknownOp")
				return r
			}(),
			resp: func() *http.Response {
				body := `{"MessageId":"abc123"}`
				r := &http.Response{
					Body: io.NopCloser(strings.NewReader(body)),
				}
				r.Header = http.Header{}
				r.Header.Set("x-amz-request-id", "reqid123")
				return r
			}(),
			want: request.AWSSQS{
				Meta: request.AWSMeta{
					Region:    "us-east-1",
					RequestID: "reqid123",
				},
				OperationName: "UnknownOp",
				OperationType: "",
				MessageID:     "abc123",
				QueueURL:      "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue",
				Destination:   "test-queue",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAWSSQS(tt.req, tt.resp)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
