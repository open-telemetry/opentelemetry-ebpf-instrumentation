// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestAWSSNSSpan(t *testing.T) {
	const topicARN = "arn:aws:sns:eu-west-1:123456789012:orders.fifo"
	const publishResponse = `<PublishResponse xmlns="https://sns.amazonaws.com/doc/2010-03-31/"><PublishResult><MessageId>message-1</MessageId></PublishResult><ResponseMetadata><RequestId>request-1</RequestId></ResponseMetadata></PublishResponse>`
	for _, tt := range []struct {
		name, host, action, extra, response string
		status                              int
		get, noTopic, reject                bool
		wantMessage, wantTopic, wantError   string
		wantBatch                           int
	}{
		{name: "publish", action: "Publish", response: publishResponse, wantMessage: "message-1", wantTopic: topicARN},
		{name: "GET query", action: "Publish", get: true, response: publishResponse, wantMessage: "message-1", wantTopic: topicARN},
		{name: "custom endpoint", host: "localstack:4566", action: "Publish", response: publishResponse, wantMessage: "message-1", wantTopic: topicARN},
		{name: "create topic XML identity", host: "localstack:4566", action: "CreateTopic", noTopic: true, response: `<CreateTopicResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/"><CreateTopicResult><TopicArn>` + topicARN + `</TopicArn></CreateTopicResult></CreateTopicResponse>`, wantTopic: topicARN},
		{name: "list topics without destination", action: "ListTopics", noTopic: true},
		{name: "add permission", action: "AddPermission", wantTopic: topicARN},
		{name: "remove permission", action: "RemovePermission", wantTopic: topicARN},
		{name: "subscribe", action: "Subscribe", wantTopic: topicARN},
		{name: "unsubscribe", action: "Unsubscribe", noTopic: true},
		{name: "delete topic", action: "DeleteTopic", wantTopic: topicARN},
		{name: "batch", action: "PublishBatch", extra: "&PublishBatchRequestEntries.member.1.Id=a&PublishBatchRequestEntries.member.1.Message=one&PublishBatchRequestEntries.member.2.Id=b&PublishBatchRequestEntries.member.2.Message=two", response: `<PublishBatchResponse><PublishBatchResult><Successful><member><MessageId>a</MessageId></member><member><MessageId>b</MessageId></member></Successful></PublishBatchResult></PublishBatchResponse>`, wantBatch: 2, wantTopic: topicARN},
		{name: "partial batch failure", action: "PublishBatch", extra: "&PublishBatchRequestEntries.member.1.Id=a&PublishBatchRequestEntries.member.2.Id=b", response: `<PublishBatchResponse><PublishBatchResult><Failed><member><Code>InvalidParameter</Code></member></Failed></PublishBatchResult></PublishBatchResponse>`, wantBatch: 2, wantTopic: topicARN, wantError: "InvalidParameter"},
		{name: "API error", action: "Publish", status: 403, response: `<ErrorResponse><Error><Code>AuthorizationError</Code></Error><RequestId>request-1</RequestId></ErrorResponse>`, wantTopic: topicARN, wantError: "AuthorizationError"},
		{name: "HTTP error without XML", action: "Publish", status: 500, wantTopic: topicARN, wantError: "500"},
		{name: "truncated XML", action: "Publish", response: `<PublishResponse><PublishResult><MessageId>partial`, wantTopic: topicARN},
		{name: "unrelated query API", host: "example.com", action: "CreateTopic", noTopic: true, reject: true},
		{name: "SQS query API", host: "sqs.eu-west-1.amazonaws.com", action: "SendMessage", reject: true},
		{name: "wrong ARN service", host: "example.com", action: "Publish", noTopic: true, extra: "&TopicArn=arn:aws:sqs:eu-west-1:123456789012:orders", reject: true},
		{name: "unknown action", action: "NotAnSNSAction", reject: true},
		{name: "SMS", action: "Publish", noTopic: true, extra: "&PhoneNumber=%2B123456789", reject: true},
		{name: "mobile push", action: "Publish", noTopic: true, extra: "&TargetArn=arn:aws:sns:eu-west-1:123456789012:endpoint/GCM/app/id", reject: true},
		{name: "malformed form", action: "Publish", extra: "&Message=%zz", reject: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			host := tt.host
			if host == "" {
				host = "sns.eu-west-1.amazonaws.com"
			}
			params := url.Values{"Action": {tt.action}, "Version": {"2010-03-31"}}
			if !tt.noTopic {
				params.Set("TopicArn", topicARN)
			}
			body := params.Encode() + tt.extra
			method, target := "POST", "https://"+host+"/"
			if tt.get {
				method, target = "GET", target+"?"+body
			}
			req, err := http.NewRequest(method, target, strings.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			status := tt.status
			if status == 0 {
				status = 200
			}
			resp := &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tt.response))}
			base := request.Span{Type: request.EventTypeHTTPClient, Method: method, Status: status, Path: "/"}
			span, ok := AWSSNSSpan(&base, req, resp)
			require.Equal(t, !tt.reject, ok)
			if tt.reject {
				assert.Nil(t, span.AWS)
			} else {
				require.NotNil(t, span.AWS)
				sns := span.AWS.SNS
				assert.Equal(t, request.HTTPSubtypeAWSSNS, span.SubType)
				assert.Equal(t, tt.action, sns.OperationName)
				assert.Equal(t, tt.wantMessage, sns.MessageID)
				assert.Equal(t, tt.wantTopic, sns.TopicARN)
				assert.Equal(t, tt.wantBatch, sns.BatchCount)
				assert.Equal(t, tt.wantError, sns.ErrorCode)
				assert.Equal(t, "eu-west-1", sns.Meta.Region)
				if tt.wantTopic != "" {
					assert.Equal(t, "orders.fifo", sns.Destination)
				}
				if tt.action == "Publish" || tt.action == "PublishBatch" {
					assert.Equal(t, request.MessagingSend, sns.OperationType)
				} else {
					assert.Empty(t, sns.OperationType)
				}
				if tt.wantMessage != "" || tt.status == 403 {
					assert.Equal(t, "request-1", sns.Meta.RequestID)
				}
				if tt.wantError != "" {
					assert.Equal(t, request.StatusCodeError, request.SpanStatusCode(&span))
				}
			}
			// Detectors share readers with the remaining HTTP enrichment chain.
			gotBody, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.Equal(t, body, string(gotBody))
			gotResponse, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, tt.response, string(gotResponse))
		})
	}
}

func TestAWSSNSTruncatedCapture(t *testing.T) {
	body := "Action=Publish&TopicArn=arn:aws:sns:eu-west-1:123456789012:orders&Message=partial"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(fmt.Sprintf("POST / HTTP/1.1\r\nHost: sns.eu-west-1.amazonaws.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body)+50, body))))
	require.NoError(t, err)
	resp := &http.Response{Body: http.NoBody}
	base := request.Span{Type: request.EventTypeHTTPClient}
	_, ok := AWSSNSSpan(&base, req, resp)
	assert.False(t, ok)
	assert.Nil(t, base.AWS)
}

func TestAWSSNSEndpoints(t *testing.T) {
	for _, host := range []string{"sns.us-east-2.amazonaws.com:443", "sns-fips.us-gov-west-1.amazonaws.com", "sns.cn-north-1.amazonaws.com.cn", "sns.eu-west-1.api.aws", "vpce-0123-abc.sns.eu-west-1.vpce.amazonaws.com"} {
		t.Run(host, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://"+host+"/?Action=ListTopics", nil)
			require.NoError(t, err)
			req.Host = ""
			resp := &http.Response{Body: http.NoBody}
			_, ok := AWSSNSSpan(&request.Span{}, req, resp)
			assert.True(t, ok)
		})
	}
}

func TestAWSSNSResponseMetadata(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		req, err := http.NewRequest(http.MethodGet, "https://sns.eu-west-1.amazonaws.com/?Action=Publish&TopicArn=arn:aws:sns:eu-west-1:123456789012:orders", nil)
		require.NoError(t, err)
		body := `<PublishResponse><PublishResult><MessageId>message-1</MessageId></PublishResult><ResponseMetadata><RequestId>xml-id</RequestId></ResponseMetadata></PublishResponse>`
		length := len(body)
		if truncated {
			length += 100
		}
		resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nx-amzn-requestid: header-id\r\n\r\n%s", length, body))), req)
		require.NoError(t, err)
		span, ok := AWSSNSSpan(&request.Span{}, req, resp)
		require.True(t, ok)
		assert.Equal(t, "header-id", span.AWS.SNS.Meta.RequestID)
		assert.Equal(t, "orders", span.AWS.SNS.Destination)
		if truncated {
			assert.Empty(t, span.AWS.SNS.MessageID)
		} else {
			assert.Equal(t, "message-1", span.AWS.SNS.MessageID)
		}
	}
}
