// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	trace2 "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestSNSAttributes(t *testing.T) {
	for _, operation := range []string{"Publish", "PublishBatch", "CreateTopic", "ListTopics"} {
		t.Run(operation, func(t *testing.T) {
			sns := request.AWSSNS{
				OperationName: operation,
				Meta:          request.AWSMeta{RequestID: "req-1", Region: "eu-west-1"},
			}
			if operation != "ListTopics" {
				sns.TopicARN = "arn:aws:sns:eu-west-1:123456789012:orders"
				sns.Destination = "orders"
			}
			if operation == "Publish" || operation == "PublishBatch" {
				sns.OperationType = request.MessagingSend
			}
			if operation == "Publish" {
				sns.MessageID = "message-1"
			}
			if operation == "PublishBatch" {
				sns.BatchCount = 2
				sns.ErrorCode = "InvalidParameter"
			}
			span := &request.Span{Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeAWSSNS, Method: "POST", Path: "/", Status: 200, AWS: &request.AWS{SNS: sns}}
			attrs := TraceAttributesSelector(span, defaultTraceAttrs(t))
			assert.Equal(t, "sns."+operation, span.TraceName())
			assert.Equal(t, "messaging_system", span.ServiceGraphConnectionType())
			// These spans describe the HTTP transport; they do not supply message creation context.
			assert.Equal(t, trace2.SpanKindClient, spanKind(span))
			assert.Contains(t, attrs, semconv.MessagingSystemAWSSNS)
			assert.Contains(t, attrs, request.MessagingOperationName(operation))
			assert.Contains(t, attrs, semconv.CloudRegion("eu-west-1"))
			assert.Contains(t, attrs, semconv.AWSRequestID("req-1"))
			if sns.TopicARN != "" {
				assert.Contains(t, attrs, semconv.AWSSNSTopicARN(sns.TopicARN))
				assert.Contains(t, attrs, semconv.MessagingDestinationName("orders"))
			}
			if sns.OperationType != "" {
				assert.Contains(t, attrs, request.MessagingOperationType("send"))
			}
			if operation == "Publish" {
				assert.Contains(t, attrs, semconv.MessagingMessageID("message-1"))
			}
			if operation == "PublishBatch" {
				assert.Contains(t, attrs, semconv.MessagingBatchMessageCount(2))
				assert.Contains(t, attrs, request.ErrorType("InvalidParameter"))
				assert.Equal(t, request.StatusCodeError, request.SpanStatusCode(span))
				assert.Equal(t, sns.ErrorCode, request.SpanErrorType(span))

				_, found := errorTypeValue(TraceAttributesSelector(span, map[attr.Name]struct{}{}))
				assert.False(t, found)
			} else {
				assert.Equal(t, request.StatusCodeUnset, request.SpanStatusCode(span))
			}
			getters := request.SpanOTELGetters(request.UnresolvedNames{})
			for _, name := range []attr.Name{attr.MessagingSystem, attr.MessagingOpName, attr.CloudRegion, attr.AWSRequestID, attr.AWSSNSTopicARN, attr.MessagingBatchCount, attr.ErrorType} {
				getter, ok := getters(name)
				require.True(t, ok, name)
				kv := getter(span)
				if kv.Valid() {
					assert.Contains(t, attrs, kv, name)
				}
			}
			for _, kv := range attrs {
				if kv.Key == semconv.MessagingMessageIDKey {
					assert.Equal(t, "Publish", operation)
					assert.Equal(t, "message-1", kv.Value.AsString())
				}
				if kv.Key == semconv.MessagingBatchMessageCountKey {
					assert.Equal(t, "PublishBatch", operation)
				}
				if kv.Key == semconv.AWSSNSTopicARNKey || kv.Key == semconv.MessagingDestinationNameKey {
					assert.NotEqual(t, "ListTopics", operation)
				}
				assert.NotEqual(t, attribute.String("messaging.operation.type", ""), kv)
			}
		})
	}

	t.Run("unknown batch count", func(t *testing.T) {
		span := &request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeAWSSNS,
			AWS:     &request.AWS{SNS: request.AWSSNS{OperationName: "PublishBatch"}},
		}
		attrs := TraceAttributesSelector(span, defaultTraceAttrs(t))
		_, found := attrValue(attrs, string(semconv.MessagingBatchMessageCountKey))
		assert.False(t, found)

		getter, ok := request.SpanOTELGetters(request.UnresolvedNames{})(attr.MessagingBatchCount)
		require.True(t, ok)
		assert.False(t, getter(span).Valid())
	})
}
