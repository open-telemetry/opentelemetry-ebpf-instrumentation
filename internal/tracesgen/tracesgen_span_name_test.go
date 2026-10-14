// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func requireAttrString(t *testing.T, span *request.Span, key string) string {
	t.Helper()
	value, ok := attrValue(TraceAttributesSelector(span, defaultTraceAttrs(t)), key)
	require.True(t, ok, key)
	return value.AsString()
}

func TestSpanName_GraphQLMatchesOperationType(t *testing.T) {
	span := &request.Span{
		Type:    request.EventTypeHTTP,
		SubType: request.HTTPSubtypeGraphQL,
		Method:  "POST",
		Route:   "/graphql",
		GraphQL: &request.GraphQL{OperationType: "mutation", OperationName: "AddBook"},
	}

	assert.Equal(t, requireAttrString(t, span, string(semconv.GraphQLOperationTypeKey)), span.TraceName())
}

func TestSpanName_AWSMatchesRPCMethod(t *testing.T) {
	tests := []struct {
		name     string
		aws      request.AWS
		subType  int
		expected string
	}{
		{name: "S3", subType: request.HTTPSubtypeAWSS3, aws: request.AWS{S3: request.AWSS3{Method: "GetObject"}}, expected: "S3.GetObject"},
		{name: "SNS", subType: request.HTTPSubtypeAWSSNS, aws: request.AWS{SNS: request.AWSSNS{OperationName: "Publish"}}, expected: "SNS.Publish"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := &request.Span{Type: request.EventTypeHTTPClient, SubType: tt.subType, Method: "POST", Path: "/", AWS: &tt.aws}

			rpcMethod := requireAttrString(t, span, string(semconv.RPCMethodKey))
			assert.Equal(t, tt.expected, span.TraceName())
			assert.Equal(t, strings.Replace(rpcMethod, "/", ".", 1), span.TraceName())
		})
	}
}

func TestSpanName_SQSIsAWSServicePrefixPlusOperationNameWithoutRPCAttributes(t *testing.T) {
	span := &request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: request.HTTPSubtypeAWSSQS,
		Method:  "POST",
		Path:    "/",
		AWS:     &request.AWS{SQS: request.AWSSQS{OperationName: "SendMessage", OperationType: request.MessagingSend}},
	}

	attrs := TraceAttributesSelector(span, defaultTraceAttrs(t))
	_, hasRPCSystem := attrValue(attrs, string(semconv.RPCSystemNameKey))
	_, hasRPCMethod := attrValue(attrs, string(semconv.RPCMethodKey))
	assert.False(t, hasRPCSystem)
	assert.False(t, hasRPCMethod)

	operation := requireAttrString(t, span, string(semconv.MessagingOperationNameKey))
	assert.Equal(t, "SQS.SendMessage", span.TraceName())
	assert.Equal(t, "SQS."+operation, span.TraceName())
}

func TestSpanName_S3WithoutOperationMatchesRPCSystem(t *testing.T) {
	span := &request.Span{Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeAWSS3, Method: "POST", Path: "/", AWS: &request.AWS{}}

	assert.Equal(t, requireAttrString(t, span, string(semconv.RPCSystemNameKey)), span.TraceName())
}

func TestSpanName_SunRPCMatchesRPCMethod(t *testing.T) {
	span := &request.Span{
		Type:   request.EventTypeSunRPCClient,
		Path:   "mount",
		Method: "MOUNTPROC_EXPORT",
		Route:  "5",
	}

	assert.Equal(t, "mount/MOUNTPROC_EXPORT", span.TraceName())
	assert.Equal(t, requireAttrString(t, span, string(semconv.RPCMethodKey)), span.TraceName())
}

func TestSpanName_SunRPCReplyOnlyMatchesRPCSystem(t *testing.T) {
	span := &request.Span{
		Type:   request.EventTypeSunRPCServer,
		Path:   "sunrpc",
		Method: request.SunRPCSyntheticReplyMethod,
	}

	_, hasMethod := attrValue(TraceAttributesSelector(span, defaultTraceAttrs(t)), string(semconv.RPCMethodKey))
	assert.False(t, hasMethod)
	assert.Equal(t, requireAttrString(t, span, string(semconv.RPCSystemNameKey)), span.TraceName())
}
