// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

func TestPostProcessSNS(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, kind := range []request.EventType{request.EventTypeHTTP, request.EventTypeHTTPClient} {
			req, err := http.NewRequest(http.MethodPost, "https://sns.eu-west-1.amazonaws.com/", strings.NewReader("Action=Publish&TopicArn=arn:aws:sns:eu-west-1:123456789012:orders&Message=hello"))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp := &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}
			ctx := &EBPFParseContext{payloadExtraction: config.PayloadExtraction{HTTP: config.HTTPConfig{AWS: config.AWSConfig{Enabled: enabled}}}}
			span := postProcessHTTPSpan(ctx, &request.Span{Type: kind}, req, resp)
			if enabled && kind == request.EventTypeHTTPClient {
				assert.Equal(t, request.HTTPSubtypeAWSSNS, span.SubType)
				require.NotNil(t, span.AWS)
				assert.Equal(t, "orders", span.AWS.SNS.Destination)
			} else {
				assert.Nil(t, span.AWS)
			}
		}
	}
}

func TestPostProcessAWSPerServiceSelection(t *testing.T) {
	newSNSRequest := func() *http.Request {
		req, err := http.NewRequest(http.MethodPost, "https://sns.eu-west-1.amazonaws.com/", strings.NewReader("Action=Publish&TopicArn=arn:aws:sns:eu-west-1:123456789012:orders&Message=hello"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}

	tests := []struct {
		name    string
		aws     config.AWSConfig
		wantSNS bool
	}{
		{name: "sns selected", aws: config.AWSConfig{SNS: true}, wantSNS: true},
		{name: "only s3 and sqs selected", aws: config.AWSConfig{S3: true, SQS: true}, wantSNS: false},
		{name: "v1 enabled covers every service", aws: config.AWSConfig{Enabled: true}, wantSNS: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}
			ctx := &EBPFParseContext{payloadExtraction: config.PayloadExtraction{HTTP: config.HTTPConfig{AWS: test.aws}}}

			span := postProcessHTTPSpan(ctx, &request.Span{Type: request.EventTypeHTTPClient}, newSNSRequest(), resp)

			if !test.wantSNS {
				assert.Nil(t, span.AWS)
				return
			}
			assert.Equal(t, request.HTTPSubtypeAWSSNS, span.SubType)
			require.NotNil(t, span.AWS)
		})
	}
}
