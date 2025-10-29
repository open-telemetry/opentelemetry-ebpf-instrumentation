// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"
	"go.opentelemetry.io/obi/test/integration/components/jaeger"
)

const (
	s3BucketName = "obi-bucket"
	s3ObjectKey  = "hello.txt"
	// Extended request ID is hardcoded for all localstack S3 requests
	s3ExtendedRequestID = "s9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234="
)

func testPythonAWSS3(t *testing.T) {
	const (
		address           = "http://localhost:8381"
		localstackAddress = "http://localhost:4566"
	)

	waitForTestComponentsNoMetrics(t, address+"/health")
	waitForTestComponentsNoMetrics(t, localstackAddress)

	// Wait for /health to appear in jaeger
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		ti.DoHTTPGet(t, "http://localhost:8381/health", 200)
		resp, err := http.Get(jaegerQueryURL + "?service=python3.12&operation=GET%20%2Fhealth")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/health"})
		require.Len(t, traces, 1)
	}, test.Interval(1*time.Second))

	s3Req(t, address+"/createbucket")
	s3Req(t, address+"/createobject")
	s3Req(t, address+"/listobjects")
	s3Req(t, address+"/deleteobject")
	s3Req(t, address+"/deletebucket")

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		assertS3Operation(t, "CreateBucket", "")
		assertS3Operation(t, "PutObject", s3ObjectKey)
		assertS3Operation(t, "ListObjects", "")
		assertS3Operation(t, "DeleteObject", s3ObjectKey)
		assertS3Operation(t, "DeleteBucket", "")
	}, test.Interval(time.Second))
}

func s3Req(t *testing.T, url string) {
	t.Helper()

	resp, err := http.Get(url)
	require.NoError(t, err)
	require.True(t, resp.StatusCode >= 200 && resp.StatusCode <= 204)
}

func assertS3Operation(t require.TestingT, op, expectedKey string) {
	opName := "s3." + op

	span := fetchS3SpanByOP(t, opName)
	require.Equal(t, opName, span.OperationName)

	tag, found := jaeger.FindIn(span.Tags, "rpc.method")
	require.True(t, found)
	require.Equal(t, op, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "aws.s3.key")
	require.True(t, found)
	require.Equal(t, expectedKey, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "rpc.service")
	require.True(t, found)
	require.Equal(t, "S3", tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "rpc.system")
	require.True(t, found)
	require.Equal(t, "aws-api", tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "aws.s3.bucket")
	require.True(t, found)
	require.Equal(t, s3BucketName, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "aws.request_id")
	require.True(t, found)
	require.NotEmpty(t, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "aws.extended_request_id")
	require.True(t, found)
	require.Equal(t, s3ExtendedRequestID, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "cloud.region")
	require.True(t, found)
	require.Empty(t, tag.Value)
}

func fetchS3SpanByOP(t require.TestingT, op string) jaeger.Span {
	var tq jaeger.TracesQuery

	params := neturl.Values{}
	params.Add("service", "python3.12")
	params.Add("operation", op)
	fullJaegerURL := fmt.Sprintf("%s?%s", jaegerQueryURL, params.Encode())

	resp, err := http.Get(fullJaegerURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
	require.GreaterOrEqual(t, len(tq.Data), 1)

	for _, tr := range tq.Data {
		spans := tr.FindByOperationName(op, "client")
		if len(spans) > 0 {
			return spans[0]
		}
	}

	// Unreachable
	t.FailNow()
	return jaeger.Span{}
}
