// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestParseAWSS3(t *testing.T) {
	tests := []struct {
		name        string
		req         *http.Request
		resp        *http.Response
		want        request.AWSS3
		wantErr     bool
		errContains string
	}{
		{
			name: "valid request with x-amz-request-id",
			req:  httptest.NewRequest(http.MethodGet, "https://s3.us-west-2.amazonaws.com/mybucket/mykey", bytes.NewBufferString("reqbody")),
			resp: &http.Response{
				Header:     http.Header{"x-amz-request-id": []string{"reqid123"}, "x-amz-id-2": []string{"extid456"}},
				Body:       io.NopCloser(bytes.NewBufferString("respbody")),
				StatusCode: http.StatusOK,
			},
			want: request.AWSS3{
				Meta: request.AWSMeta{
					RequestID:         "reqid123",
					ExtendedRequestID: "extid456",
					Region:            "us-west-2",
				},
				Bucket: "mybucket",
				Key:    "mykey",
				Method: "GetObject",
			},
			wantErr: false,
		},
		{
			name: "valid request with x-amz-requestid fallback",
			req:  httptest.NewRequest(http.MethodPut, "https://s3.eu-central-1.amazonaws.com/bucket/key", bytes.NewBufferString("reqbody")),
			resp: &http.Response{
				Header:     http.Header{"x-amz-requestid": []string{"reqid123"}, "x-amz-id-2": []string{"extid456"}},
				Body:       io.NopCloser(bytes.NewBufferString("respbody")),
				StatusCode: http.StatusOK,
			},
			want: request.AWSS3{
				Meta: request.AWSMeta{
					RequestID:         "reqid123",
					ExtendedRequestID: "extid456",
					Region:            "eu-central-1",
				},
				Bucket: "bucket",
				Key:    "key",
				Method: "PutObject",
			},
			wantErr: false,
		},
		{
			name: "missing request id headers",
			req:  httptest.NewRequest(http.MethodGet, "https://s3.us-east-1.amazonaws.com/bucket/key", nil),
			resp: &http.Response{
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewBufferString("respbody")),
				StatusCode: http.StatusOK,
			},
			want:        request.AWSS3{},
			wantErr:     true,
			errContains: "missing S3 request ID header",
		},
		{
			name: "no bucket or key in path",
			req:  httptest.NewRequest(http.MethodGet, "https://s3.us-west-2.amazonaws.com/", nil),
			resp: &http.Response{
				Header:     http.Header{"x-amz-request-id": []string{"reqid123"}, "x-amz-id-2": []string{"extid456"}},
				Body:       io.NopCloser(bytes.NewBufferString("respbody")),
				StatusCode: http.StatusOK,
			},
			want: request.AWSS3{
				Meta: request.AWSMeta{
					RequestID:         "reqid123",
					ExtendedRequestID: "extid456",
					Region:            "us-west-2",
				},
				Bucket: "",
				Key:    "",
				Method: "ListBuckets",
			},
			wantErr: false,
		},
		{
			name: "region not matched in host",
			req:  httptest.NewRequest(http.MethodGet, "https://s3.amazonaws.com/bucket/key", nil),
			resp: &http.Response{
				Header:     http.Header{"x-amz-request-id": []string{"reqid123"}, "x-amz-id-2": []string{"extid456"}},
				Body:       io.NopCloser(bytes.NewBufferString("respbody")),
				StatusCode: http.StatusOK,
			},
			want: request.AWSS3{
				Meta: request.AWSMeta{
					RequestID:         "reqid123",
					ExtendedRequestID: "extid456",
					Region:            "",
				},
				Bucket: "bucket",
				Key:    "key",
				Method: "GetObject",
			},
			wantErr: false,
		},
		{
			name: "multipart upload query params",
			req:  httptest.NewRequest(http.MethodPut, "https://s3.us-west-2.amazonaws.com/bucket/key?uploadId=123&partNumber=2", nil),
			resp: &http.Response{
				Header:     http.Header{"x-amz-request-id": []string{"reqid123"}, "x-amz-id-2": []string{"extid456"}},
				Body:       io.NopCloser(bytes.NewBufferString("respbody")),
				StatusCode: http.StatusOK,
			},
			want: request.AWSS3{
				Meta: request.AWSMeta{
					RequestID:         "reqid123",
					ExtendedRequestID: "extid456",
					Region:            "us-west-2",
				},
				Bucket: "bucket",
				Key:    "key",
				Method: "UploadPart",
			},
			wantErr: false,
		},
		{
			name: "POST create multipart upload",
			req:  httptest.NewRequest(http.MethodPost, "https://s3.us-west-2.amazonaws.com/bucket/key?uploads=", nil),
			resp: &http.Response{
				Header:     http.Header{"x-amz-request-id": []string{"reqid123"}, "x-amz-id-2": []string{"extid456"}},
				Body:       io.NopCloser(bytes.NewBufferString("respbody")),
				StatusCode: http.StatusOK,
			},
			want: request.AWSS3{
				Meta: request.AWSMeta{
					RequestID:         "reqid123",
					ExtendedRequestID: "extid456",
					Region:            "us-west-2",
				},
				Bucket: "bucket",
				Key:    "key",
				Method: "CreateMultipartUpload",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAWSS3(tt.req, tt.resp)
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
