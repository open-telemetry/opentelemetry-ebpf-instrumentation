// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"testing"
)

func TestParseAWSRegion(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{
			name: "ec2 with region",
			host: "ec2.us-west-2.amazonaws.com",
			want: "us-west-2",
		},
		{
			name: "s3 with region",
			host: "s3.eu-central-1.amazonaws.com",
			want: "eu-central-1",
		},
		{
			name: "sns with cn region",
			host: "sns.cn-north-1.amazonaws.com.cn",
			want: "cn-north-1",
		},
		{
			name: "sts default region",
			host: "sts.amazonaws.com",
			want: "us-east-1",
		},
		{
			name: "bucket s3 eu-west-1",
			host: "bucket.s3.eu-west-1.amazonaws.com",
			want: "eu-west-1",
		},
		{
			name: "bucket s3 default region",
			host: "bucket.s3.amazonaws.com",
			want: "us-east-1",
		},
		{
			name: "monitoring us-gov-west-1",
			host: "monitoring.us-gov-west-1.amazonaws.com",
			want: "us-gov-west-1",
		},
		{
			name: "s3 cn-north-1 with .cn",
			host: "s3.cn-north-1.amazonaws.com.cn",
			want: "cn-north-1",
		},
		{
			name: "bucket s3 cn-north-1 with .cn",
			host: "bucket.s3.cn-north-1.amazonaws.com.cn",
			want: "cn-north-1",
		},
		{
			name: "service only",
			host: "s3.amazonaws.com",
			want: "us-east-1",
		},
		{
			name: "service only .cn",
			host: "s3.amazonaws.com.cn",
			want: "us-east-1",
		},
		{
			name: "bucket s3 dot region",
			host: "bucket.s3.us-west-2.amazonaws.com",
			want: "us-west-2",
		},
		{
			name: "empty host",
			host: "",
			want: "us-east-1",
		},
		{
			name: "random host",
			host: "example.com",
			want: "us-east-1",
		},
		{
			name: "service.region.amazonaws.com.cn",
			host: "ec2.ap-southeast-1.amazonaws.com.cn",
			want: "ap-southeast-1",
		},
		{
			name: "bucket s3 ap-southeast-2",
			host: "bucket.s3.ap-southeast-2.amazonaws.com",
			want: "ap-southeast-2",
		},
		{
			name: "bucket s3 ap-southeast-2 .cn",
			host: "bucket.s3.ap-southeast-2.amazonaws.com.cn",
			want: "ap-southeast-2",
		},
		{
			name: "service.region.amazonaws.com with numbers",
			host: "lambda.us-east-1.amazonaws.com",
			want: "us-east-1",
		},
		{
			name: "service.region.amazonaws.com with dash",
			host: "dynamodb.us-west-2.amazonaws.com",
			want: "us-west-2",
		},
		{
			name: "bucket s3 region with dot",
			host: "bucket.s3.us-west-1.amazonaws.com",
			want: "us-west-1",
		},
		{
			name: "service.region.amazonaws.com with .cn",
			host: "ec2.cn-northwest-1.amazonaws.com.cn",
			want: "cn-northwest-1",
		},
		{
			name: "bucket s3 region with .cn",
			host: "bucket.s3.cn-northwest-1.amazonaws.com.cn",
			want: "cn-northwest-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Host: tt.host}
			got := parseAWSRegion(req)
			if got != tt.want {
				t.Errorf("parseAWSRegion(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
