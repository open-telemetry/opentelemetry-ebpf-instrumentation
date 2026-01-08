// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package cni

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindOvnMp0IP(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		wantIP      string
		wantErr     string
	}{
		{
			name:        "no annotation",
			annotations: map[string]string{},
			wantIP:      "",
		},
		{
			name: "unexpected annotation",
			annotations: map[string]string{
				ovnSubnetAnnotation: `{"other-network":"10.132.0.0/23"}`,
			},
			wantErr: "unexpected content for annotation",
		},
		{
			name: "annotation malformed",
			annotations: map[string]string{
				ovnSubnetAnnotation: "whatever",
			},
			wantErr: "cannot read annotation",
		},
		{
			name: "single-stack IP malformed",
			annotations: map[string]string{
				ovnSubnetAnnotation: `{"default":"10.129/23"}`,
			},
			wantErr: "cannot parse IP",
		},
		{
			name: "dual-stack IP malformed",
			annotations: map[string]string{
				ovnSubnetAnnotation: `{"default":["10.129/23"]}`,
			},
			wantErr: "cannot parse IP",
		},
		{
			name: "single-stack IPv4",
			annotations: map[string]string{
				ovnSubnetAnnotation: `{"default":"10.129.0.0/23"}`,
			},
			wantIP: "10.129.0.2",
		},
		{
			name: "single-stack IPv6",
			annotations: map[string]string{
				ovnSubnetAnnotation: `{"default":"fd01:0:0:2::/64"}`,
			},
			wantIP: "", // IPv6 not supported
		},
		{
			name: "dual-stack IPv4 first",
			annotations: map[string]string{
				ovnSubnetAnnotation: `{"default":["10.130.0.0/23","fd01:0:0:2::/64"]}`,
			},
			wantIP: "10.130.0.2", // IPv6 not supported
		},
		{
			name: "dual-stack IPv6 first",
			annotations: map[string]string{
				ovnSubnetAnnotation: `{"default":["fd01:0:0:2::/64","10.131.0.0/23"]}`,
			},
			wantIP: "10.131.0.2", // IPv6 not supported
		},
		{
			name: "dual-stack IPv6 only",
			annotations: map[string]string{
				ovnSubnetAnnotation: `{"default":["fd01:0:0:2::/64"]}`,
			},
			wantIP: "", // IPv6 not supported
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := findOvnMp0IP(tt.annotations)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tt.wantIP, ip)
		})
	}
}
