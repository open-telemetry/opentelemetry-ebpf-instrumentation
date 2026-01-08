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
			name: "annotation malformed",
			annotations: map[string]string{
				ovnSubnetAnnotation: "whatever",
			},
			wantErr: "cannot read annotation",
		},
		{
			name: "IP malformed",
			annotations: map[string]string{
				ovnSubnetAnnotation: `{"default":"10.129/23"}`,
			},
			wantErr: "invalid CIDR address",
		},
		{
			name: "valid annotation",
			annotations: map[string]string{
				ovnSubnetAnnotation: `{"default":"10.129.0.0/23"}`,
			},
			wantIP: "10.129.0.2",
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
