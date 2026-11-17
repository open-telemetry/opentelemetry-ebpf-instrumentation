// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestMinimumReleaseAcrossBaselines(t *testing.T) {
	for _, tc := range []struct {
		name     string
		findings []finding
		want     string
	}{
		{name: "unchanged", want: "patch"},
		{
			name:     "addition already released in minor",
			findings: []finding{{Baseline: "v1.0.0", Compatible: true}},
			want:     "patch",
		},
		{
			name:     "addition already released in patch",
			findings: []finding{{Baseline: "v1.1.0", Compatible: true}},
			want:     "patch",
		},
		{
			name:     "new addition",
			findings: []finding{{Baseline: "v1.0.0", Compatible: true}, {Baseline: "v1.1.1", Compatible: true}},
			want:     "minor",
		},
		{
			name:     "older contract breaks",
			findings: []finding{{Baseline: "v1.0.0", Compatible: false}, {Baseline: "v1.1.1", Compatible: true}},
			want:     "major",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := minimumRelease(tc.findings, "v1.1.1"); got != tc.want {
				t.Fatalf("minimum release=%s, want %s", got, tc.want)
			}
		})
	}
}
