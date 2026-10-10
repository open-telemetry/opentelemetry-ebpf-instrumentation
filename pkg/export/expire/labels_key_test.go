// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package expire

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLabelsKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels []string
		want   string
	}{
		{name: "nil"},
		{name: "empty tuple", labels: []string{}},
		{name: "empty values", labels: []string{"", ""}, want: "0:0:"},
		{name: "colons", labels: []string{"checkout:blue", "prod"}, want: "13:checkout:blue4:prod"},
		{name: "unicode", labels: []string{"é", "世界"}, want: "2:é6:世界"},
		{
			name:   "length boundaries",
			labels: []string{strings.Repeat("a", 9), strings.Repeat("b", 10), strings.Repeat("c", 99), strings.Repeat("d", 100)},
			want:   "9:" + strings.Repeat("a", 9) + "10:" + strings.Repeat("b", 10) + "99:" + strings.Repeat("c", 99) + "100:" + strings.Repeat("d", 100),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, LabelsKey(tc.labels))
		})
	}
}

func BenchmarkLabelsKey(b *testing.B) {
	for _, tc := range []struct {
		name   string
		labels []string
	}{
		{name: "service", labels: []string{"checkout:blue", "prod"}},
		{name: "long", labels: []string{strings.Repeat("a", 100), strings.Repeat("b", 1000), "prod"}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				LabelsKey(tc.labels)
			}
		})
	}
}
