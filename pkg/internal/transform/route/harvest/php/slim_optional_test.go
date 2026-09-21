// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandSlimOptionalSegments(t *testing.T) {
	tests := []struct {
		name  string
		route string
		want  []string
	}{
		{
			name:  "no optional segments",
			route: "/users/{id:[0-9]+}",
			want:  []string{"/users/{id:[0-9]+}"},
		},
		{
			name:  "one optional segment",
			route: "/users[/{id}]",
			want:  []string{"/users", "/users/{id}"},
		},
		{
			name:  "optional placeholder after slash",
			route: "/books/[{id}]",
			want:  []string{"/books/", "/books/{id}"},
		},
		{
			name:  "nested optional segments",
			route: "/news[/{year:[0-9]+}[/{month}]]",
			want: []string{
				"/news",
				"/news/{year:[0-9]+}",
				"/news/{year:[0-9]+}/{month}",
			},
		},
		{
			name:  "unlimited optional segments",
			route: "/news[/{params:.*}]",
			want:  []string{"/news", "/news/{params:.*}"},
		},
		{
			name:  "unclosed optional segment",
			route: "/users[/{id}",
			want:  []string{"/users[/{id}"},
		},
		{
			name:  "optional segment followed by static path",
			route: "/users[/{id}]/profile",
			want:  []string{"/users[/{id}]/profile"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, expandSlimOptionalSegments(test.route))
		})
	}
}

func TestStripSlimOptionalSegments(t *testing.T) {
	stripped, variantEnds, ok := stripSlimOptionalSegments("/news[/{year:[0-9]+}[/{month}]]")

	assert.True(t, ok)
	assert.Equal(t, "/news/{year:[0-9]+}/{month}", stripped)
	assert.Equal(t, []int{len("/news"), len("/news/{year:[0-9]+}")}, variantEnds)

	stripped, variantEnds, ok = stripSlimOptionalSegments("/users[/{id}")
	assert.False(t, ok)
	assert.Equal(t, "/users[/{id}", stripped)
	assert.Nil(t, variantEnds)
}
