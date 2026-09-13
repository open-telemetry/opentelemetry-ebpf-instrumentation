// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInlineConstrainedParam(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "constraint", value: `id<\d+>`, want: true},
		{name: "character class", value: `page<[0-9]+>`, want: true},
		{name: "regex quantifier", value: `year<\d{4}>`, want: true},
		{name: "default", value: `page<\d+>?1`, want: true},
		{name: "null default", value: `page<\d+>?`, want: true},
		{name: "underscore name", value: `_locale<en|fr>`, want: true},
		{name: "empty", value: ""},
		{name: "missing constraint", value: "id"},
		{name: "missing name", value: `<\d+>`},
		{name: "invalid name", value: `1id<\d+>`},
		{name: "empty constraint", value: "id<>"},
		{name: "missing opening delimiter", value: `id\d+>`},
		{name: "missing closing delimiter", value: `id<\d+`},
		{name: "path separator", value: `path<.+/.+>`},
		{name: "nested angle delimiter", value: `id<a>b>`},
		{name: "suffix without default marker", value: `id<\d+>1`},
		{name: "closing brace in default", value: `id<\d+>?one}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isInlineConstrainedParam(test.value))
		})
	}
}
