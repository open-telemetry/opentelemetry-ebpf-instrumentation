// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package langtools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidServiceName(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "plain name", value: "orders", want: true},
		{name: "name with spaces", value: "orders worker", want: true},
		{name: "empty"},
		{name: "current directory", value: "."},
		{name: "parent directory", value: ".."},
		{name: "standard input", value: "-"},
		{name: "root", value: "/"},
		{name: "control character", value: "orders\nworker"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ValidServiceName(tt.value))
		})
	}
}
