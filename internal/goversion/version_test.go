// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goversion

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "bare stable", input: "1.27.0", want: "go1.27.0"},
		{name: "prefixed stable", input: "go1.27.0", want: "go1.27.0"},
		{name: "patch", input: "go1.27.1", want: "go1.27.1"},
		{name: "release candidate", input: "go1.28rc2", want: "go1.28rc2"},
		{name: "beta", input: "1.28beta1", want: "go1.28beta1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := Parse(test.input)
			require.NoError(t, err)
			assert.Equal(t, test.want, actual.String())
		})
	}
}

func TestParseRejectsNonToolchainVersions(t *testing.T) {
	for _, input := range []string{
		"prefix go1.27.0 suffix",
		"go1.27.0 trailing",
		"devel go1.29-abcdef",
		"1.27.0rc1",
		"",
	} {
		t.Run(input, func(t *testing.T) {
			_, err := Parse(input)
			require.ErrorContains(t, err, "invalid Go version")
		})
	}
}
