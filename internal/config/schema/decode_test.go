// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

type testEnum string

const (
	testEnumOne testEnum = "one"
	testEnumTwo testEnum = "two"
)

func TestUnmarshalEnum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		node  yaml.Node
		want  testEnum
		error string
	}{
		{
			name: "valid",
			node: yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: string(testEnumTwo),
			},
			want: testEnumTwo,
		},
		{
			name: "null clears value",
			node: yaml.Node{
				Kind: yaml.ScalarNode,
				Tag:  "!!null",
			},
			want: "",
		},
		{
			name: "non scalar",
			node: yaml.Node{
				Kind: yaml.MappingNode,
				Tag:  "!!map",
			},
			error: "field must be a scalar",
		},
		{
			name: "invalid value",
			node: yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: "three",
			},
			error: `invalid field "three"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := testEnumOne

			err := unmarshalEnum(&test.node, "field", &got, testEnumOne, testEnumTwo)

			if test.error != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.error)
				require.Equal(t, testEnumOne, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}
