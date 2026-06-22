// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestDaemonEnumsYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		valid   string
		want    string
		invalid string
		err     string
		parse   func([]byte) (string, error)
	}{
		{
			name:    "log level",
			valid:   "level: WARN\n",
			want:    string(LogLevelWarn),
			invalid: "level: TRACE\n",
			err:     "invalid level",
			parse: func(data []byte) (string, error) {
				var doc struct {
					Level LogLevel `yaml:"level"`
				}
				err := yaml.Unmarshal(data, &doc)
				return string(doc.Level), err
			},
		},
		{
			name:    "log format",
			valid:   "format: json\n",
			want:    string(LogFormatJSON),
			invalid: "format: xml\n",
			err:     "invalid format",
			parse: func(data []byte) (string, error) {
				var doc struct {
					Format LogFormat `yaml:"format"`
				}
				err := yaml.Unmarshal(data, &doc)
				return string(doc.Format), err
			},
		},
		{
			name:    "empty log format",
			valid:   "format: \"\"\n",
			want:    string(LogFormatUnset),
			invalid: "format: text\n",
			err:     "invalid format",
			parse: func(data []byte) (string, error) {
				var doc struct {
					Format LogFormat `yaml:"format"`
				}
				err := yaml.Unmarshal(data, &doc)
				return string(doc.Format), err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := test.parse([]byte(test.valid))
			require.NoError(t, err)
			require.Equal(t, test.want, got)

			_, err = test.parse([]byte(test.invalid))
			require.Error(t, err)
			require.Contains(t, err.Error(), test.err)
		})
	}
}
