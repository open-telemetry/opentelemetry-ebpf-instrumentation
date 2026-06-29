// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestDurationYAML(t *testing.T) {
	t.Parallel()

	var doc struct {
		TTL Duration `yaml:"ttl"`
	}

	require.NoError(t, yaml.Unmarshal([]byte("ttl: 5m0s\n"), &doc))
	require.Equal(t, Duration(5*time.Minute), doc.TTL)
	require.Equal(t, 5*time.Minute, doc.TTL.TimeDuration())

	data, err := yaml.Marshal(doc)
	require.NoError(t, err)
	require.Equal(t, "ttl: 5m0s\n", string(data))
}

func TestDurationYAMLNullAndErrors(t *testing.T) {
	t.Parallel()

	t.Run("null", func(t *testing.T) {
		t.Parallel()

		ttl := Duration(time.Second)

		require.NoError(t, ttl.UnmarshalYAML(&yaml.Node{Tag: "!!null"}))
		require.Equal(t, Duration(0), ttl)
	})

	tests := []struct {
		name string
		yaml string
		err  string
	}{
		{
			name: "non scalar",
			yaml: "ttl: []\n",
			err:  "duration must be a scalar",
		},
		{
			name: "invalid duration",
			yaml: "ttl: nope\n",
			err:  "parse duration",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var doc struct {
				TTL Duration `yaml:"ttl"`
			}

			err := yaml.Unmarshal([]byte(test.yaml), &doc)
			require.Error(t, err)
			require.Contains(t, err.Error(), test.err)
		})
	}
}

func TestMillisecondsYAML(t *testing.T) {
	t.Parallel()

	var doc struct {
		Interval Milliseconds `yaml:"interval"`
	}

	require.NoError(t, yaml.Unmarshal([]byte("interval: 1000\n"), &doc))
	require.Equal(t, Milliseconds(time.Second), doc.Interval)
	require.Equal(t, time.Second, doc.Interval.TimeDuration())

	data, err := yaml.Marshal(doc)
	require.NoError(t, err)
	require.Equal(t, "interval: 1000\n", string(data))
}

func TestMillisecondsYAMLNullAndErrors(t *testing.T) {
	t.Parallel()

	t.Run("null", func(t *testing.T) {
		t.Parallel()

		interval := Milliseconds(time.Second)

		require.NoError(t, interval.UnmarshalYAML(&yaml.Node{Tag: "!!null"}))
		require.Equal(t, Milliseconds(0), interval)
	})

	tests := []struct {
		name string
		yaml string
		err  string
	}{
		{
			name: "non scalar",
			yaml: "interval: []\n",
			err:  "milliseconds must be a scalar",
		},
		{
			name: "invalid milliseconds",
			yaml: "interval: nope\n",
			err:  "parse milliseconds",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var doc struct {
				Interval Milliseconds `yaml:"interval"`
			}

			err := yaml.Unmarshal([]byte(test.yaml), &doc)
			require.Error(t, err)
			require.Contains(t, err.Error(), test.err)
		})
	}
}
