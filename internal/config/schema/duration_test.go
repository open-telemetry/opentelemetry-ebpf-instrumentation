// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
