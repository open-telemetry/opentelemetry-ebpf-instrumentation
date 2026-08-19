// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

func TestParseNodejsEventLoopEvent(t *testing.T) {
	const ktime = 2 * 3600 * 1_000_000_000 // 2h since boot

	values := NodejsEventLoopValues{
		ELUIdleNs:     1_000_000_000,
		ELUActiveNs:   250_000_000,
		DelayMinNs:    9_000_000,
		DelayMaxNs:    153_000_000,
		DelayMeanNs:   12_000_000,
		DelayStddevNs: 10_000_000,
		DelayP50Ns:    11_000_000,
		DelayP90Ns:    12_700_000,
		DelayP99Ns:    13_300_000,
		DelayCount:    181,
	}

	event := ParseNodejsEventLoopEvent(ktime, 55, 99, values)

	assert.Equal(t, app.PID(55), event.PID)
	assert.Equal(t, uint32(99), event.PIDNamespaceID)
	assert.Equal(t, values, event.NodejsEventLoopValues)
	require.WithinDuration(t, timing.KernelTime(ktime), event.Time, 100*time.Millisecond)
}
