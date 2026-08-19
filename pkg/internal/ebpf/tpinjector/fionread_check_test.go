// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// one entry per expected p.fionreadProbe call: the detection probe runs first, the
// end-to-end verification of the loaded fixup second
type probeOutcome struct {
	broken bool
	err    error
}

func TestSockhashSafe(t *testing.T) {
	probeErr := errors.New("probe failed")

	tests := []struct {
		name         string
		outcomes     []probeOutcome
		fixupEnabled bool
		wantSafe     bool
		wantCalls    int
	}{
		{
			name:      "unaffected kernel skips verification",
			outcomes:  []probeOutcome{{broken: false}},
			wantSafe:  true,
			wantCalls: 1,
		},
		{
			name:      "affected kernel without a loaded fixup",
			outcomes:  []probeOutcome{{broken: true}},
			wantSafe:  false,
			wantCalls: 1,
		},
		{
			name:      "detection probe error is treated as affected",
			outcomes:  []probeOutcome{{err: probeErr}},
			wantSafe:  false,
			wantCalls: 1,
		},
		{
			name:         "verification probe error keeps propagation off",
			outcomes:     []probeOutcome{{broken: true}, {err: probeErr}},
			fixupEnabled: true,
			wantSafe:     false,
			wantCalls:    2,
		},
		{
			name:         "ineffective fixup keeps propagation off",
			outcomes:     []probeOutcome{{broken: true}, {broken: true}},
			fixupEnabled: true,
			wantSafe:     false,
			wantCalls:    2,
		},
		{
			name:         "verified fixup enables propagation",
			outcomes:     []probeOutcome{{broken: true}, {broken: false}},
			fixupEnabled: true,
			wantSafe:     true,
			wantCalls:    2,
		},
		{
			name:         "detection probe error recovers when the fixup verifies",
			outcomes:     []probeOutcome{{err: probeErr}, {broken: false}},
			fixupEnabled: true,
			wantSafe:     true,
			wantCalls:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			p := &Tracer{
				log:                  slog.Default(),
				fionreadFixupEnabled: tt.fixupEnabled,
				fionreadProbe: func(*ebpf.Map) (bool, error) {
					require.Less(t, calls, len(tt.outcomes), "unexpected extra probe call")
					o := tt.outcomes[calls]
					calls++
					return o.broken, o.err
				},
			}

			assert.Equal(t, tt.wantSafe, p.sockhashSafe())
			assert.Equal(t, tt.wantCalls, calls)

			// the decision is cached: repeated calls must not re-probe
			assert.Equal(t, tt.wantSafe, p.sockhashSafe())
			assert.Equal(t, tt.wantCalls, calls)
		})
	}
}

func TestSockhashSafeGatesAttachments(t *testing.T) {
	p := &Tracer{
		log:           slog.Default(),
		fionreadProbe: func(*ebpf.Map) (bool, error) { return true, nil },
	}

	assert.False(t, p.sockhashSafe())
	assert.Nil(t, p.SockMsgs())
	assert.Nil(t, p.SockOps())
	assert.Nil(t, p.Iters())
}
