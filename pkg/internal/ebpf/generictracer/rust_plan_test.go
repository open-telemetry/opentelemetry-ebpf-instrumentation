// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type rustTestLink struct{ closed bool }

func (l *rustTestLink) Close() error { l.closed = true; return nil }

func TestRustPublicSpawnFallback(t *testing.T) {
	for name, runtimeSpawn := range map[string]bool{"missing runtime spawn": false, "runtime attachment fails": true} {
		t.Run(name, func(t *testing.T) {
			var symbols rustProbeSymbols
			symbols.addresses[rustTaskSpawnPublic] = []uint64{1}
			symbols.addresses[rustTaskSchedule] = []uint64{2}
			symbols.addresses[rustTaskScheduleLocal] = []uint64{4}
			if runtimeSpawn {
				symbols.addresses[rustTaskSpawn] = []uint64{3}
			}

			groups := planRustProbes(symbols)
			require.Len(t, groups, 1)
			_, features, err := attachRustGroups(groups, func(alternative rustProbeAlternative) ([]io.Closer, error) {
				if len(alternative[rustTaskSpawn]) > 0 {
					return nil, errors.New("runtime spawn unavailable")
				}
				require.NotEmpty(t, alternative[rustTaskSpawnPublic])
				require.NotEmpty(t, alternative[rustTaskSchedule])
				require.NotEmpty(t, alternative[rustTaskScheduleLocal])
				return nil, nil
			})
			require.NoError(t, err)
			require.True(t, features["task-create"])
		})
	}
}
