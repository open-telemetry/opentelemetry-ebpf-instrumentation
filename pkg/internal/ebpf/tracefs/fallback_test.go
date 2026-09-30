// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tracefs

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func TestWithFallback(t *testing.T) {
	for _, kind := range []ProbeType{Uprobe, Kprobe} {
		t.Run(string(kind), func(t *testing.T) {
			for _, tc := range []struct {
				name              string
				perfErr, traceErr error
				fallback          bool
			}{
				{name: "PMU success"},
				{name: "EACCES", perfErr: unix.EACCES, fallback: true},
				{name: "wrapped EACCES", perfErr: fmt.Errorf("opening perf event: %w", unix.EACCES), fallback: true},
				{name: "EPERM", perfErr: unix.EPERM},
				{name: "EINVAL", perfErr: unix.EINVAL},
				{name: "ENOENT", perfErr: unix.ENOENT},
				{name: "tracefs failure", perfErr: unix.EACCES, traceErr: unix.EROFS, fallback: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					fallbackUsed.Store(false)
					t.Cleanup(func() { fallbackUsed.Store(false) })
					want := &nopCloser{}
					perfCalls, traceCalls := 0, 0
					got, err := WithFallback(kind,
						func() (io.Closer, error) {
							perfCalls++
							if tc.perfErr != nil {
								return nil, tc.perfErr
							}
							return want, nil
						},
						func() (io.Closer, error) {
							traceCalls++
							if tc.traceErr != nil {
								return nil, tc.traceErr
							}
							return want, nil
						})
					assert.Equal(t, 1, perfCalls)
					if tc.fallback {
						assert.Equal(t, 1, traceCalls)
					} else {
						assert.Zero(t, traceCalls)
					}
					success := tc.perfErr == nil || (tc.fallback && tc.traceErr == nil)
					if success {
						require.NoError(t, err)
						assert.Same(t, want, got)
					} else {
						require.ErrorIs(t, err, tc.perfErr)
						if tc.traceErr != nil {
							require.ErrorIs(t, err, tc.traceErr)
						}
						assert.Nil(t, got)
					}
					timeout := 10 * time.Second
					if tc.fallback && success {
						timeout *= 3
					}
					assert.Equal(t, tc.fallback && success, fallbackUsed.Load())
					assert.Equal(t, timeout, EffectiveShutdownTimeout(10*time.Second))
				})
			}
		})
	}
}
