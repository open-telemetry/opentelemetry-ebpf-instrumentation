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
				name                            string
				perfErr, traceErr, duplicateErr error
				byName, duplicates              bool
			}{
				{name: "PMU success"},
				{name: "EACCES", perfErr: unix.EACCES, byName: true},
				{name: "wrapped EACCES", perfErr: fmt.Errorf("opening perf event: %w", unix.EACCES), byName: true},
				{name: "EPERM", perfErr: unix.EPERM},
				{name: "EINVAL", perfErr: unix.EINVAL},
				{name: "ENOENT", perfErr: unix.ENOENT},
				{name: "tracefs failure", perfErr: unix.EACCES, traceErr: unix.EROFS, byName: true},
				{name: "ambiguous PMU symbol", perfErr: fmt.Errorf("opening perf event: %w", unix.EADDRNOTAVAIL), duplicates: true},
				{name: "duplicate attachment fails", perfErr: unix.EADDRNOTAVAIL, duplicateErr: unix.EACCES, duplicates: true},
				{name: "ambiguous tracefs symbol", perfErr: unix.EACCES, traceErr: fmt.Errorf("creating event: %w", unix.EADDRNOTAVAIL), byName: true, duplicates: true},
				{name: "all attempts fail", perfErr: unix.EACCES, traceErr: unix.EADDRNOTAVAIL, duplicateErr: unix.EROFS, byName: true, duplicates: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					fallbackUsed.Store(false)
					t.Cleanup(func() { fallbackUsed.Store(false) })
					want := &nopCloser{}
					var calls []string
					attempt := func(name string, err error) func() (io.Closer, error) {
						return func() (io.Closer, error) {
							calls = append(calls, name)
							if err != nil {
								return nil, err
							}
							return want, nil
						}
					}
					got, err := WithFallback(kind, AttachFuncs[io.Closer]{
						PMU:               attempt("PMU", tc.perfErr),
						TraceFS:           attempt("tracefs", tc.traceErr),
						TraceFSDuplicates: attempt("duplicates", tc.duplicateErr),
					})
					wantCalls := []string{"PMU"}
					lastErr := tc.perfErr
					if tc.byName {
						wantCalls = append(wantCalls, "tracefs")
						lastErr = tc.traceErr
					}
					if tc.duplicates && kind == Kprobe {
						wantCalls = append(wantCalls, "duplicates")
						lastErr = tc.duplicateErr
					}
					assert.Equal(t, wantCalls, calls)
					if lastErr == nil {
						require.NoError(t, err)
						assert.Same(t, want, got)
					} else {
						require.ErrorIs(t, err, lastErr)
						require.ErrorIs(t, err, tc.perfErr)
						if tc.byName && tc.traceErr != nil {
							require.ErrorIs(t, err, tc.traceErr)
						}
						assert.Nil(t, got)
					}
					used := len(wantCalls) > 1 && lastErr == nil
					timeout := 10 * time.Second
					if used {
						timeout *= 3
					}
					assert.Equal(t, used, fallbackUsed.Load())
					assert.Equal(t, timeout, EffectiveShutdownTimeout(10*time.Second))
				})
			}
		})
	}
}
