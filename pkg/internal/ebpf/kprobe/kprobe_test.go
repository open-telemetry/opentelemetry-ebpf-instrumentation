// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"
)

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func restoreAttachments(t *testing.T) {
	t.Helper()
	pmu, trace := attachPMU, attachTraceFSEvent
	t.Cleanup(func() {
		attachPMU, attachTraceFSEvent = pmu, trace
	})
}

func TestAttach(t *testing.T) {
	for _, ret := range []bool{false, true} {
		for _, tc := range []struct {
			name             string
			pmuErr, traceErr error
			fallback         bool
		}{
			{name: "PMU success"},
			{name: "EACCES", pmuErr: fmt.Errorf("opening perf event: %w", unix.EACCES), fallback: true},
			{name: "EPERM", pmuErr: unix.EPERM},
			{name: "EINVAL", pmuErr: unix.EINVAL},
			{name: "ENOENT", pmuErr: unix.ENOENT},
			{name: "fallback failure", pmuErr: unix.EACCES, traceErr: unix.EROFS, fallback: true},
		} {
			t.Run(fmt.Sprintf("%s/return=%t", tc.name, ret), func(t *testing.T) {
				restoreAttachments(t)
				prog := &ebpf.Program{}
				want := &nopCloser{}
				pmuCalls, traceCalls := 0, 0
				attachPMU = func(symbol string, got *ebpf.Program, gotRet bool) (io.Closer, error) {
					pmuCalls++
					assert.Equal(t, "tcp_sendmsg", symbol)
					assert.Same(t, prog, got)
					assert.Equal(t, ret, gotRet)
					if tc.pmuErr != nil {
						return nil, tc.pmuErr
					}
					return want, nil
				}
				attachTraceFSEvent = func(got *ebpf.Program, opts tracefs.Options) (io.Closer, error) {
					traceCalls++
					assert.Same(t, prog, got)
					assert.Equal(t, tracefs.Options{Type: tracefs.Kprobe, Targets: []string{"tcp_sendmsg"}, Return: ret}, opts)
					if tc.traceErr != nil {
						return nil, tc.traceErr
					}
					return want, nil
				}

				got, err := Attach("tcp_sendmsg", prog, ret)
				assert.Equal(t, 1, pmuCalls)
				if tc.fallback {
					assert.Equal(t, 1, traceCalls)
				} else {
					assert.Zero(t, traceCalls)
				}
				if tc.pmuErr == nil || (tc.fallback && tc.traceErr == nil) {
					require.NoError(t, err)
					assert.Same(t, want, got)
				} else {
					require.ErrorIs(t, err, tc.pmuErr)
					if tc.traceErr != nil {
						require.ErrorIs(t, err, tc.traceErr)
					}
					assert.Nil(t, got)
				}
			})
		}
	}
}

func TestTraceFSRetrySyscallPrefix(t *testing.T) {
	require.NotEmpty(t, syscallPrefix(), "OBI supports amd64 and arm64")
	for _, ret := range []bool{false, true} {
		for _, firstErr := range []error{unix.ENOENT, unix.EINVAL, unix.EACCES, unix.EPERM} {
			t.Run(fmt.Sprintf("%s/return=%t", firstErr, ret), func(t *testing.T) {
				restoreAttachments(t)
				var targets []string
				want := &nopCloser{}
				attachTraceFSEvent = func(_ *ebpf.Program, opts tracefs.Options) (io.Closer, error) {
					assert.Equal(t, ret, opts.Return)
					targets = append(targets, opts.Targets...)
					if len(targets) == 1 {
						return nil, firstErr
					}
					return want, nil
				}

				got, err := attachTraceFS("sys_connect", nil, ret)
				if errors.Is(firstErr, unix.ENOENT) || errors.Is(firstErr, unix.EINVAL) {
					require.NoError(t, err)
					assert.Same(t, want, got)
					assert.Equal(t, []string{"sys_connect", syscallPrefix() + "sys_connect"}, targets)
				} else {
					require.ErrorIs(t, err, firstErr)
					assert.Nil(t, got)
					assert.Equal(t, []string{"sys_connect"}, targets)
				}
			})
		}
	}
}
