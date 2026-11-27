// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe

import (
	"errors"
	"fmt"
	"io"
	"os"
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
	m := useTestMonitor(t)
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
				assert.Empty(t, m.probes)
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

func TestAttachResolvesAmbiguousTraceFSName(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"listener", unix.EADDRNOTAVAIL},
		{"listener", unix.EINVAL},
		{syscallPrefix() + "listener", unix.EINVAL},
	} {
		t.Run(fmt.Sprintf("%s/%v", tc.name, tc.err), func(t *testing.T) {
			restoreAttachments(t)
			m := useTestMonitor(t)
			base := "0010 T " + tc.name + "\n"
			require.NoError(t, os.WriteFile(m.kallsyms, []byte(base), 0o600))
			attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) { return nil, unix.EACCES }
			var attached []string
			attachTraceFSEvent = func(_ *ebpf.Program, opts tracefs.Options) (io.Closer, error) {
				target := opts.Targets[0]
				switch target {
				case tc.name:
					// The livepatch is visible when tracefs rejects this particular name.
					require.NoError(t, os.WriteFile(m.kallsyms, []byte(base+"0020 t "+tc.name+"\t[patch]\n"), 0o600))
					return nil, tc.err
				case "listener":
					return nil, unix.ENOENT
				}
				attached = append(attached, target)
				return &nopCloser{}, nil
			}

			probe, err := Attach("listener", nil, false)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, probe.Close()) })
			assert.Equal(t, []string{"0x10"}, attached)
			assert.Empty(t, m.probes)
		})
	}
}

func TestAttachPreservesUnambiguousTraceFSError(t *testing.T) {
	restoreAttachments(t)
	m := useTestMonitor(t)
	require.NoError(t, os.WriteFile(m.kallsyms, []byte("0010 T listener\n"), 0o600))
	attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) { return nil, unix.EACCES }
	invalid := fmt.Errorf("original name: %w", unix.EINVAL)
	missing := fmt.Errorf("prefixed name: %w", unix.ENOENT)
	attachTraceFSEvent = func(_ *ebpf.Program, opts tracefs.Options) (io.Closer, error) {
		switch opts.Targets[0] {
		case "listener":
			return nil, invalid
		case syscallPrefix() + "listener":
			return nil, missing
		}
		return &nopCloser{}, nil
	}

	probe, err := Attach("listener", nil, false)
	require.Nil(t, probe)
	require.ErrorIs(t, err, unix.EACCES)
	require.ErrorIs(t, err, invalid)
	require.ErrorIs(t, err, missing)
}

func TestTraceFSRetrySyscallPrefix(t *testing.T) {
	require.NotEmpty(t, syscallPrefix(), "OBI supports amd64 and arm64")
	m := useTestMonitor(t)
	require.NoError(t, os.Remove(m.patchDir))
	require.NoError(t, os.WriteFile(m.kallsyms, []byte("0010 T "+syscallPrefix()+"sys_connect\n"), 0o600))
	for _, ret := range []bool{false, true} {
		for _, firstErr := range []error{unix.ENOENT, unix.EINVAL, unix.EACCES, unix.EPERM} {
			t.Run(fmt.Sprintf("%s/return=%t", firstErr, ret), func(t *testing.T) {
				restoreAttachments(t)
				attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) { return nil, unix.EACCES }
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

				got, err := Attach("sys_connect", nil, ret)
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
