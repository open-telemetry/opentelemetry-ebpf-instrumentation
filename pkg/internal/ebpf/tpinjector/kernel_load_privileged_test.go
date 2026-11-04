// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"errors"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestSKMsgCompatibilityPrograms(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())
	cfg := obi.DefaultConfig
	cfg.EBPF.TrackRequestHeaders = true
	require.NoError(t, cfg.EBPF.ContextPropagation.UnmarshalText([]byte("headers")))
	cfg.EBPF.BufferSizes.HTTP = 262144
	cfg.EBPF.BufferSizes.TCP = 65536
	tracer := New(&cfg, nil)
	tracer.fionreadProbe = func(*ebpf.Map) (bool, error) { return false, nil }
	bundles, err := tracer.LoadSpecs()
	require.NoError(t, err)
	template := bundles[0].Spec
	require.NoError(t, ebpfconvenience.RewriteConstants(template, bundles[0].Constants))
	for _, name := range slices.Sorted(maps.Keys(template.Programs)) {
		t.Run(name, func(t *testing.T) {
			spec := template.Copy()
			for program := range spec.Programs {
				if program != name {
					delete(spec.Programs, program)
				}
			}
			for _, m := range spec.Maps {
				m.Pinning = ebpf.PinNone
				if m.Type == ebpf.ProgramArray {
					m.Contents = nil
				}
				if m.MaxEntries == 0 && m.Type == ebpf.RingBuf {
					m.MaxEntries = uint32(os.Getpagesize())
				}
			}
			collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{LogSizeStart: 16 * 1024 * 1024},
			})
			if err != nil {
				if verifierError, ok := errors.AsType[*ebpf.VerifierError](err); ok {
					t.Fatalf("%s: %+v", name, verifierError)
				}
				t.Fatal(err)
			}
			collection.Close()
		})
	}
}
