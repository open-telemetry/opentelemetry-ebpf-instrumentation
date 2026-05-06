// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/export"
)

func TestFixupSpec(t *testing.T) {
	const origKpName = "real_kp"
	const origTpName = "real_tp"

	makeSpec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				progObiKprobeTCPCloseSrtt:         {Name: origKpName, Type: ebpf.Kprobe},
				progObiTracepointInetSockSetState: {Name: origTpName, Type: ebpf.TracePoint},
			},
		}
	}

	tests := []struct {
		name       string
		features   export.Features
		wantKpName string
		wantTpName string
	}{
		{
			name:       "all disabled",
			features:   export.Features(0),
			wantKpName: "stats_dummy_kp",
			wantTpName: "stats_dummy_tp",
		},
		{
			name:       "rtt only",
			features:   export.FeatureStatsTCPRtt,
			wantKpName: origKpName,
			wantTpName: "stats_dummy_tp",
		},
		{
			name:       "failed connections only",
			features:   export.FeatureStatsTCPFailedConnections,
			wantKpName: "stats_dummy_kp",
			wantTpName: origTpName,
		},
		{
			name:       "all enabled",
			features:   export.FeatureStats,
			wantKpName: origKpName,
			wantTpName: origTpName,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := makeSpec()
			fixupSpec(spec, &tc.features)
			if got := spec.Programs[progObiKprobeTCPCloseSrtt].Name; got != tc.wantKpName {
				t.Errorf("kprobe program: got %q, want %q", got, tc.wantKpName)
			}
			if got := spec.Programs[progObiTracepointInetSockSetState].Name; got != tc.wantTpName {
				t.Errorf("tracepoint program: got %q, want %q", got, tc.wantTpName)
			}
		})
	}
}

// TestTracepointConstantFormat validates that all tracepoint constants are in group/name format.
// When adding a new tracepoint constant, add it to the hooks slice below.
func TestTracepointConstantFormat(t *testing.T) {
	hooks := []string{
		TracepointInetSockSetState,
	}
	for _, hook := range hooks {
		if _, _, ok := strings.Cut(hook, "/"); !ok {
			t.Errorf("tracepoint constant %q is not in group/name format", hook)
		}
	}
}
