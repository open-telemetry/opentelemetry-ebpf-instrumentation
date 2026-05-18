// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestFixupSpec(t *testing.T) {
	const origKpName = "real_kp"
	const origTpName = "real_tp"
	const origConnRoleName = "real_conn_role"

	makeSpec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				progObiKprobeTCPCloseSrtt:              {Name: origKpName, Type: ebpf.Kprobe},
				progObiTpInetSockSetStateTCPFailedConn: {Name: origTpName, Type: ebpf.TracePoint},
				progObiTpInetSockSetStateConnRole:      {Name: origConnRoleName, Type: ebpf.TracePoint},
			},
		}
	}

	tests := []struct {
		name      string
		toDisable []string
		want      map[string]string
	}{
		{
			name:      "disable nothing",
			toDisable: nil,
			want: map[string]string{
				progObiKprobeTCPCloseSrtt:              origKpName,
				progObiTpInetSockSetStateTCPFailedConn: origTpName,
				progObiTpInetSockSetStateConnRole:      origConnRoleName,
			},
		},
		{
			name:      "disable kprobe only",
			toDisable: []string{progObiKprobeTCPCloseSrtt},
			want: map[string]string{
				progObiKprobeTCPCloseSrtt:              "stats_dummy",
				progObiTpInetSockSetStateTCPFailedConn: origTpName,
				progObiTpInetSockSetStateConnRole:      origConnRoleName,
			},
		},
		{
			name:      "disable failed conn only",
			toDisable: []string{progObiTpInetSockSetStateTCPFailedConn},
			want: map[string]string{
				progObiKprobeTCPCloseSrtt:              origKpName,
				progObiTpInetSockSetStateTCPFailedConn: "stats_dummy",
				progObiTpInetSockSetStateConnRole:      origConnRoleName,
			},
		},
		{
			name:      "disable conn role only",
			toDisable: []string{progObiTpInetSockSetStateConnRole},
			want: map[string]string{
				progObiKprobeTCPCloseSrtt:              origKpName,
				progObiTpInetSockSetStateTCPFailedConn: origTpName,
				progObiTpInetSockSetStateConnRole:      "stats_dummy",
			},
		},
		{
			name: "disable all",
			toDisable: []string{
				progObiKprobeTCPCloseSrtt,
				progObiTpInetSockSetStateTCPFailedConn,
				progObiTpInetSockSetStateConnRole,
			},
			want: map[string]string{
				progObiKprobeTCPCloseSrtt:              "stats_dummy",
				progObiTpInetSockSetStateTCPFailedConn: "stats_dummy",
				progObiTpInetSockSetStateConnRole:      "stats_dummy",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := makeSpec()
			if err := fixupSpec(spec, tc.toDisable); err != nil {
				t.Fatalf("fixupSpec: %v", err)
			}
			for prog, wantName := range tc.want {
				if got := spec.Programs[prog].Name; got != wantName {
					t.Errorf("program %s: got %q, want %q", prog, got, wantName)
				}
			}
		})
	}
}

func TestFixupSpecUnknownProgram(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			progObiKprobeTCPCloseSrtt: {Name: "real_kp", Type: ebpf.Kprobe},
		},
	}
	if err := fixupSpec(spec, []string{"nonexistent_prog"}); err == nil {
		t.Error("expected error for unknown program name, got nil")
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
