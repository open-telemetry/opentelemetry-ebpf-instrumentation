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

	const origSendmsgName = "real_sendmsg"
	const origRetprobeSendmsgName = "real_retprobe_sendmsg"
	const origCleanupRbufName = "real_cleanup_rbuf"

	makeSpec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				progObiStatsKprobeTCPClose:                        {Name: origKpName, Type: ebpf.Kprobe},
				progObiStatsTpInetSockSetStateTCPFailedConnection: {Name: origTpName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateConnRole:            {Name: origConnRoleName, Type: ebpf.TracePoint},
				progObiStatsKprobeTCPSendmsg:                      {Name: origSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKretprobeTCPSendmsg:                   {Name: origRetprobeSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCleanupRbuf:                  {Name: origCleanupRbufName, Type: ebpf.Kprobe},
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
				progObiStatsKprobeTCPClose:                        origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
			},
		},
		{
			name:      "disable kprobe only",
			toDisable: []string{progObiStatsKprobeTCPClose},
			want: map[string]string{
				progObiStatsKprobeTCPClose:                        "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
			},
		},
		{
			name:      "disable failed conn only",
			toDisable: []string{progObiStatsTpInetSockSetStateTCPFailedConnection},
			want: map[string]string{
				progObiStatsKprobeTCPClose:                        origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
			},
		},
		{
			name:      "disable conn role only",
			toDisable: []string{progObiStatsTpInetSockSetStateConnRole},
			want: map[string]string{
				progObiStatsKprobeTCPClose:                        origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            "stats_dummy",
			},
		},
		{
			name:      "disable io programs",
			toDisable: []string{progObiStatsKprobeTCPSendmsg, progObiStatsKretprobeTCPSendmsg, progObiStatsKprobeTCPCleanupRbuf},
			want: map[string]string{
				progObiStatsKprobeTCPClose:       origKpName,
				progObiStatsKprobeTCPSendmsg:     "stats_dummy",
				progObiStatsKretprobeTCPSendmsg:  "stats_dummy",
				progObiStatsKprobeTCPCleanupRbuf: "stats_dummy",
			},
		},
		{
			name: "disable all",
			toDisable: []string{
				progObiStatsKprobeTCPClose,
				progObiStatsTpInetSockSetStateTCPFailedConnection,
				progObiStatsTpInetSockSetStateConnRole,
				progObiStatsKprobeTCPSendmsg,
				progObiStatsKretprobeTCPSendmsg,
				progObiStatsKprobeTCPCleanupRbuf,
			},
			want: map[string]string{
				progObiStatsKprobeTCPClose:                        "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateConnRole:            "stats_dummy",
				progObiStatsKprobeTCPSendmsg:                      "stats_dummy",
				progObiStatsKretprobeTCPSendmsg:                   "stats_dummy",
				progObiStatsKprobeTCPCleanupRbuf:                  "stats_dummy",
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
			progObiStatsKprobeTCPClose: {Name: "real_kp", Type: ebpf.Kprobe},
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
