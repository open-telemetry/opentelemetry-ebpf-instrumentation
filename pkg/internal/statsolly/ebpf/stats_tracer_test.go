// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestFixupSpec(t *testing.T) {
	const origKpName = "real_kp"
	const origTpName = "real_tp"
	const origConnRoleName = "real_conn_role"
	const origSuccessTpName = "real_success_tp"

	const origSendmsgName = "real_sendmsg"
	const origRetprobeSendmsgName = "real_retprobe_sendmsg"
	const origRetprobeSendpagesName = "real_retprobe_sendpages"
	const origCleanupRbufName = "real_cleanup_rbuf"
	const origCloseIoFlushName = "real_close_io_flush"
	const origDestroySockName = "real_destroy_sock"
	const origRetransmitName = "real_retransmit"
	const origSendResetName = "real_send_reset"
	const origReceiveResetName = "real_receive_reset"
	const origRcvStateProcessName = "real_rcv_state_process"
	const origDestroySockSegRstName = "real_destroy_sock_seg_rst"

	makeSpec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				progObiStatsKprobeTCPCloseSrtt:                        {Name: origKpName, Type: ebpf.Kprobe},
				progObiStatsTpInetSockSetStateTCPFailedConnection:     {Name: origTpName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateConnRole:                {Name: origConnRoleName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: {Name: origSuccessTpName, Type: ebpf.TracePoint},
				progObiStatsKprobeTCPSend:                             {Name: origSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKretprobeTCPSendmsgLocked:                 {Name: origRetprobeSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKretprobeDoTCPSendpages:                   {Name: origRetprobeSendpagesName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCleanupRbuf:                      {Name: origCleanupRbufName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCloseIoFlush:                     {Name: origCloseIoFlushName, Type: ebpf.Kprobe},
				progObiStatsTpTCPDestroySock:                          {Name: origDestroySockName, Type: ebpf.TracePoint},
				progObiStatsRawTpTCPRetransmitSkb:                     {Name: origRetransmitName, Type: ebpf.RawTracepoint},
				progObiStatsRawTpTCPSendReset:                         {Name: origSendResetName, Type: ebpf.RawTracepoint},
				progObiStatsRawTpTCPReceiveReset:                      {Name: origReceiveResetName, Type: ebpf.RawTracepoint},
				progObiStatsKprobeTCPRcvStateProcess:                  {Name: origRcvStateProcessName, Type: ebpf.Kprobe},
				progObiStatsRawTpTCPDestroySockSegRst:                 {Name: origDestroySockSegRstName, Type: ebpf.RawTracepoint},
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
				progObiStatsKprobeTCPCloseSrtt:                        origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection:     origTpName,
				progObiStatsTpInetSockSetStateConnRole:                origConnRoleName,
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: origSuccessTpName,
				progObiStatsKprobeTCPSend:                             origSendmsgName,
				progObiStatsKretprobeTCPSendmsgLocked:                 origRetprobeSendmsgName,
				progObiStatsKretprobeDoTCPSendpages:                   origRetprobeSendpagesName,
				progObiStatsKprobeTCPCleanupRbuf:                      origCleanupRbufName,
				progObiStatsKprobeTCPCloseIoFlush:                     origCloseIoFlushName,
				progObiStatsTpTCPDestroySock:                          origDestroySockName,
				progObiStatsRawTpTCPRetransmitSkb:                     origRetransmitName,
				progObiStatsRawTpTCPSendReset:                         origSendResetName,
				progObiStatsRawTpTCPReceiveReset:                      origReceiveResetName,
				progObiStatsKprobeTCPRcvStateProcess:                  origRcvStateProcessName,
				progObiStatsRawTpTCPDestroySockSegRst:                 origDestroySockSegRstName,
			},
		},
		{
			// Regression: stats_tcp_io standalone (no stats_tcp_rtt) must still attach
			// the io_flush probe on tcp_close to avoid losing the final incomplete batch.
			name:      "disable srtt only",
			toDisable: []string{progObiStatsKprobeTCPCloseSrtt},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
				progObiStatsKprobeTCPCloseIoFlush:                 origCloseIoFlushName,
				progObiStatsKprobeTCPSend:                         origSendmsgName,
				progObiStatsKretprobeTCPSendmsgLocked:             origRetprobeSendmsgName,
				progObiStatsKprobeTCPCleanupRbuf:                  origCleanupRbufName,
				progObiStatsRawTpTCPRetransmitSkb:                 origRetransmitName,
			},
		},
		{
			name:      "disable retransmits only",
			toDisable: []string{progObiStatsRawTpTCPRetransmitSkb},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
				progObiStatsRawTpTCPRetransmitSkb:                 "stats_dummy",
			},
		},
		{
			name:      "disable failed conn only",
			toDisable: []string{progObiStatsTpInetSockSetStateTCPFailedConnection},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
			},
		},
		{
			name:      "disable successful conn only",
			toDisable: []string{progObiStatsTpInetSockSetStateTCPSuccessfulConnection},
			want: map[string]string{
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection:     origTpName,
				progObiStatsTpInetSockSetStateConnRole:                origConnRoleName,
			},
		},
		{
			name:      "disable resets only",
			toDisable: []string{progObiStatsRawTpTCPSendReset, progObiStatsRawTpTCPReceiveReset, progObiStatsKprobeTCPRcvStateProcess, progObiStatsRawTpTCPDestroySockSegRst},
			want: map[string]string{
				progObiStatsRawTpTCPSendReset:         "stats_dummy",
				progObiStatsRawTpTCPReceiveReset:      "stats_dummy",
				progObiStatsKprobeTCPRcvStateProcess:  "stats_dummy",
				progObiStatsRawTpTCPDestroySockSegRst: "stats_dummy",
				progObiStatsRawTpTCPRetransmitSkb:     origRetransmitName,
			},
		},
		{
			name:      "disable conn role only",
			toDisable: []string{progObiStatsTpInetSockSetStateConnRole},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            "stats_dummy",
			},
		},
		{
			name:      "disable io programs",
			toDisable: []string{progObiStatsKprobeTCPSend, progObiStatsKretprobeTCPSendmsgLocked, progObiStatsKretprobeDoTCPSendpages, progObiStatsKprobeTCPCleanupRbuf, progObiStatsKprobeTCPCloseIoFlush},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:        origKpName,
				progObiStatsKprobeTCPSend:             "stats_dummy",
				progObiStatsKretprobeTCPSendmsgLocked: "stats_dummy",
				progObiStatsKretprobeDoTCPSendpages:   "stats_dummy",
				progObiStatsKprobeTCPCleanupRbuf:      "stats_dummy",
				progObiStatsKprobeTCPCloseIoFlush:     "stats_dummy",
			},
		},
		{
			name: "disable all",
			toDisable: []string{
				progObiStatsKprobeTCPCloseSrtt,
				progObiStatsTpInetSockSetStateTCPFailedConnection,
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection,
				progObiStatsTpInetSockSetStateConnRole,
				progObiStatsKprobeTCPSend,
				progObiStatsKretprobeTCPSendmsgLocked,
				progObiStatsKretprobeDoTCPSendpages,
				progObiStatsKprobeTCPCleanupRbuf,
				progObiStatsKprobeTCPCloseIoFlush,
				progObiStatsTpTCPDestroySock,
				progObiStatsRawTpTCPRetransmitSkb,
				progObiStatsRawTpTCPSendReset,
				progObiStatsRawTpTCPReceiveReset,
				progObiStatsKprobeTCPRcvStateProcess,
				progObiStatsRawTpTCPDestroySockSegRst,
			},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                        "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection:     "stats_dummy",
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateConnRole:                "stats_dummy",
				progObiStatsKprobeTCPSend:                             "stats_dummy",
				progObiStatsKretprobeTCPSendmsgLocked:                 "stats_dummy",
				progObiStatsKretprobeDoTCPSendpages:                   "stats_dummy",
				progObiStatsKprobeTCPCleanupRbuf:                      "stats_dummy",
				progObiStatsKprobeTCPCloseIoFlush:                     "stats_dummy",
				progObiStatsTpTCPDestroySock:                          "stats_dummy",
				progObiStatsRawTpTCPRetransmitSkb:                     "stats_dummy",
				progObiStatsRawTpTCPSendReset:                         "stats_dummy",
				progObiStatsRawTpTCPReceiveReset:                      "stats_dummy",
				progObiStatsKprobeTCPRcvStateProcess:                  "stats_dummy",
				progObiStatsRawTpTCPDestroySockSegRst:                 "stats_dummy",
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
			progObiStatsKprobeTCPCloseSrtt: {Name: "real_kp", Type: ebpf.Kprobe},
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
		TracepointTCPDestroySock,
	}
	for _, hook := range hooks {
		if _, _, ok := strings.Cut(hook, "/"); !ok {
			t.Errorf("tracepoint constant %q is not in group/name format", hook)
		}
	}
}

type closeCounter struct{ closes int }

func (c *closeCounter) Close() error {
	c.closes++
	return nil
}

func TestAttachDoTCPSendPages(t *testing.T) {
	origKernelVersion, origAttachKprobe := kernelVersion, attachKprobe
	t.Cleanup(func() {
		kernelVersion, attachKprobe = origKernelVersion, origAttachKprobe
	})

	type attachCall struct {
		program *ebpf.Program
		ret     bool
	}

	entry, ret := &ebpf.Program{}, &ebpf.Program{}
	objects := &StatsObjects{StatsPrograms: StatsPrograms{
		ObiStatsKprobeTcpSend:           entry,
		ObiStatsKretprobeDoTcpSendpages: ret,
	}}
	bothCalls := []attachCall{{program: ret, ret: true}, {program: entry}}

	tests := []struct {
		name         string
		major, minor int
		failOn       *ebpf.Program
		wantCalls    []attachCall
		wantLinks    int
		wantCloses   int
	}{
		{name: "skipped on 6.5", major: 6, minor: 5},
		{name: "skipped on 7.0", major: 7},
		{name: "both attached on 6.4", major: 6, minor: 4, wantCalls: bothCalls, wantLinks: 2},
		{name: "both attached on 5.8", major: 5, minor: 8, wantCalls: bothCalls, wantLinks: 2},
		{name: "return probe closed when the entry probe fails", major: 6, minor: 4, failOn: entry, wantCalls: bothCalls, wantCloses: 1},
		{name: "entry probe not attached when the return probe fails", major: 6, minor: 4, failOn: ret, wantCalls: bothCalls[:1]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kernelVersion = func() (int, int) { return tc.major, tc.minor }

			var calls []attachCall
			link := &closeCounter{}
			attachKprobe = func(symbol string, program *ebpf.Program, ret bool) (io.Closer, error) {
				if symbol != KprobeDoTCPSendPages {
					t.Errorf("attached to %q, want %q", symbol, KprobeDoTCPSendPages)
				}
				calls = append(calls, attachCall{program: program, ret: ret})
				if program == tc.failOn {
					return nil, errors.New("attach failed")
				}
				return link, nil
			}

			links := attachDoTCPSendPages(slog.New(slog.DiscardHandler), objects)

			if !slices.Equal(calls, tc.wantCalls) {
				t.Errorf("attach calls: got %v, want %v", calls, tc.wantCalls)
			}
			if len(links) != tc.wantLinks {
				t.Errorf("links: got %d, want %d", len(links), tc.wantLinks)
			}
			if link.closes != tc.wantCloses {
				t.Errorf("closes: got %d, want %d", link.closes, tc.wantCloses)
			}
		})
	}
}
