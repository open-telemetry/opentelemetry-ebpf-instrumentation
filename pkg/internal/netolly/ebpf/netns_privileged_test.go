// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tcmanager"
	"go.opentelemetry.io/obi/pkg/netolly/flowdef"
)

const (
	inNetNSEnv = "OBI_NETOLLY_TEST_IN_NETNS"
	// a 1500-byte MTU makes TCP send TSO skbs over loopback, which keeps them merged
	loopbackMTU = 1500
)

// flowFetcher reads the flows of a fetcher as the agent does: those in its map, plus those the programs
// send through the ring buffer when they can't insert them into the map
type flowFetcher struct {
	fetcher interface {
		LookupAndDeleteMap() map[NetFlowId]*NetFlowMetrics
		ReadRingBuf() (ringbuf.Record, error)
	}
	readerDone chan struct{}

	mu            sync.Mutex
	ringBufFlows  []NetFlowRecordT
	lastRingBufAt time.Time
	// ring buffer records by the errno of the failed map insertion
	ringBufErrnos map[uint8]int
}

func newFlowFetcher(t *testing.T, fetcher interface {
	LookupAndDeleteMap() map[NetFlowId]*NetFlowMetrics
	ReadRingBuf() (ringbuf.Record, error)
	Close() error
},
) *flowFetcher {
	f := &flowFetcher{fetcher: fetcher, readerDone: make(chan struct{}), ringBufErrnos: map[uint8]int{}}
	go func() {
		defer close(f.readerDone)
		for {
			// fails once the fetcher is closed
			rec, err := fetcher.ReadRingBuf()
			if err != nil {
				return
			}
			flow, err := ReadFrom(bytes.NewReader(rec.RawSample))
			if err != nil {
				t.Errorf("parsing ring buffer record: %v", err)
				return
			}
			f.mu.Lock()
			f.ringBufFlows = append(f.ringBufFlows, flow)
			f.ringBufErrnos[flow.Metrics.Errno]++
			f.lastRingBufAt = time.Now()
			f.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		fetcher.Close()
		<-f.readerDone
	})
	return f
}

// LookupAndDeleteMap returns the flows read from the map and from the ring buffer since the last call
func (f *flowFetcher) LookupAndDeleteMap() map[NetFlowId]*NetFlowMetrics {
	flows := f.fetcher.LookupAndDeleteMap()
	// lets the reader catch up with the records the programs sent before the map was read
	for {
		f.mu.Lock()
		idle := time.Since(f.lastRingBufAt) > 10*time.Millisecond
		if idle {
			for i := range f.ringBufFlows {
				rf := &f.ringBufFlows[i]
				if stored, ok := flows[rf.Id]; ok {
					stored.Accumulate(&rf.Metrics)
				} else {
					flows[rf.Id] = &rf.Metrics
				}
			}
			f.ringBufFlows = nil
		}
		f.mu.Unlock()
		if idle {
			return flows
		}
		time.Sleep(time.Millisecond)
	}
}

// reruns the test in a network namespace of its own, so it can change the loopback MTU and attach
// to loopback without touching the host. Returns false in that rerun, where the test does its work.
func rerunInNewNetNS(t *testing.T) bool {
	if os.Getenv(inNetNSEnv) != "" {
		return false
	}
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")

	// -test.run matches each level of a subtest name separately, so each one is anchored on its own
	levels := strings.Split(t.Name(), "/")
	for i, level := range levels {
		levels[i] = "^" + regexp.QuoteMeta(level) + "$"
	}
	cmd := exec.Command(os.Args[0], "-test.run="+strings.Join(levels, "/"), "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), inNetNSEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	require.NoError(t, err)
	return true
}

func setUpLoopback(t *testing.T) {
	lo, err := netlink.LinkByName("lo")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetMTU(lo, loopbackMTU))
	require.NoError(t, netlink.LinkSetUp(lo))
}

func newSockFetcher(t *testing.T, reader config.EBPFMapReader) *flowFetcher {
	sockFetcher, err := NewSockFlowFetcher(0, 1000, flowdef.PortGuessDisable,
		&config.EBPFTracer{ForceBPFMapReader: reader})
	require.NoError(t, err)
	fetcher := newFlowFetcher(t, sockFetcher)
	waitUntilCounting(t, fetcher)
	return fetcher
}

func newTCFetcher(t *testing.T, ingress, egress bool, reader config.EBPFMapReader) *flowFetcher {
	ifaceManager := tcmanager.NewInterfaceManager()
	tcFetcher, err := NewFlowFetcher(0, 1000, ingress, egress, ifaceManager, flowdef.PortGuessDisable,
		&config.EBPFTracer{TCBackend: config.TCBackendAuto, ForceBPFMapReader: reader})
	require.NoError(t, err)
	fetcher := newFlowFetcher(t, tcFetcher)

	// started after the fetcher registers its programs, as the agent does: the netlink backend
	// only attaches to interfaces reported after that
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ifaceManager.Start(ctx)
	waitUntilCounting(t, fetcher)
	return fetcher
}

// waits until the fetcher counts loopback traffic (the TC programs are attached asynchronously,
// when the interface manager reports the interface) and leaves its map empty
func waitUntilCounting(t *testing.T, fetcher *flowFetcher) {
	ln, err := net.Listen("tcp4", "127.0.0.2:0")
	require.NoError(t, err)
	defer ln.Close()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		conn, err := loopbackDialer.Dial("tcp4", ln.Addr().String())
		if !assert.NoError(ct, err) {
			return
		}
		conn.Close()
		srv, err := ln.Accept()
		if assert.NoError(ct, err) {
			srv.Close()
		}
		assert.NotEmpty(ct, fetcher.LookupAndDeleteMap())
	}, 10*time.Second, 100*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	fetcher.LookupAndDeleteMap()
}

// the programs ignore flows whose source and destination IPs are equal, so tests connect from
// 127.0.0.1 to 127.0.0.2
var loopbackDialer = net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}
