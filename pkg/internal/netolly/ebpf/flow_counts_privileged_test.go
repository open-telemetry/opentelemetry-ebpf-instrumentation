// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
)

const (
	concurrentPayload = 64
	// Ethernet + IPv4 + UDP + payload
	concurrentWireSize = 14 + 20 + 8 + concurrentPayload
	concurrentSenders  = 4
	concurrentDuration = 2 * time.Second
	// much shorter than any real export period, so that reads often race with the programs
	concurrentReadPeriod = 100 * time.Millisecond
	// A packet the programs add between the reader copying an entry and deleting it is lost, in
	// full or, when the copy catches the program halfway through updating the entry, in part. The
	// batch reader copies and deletes in one system call and loses a few hundredths of a percent at
	// most. The legacy reader uses two, and loses more the slower it runs: up to about 1.5% when the
	// test runs in an emulated VM.
	batchMaxLoss  = 0.005
	legacyMaxLoss = 0.03
	// UNKNOWN in bpf/netolly/flows_common.h: the direction of a UDP flow when port guessing is off
	directionUnknown = 255
)

var concurrentCases = []struct {
	name    string
	reader  config.EBPFMapReader
	maxLoss float64
	// the flows map as created on kernels that keep stale per-CPU values in reused elements
	noPrealloc bool
}{
	{"batch", config.MapReaderBatch, batchMaxLoss, false},
	{"legacy", config.MapReaderLegacy, legacyMaxLoss, false},
	{"batch-no-prealloc", config.MapReaderBatch, batchMaxLoss, true},
	{"legacy-no-prealloc", config.MapReaderLegacy, legacyMaxLoss, true},
}

func TestConcurrentFlowCounts_SocketFilter(t *testing.T) {
	for _, c := range concurrentCases {
		t.Run(c.name, func(t *testing.T) {
			if rerunInNewNetNS(t) {
				return
			}
			setUpLoopback(t)
			forceNoPrealloc(t, c.noPrealloc)
			// loopback hands every packet to the socket twice, as it is sent and as it is received,
			// and both copies have the same flow key
			assertConcurrentFlowCounts(t, newSockFetcher(t, c.reader), 2, c.maxLoss)
		})
	}
}

func TestConcurrentFlowCounts_TC(t *testing.T) {
	for _, c := range concurrentCases {
		t.Run(c.name, func(t *testing.T) {
			if rerunInNewNetNS(t) {
				return
			}
			setUpLoopback(t)
			forceNoPrealloc(t, c.noPrealloc)
			assertConcurrentFlowCounts(t, newTCFetcher(t, false, true, c.reader), 1, c.maxLoss)
		})
	}
}

// makes the fetchers create the flows map as they do on kernels that keep stale per-CPU values,
// whatever this kernel does
func forceNoPrealloc(t *testing.T, force bool) {
	if !force {
		return
	}
	probed := reusedSlotsStale
	reusedSlotsStale = func() bool { return true }
	t.Cleanup(func() { reusedSlotsStale = probed })
}

func TestReusedSlotsProbe(t *testing.T) {
	// the fetchers do this before probing: kernels before 5.11 charge maps to RLIMIT_MEMLOCK
	require.NoError(t, rlimit.RemoveMemlock())
	stale, err := probeReusedSlotsStale()
	require.NoError(t, err)
	t.Logf("kernel keeps stale per-CPU values in reused map elements: %v", stale)
	// the answer must not depend on the CPUs the probing thread runs on
	for range 50 {
		again, err := probeReusedSlotsStale()
		require.NoError(t, err)
		require.Equal(t, stale, again)
	}
}

// sends one UDP flow from several CPUs at once while the map is read and emptied every few
// milliseconds, and checks that the CPUs raced to insert the flow, and that no packet is counted
// twice and almost none are lost, for each copy the hooks see
func assertConcurrentFlowCounts(t *testing.T, fetcher *flowFetcher, copies uint64, maxLoss float64) {
	cpus := sendingCPUs(t)

	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	require.NoError(t, err)
	t.Cleanup(func() { srv.Close() })
	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, srv.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	raw, err := client.SyscallConn()
	require.NoError(t, err)
	clientPort := uint16(client.LocalAddr().(*net.UDPAddr).Port)
	serverPort := uint16(srv.LocalAddr().(*net.UDPAddr).Port)

	var packets, bytes uint64
	var directions []uint8
	collect := func() {
		for id, m := range fetcher.LookupAndDeleteMap() {
			if id.SrcPort == clientPort && id.DstPort == serverPort {
				packets += uint64(m.Packets)
				bytes += m.Bytes
				directions = append(directions, m.IfaceDirection)
			}
		}
	}

	stopReading := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		ticker := time.NewTicker(concurrentReadPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-stopReading:
				return
			case <-ticker.C:
				collect()
			}
		}
	}()

	var sent atomic.Uint64
	var wg sync.WaitGroup
	deadline := time.Now().Add(concurrentDuration)
	payload := make([]byte, concurrentPayload)
	for _, cpu := range cpus {
		wg.Go(func() {
			// the hooks run on the sending CPU, so each sender writes its own per-CPU slot
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var set unix.CPUSet
			set.Set(cpu)
			if err := unix.SchedSetaffinity(0, &set); err != nil {
				t.Errorf("pinning sender to CPU %d: %v", cpu, err)
				return
			}
			for time.Now().Before(deadline) {
				// straight to the system call: client.Write would serialize the senders on the
				// socket's write lock, and the programs would never see the flow on two CPUs at once
				var werr error
				if err := raw.Control(func(fd uintptr) {
					_, werr = unix.Write(int(fd), payload)
				}); err == nil && werr == nil {
					sent.Add(1)
				}
			}
		})
	}
	wg.Wait()
	close(stopReading)
	<-readerDone
	collect()

	want := sent.Load()
	collisions := fetcher.ringBufRecords(unix.EEXIST)
	t.Logf("%d CPUs sent %d packets; counted %d packets, %d bytes; %d insertion collisions",
		len(cpus), want, packets, bytes, collisions)
	require.Positive(t, want)
	// each read deletes the entry, and the next packets the CPUs send race to insert it again
	assert.Positive(t, collisions, "no packet went through the ring buffer because another CPU inserted its flow first")
	assert.LessOrEqual(t, packets, copies*want, "packets counted twice")
	assert.InEpsilon(t, float64(copies*want), float64(packets), maxLoss, "packets lost")
	assert.LessOrEqual(t, bytes, copies*want*concurrentWireSize, "bytes counted twice")
	assert.InEpsilon(t, float64(copies*want*concurrentWireSize), float64(bytes), maxLoss, "bytes lost")
	// the direction comes from the CPU that created each entry, not from another CPU's slot of it
	for _, d := range directions {
		assert.EqualValues(t, directionUnknown, d, "flow direction")
	}
}

func sendingCPUs(t *testing.T) []int {
	var allowed unix.CPUSet
	require.NoError(t, unix.SchedGetaffinity(0, &allowed))
	var cpus []int
	for cpu := 0; cpu < 1024 && len(cpus) < concurrentSenders; cpu++ {
		if allowed.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) < 2 {
		t.Skip("needs at least 2 CPUs to send from")
	}
	return cpus
}

// ringBufRecords returns how many records the programs sent through the ring buffer because inserting
// into the map failed with errno
func (f *flowFetcher) ringBufRecords(errno unix.Errno) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ringBufErrnos[uint8(errno)]
}
