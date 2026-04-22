// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tcmanager

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestTCXManagerVethRaceENODEV exercises the production failure
//
//	level=ERROR msg="Error attaching tcx" component=tcx_manager
//	            error="attach tcx link: no such device"
//
// by creating and tearing down veth pairs faster than the netlink
// watcher → InterfaceManager → TCXManager pipeline can attach a TCX
// program. The watcher emits EventAdded as soon as IFF_UP|IFF_RUNNING
// flags appear; if the link is removed before the AttachTCX syscall
// reaches the kernel, the kernel returns ENODEV. tcxManager currently
// only treats EEXIST as benign, so ENODEV ends up on Errors().
//
// This test asserts the *desired* post-fix behaviour: zero
// ENODEV-on-attach errors should escape to TCXManager.Errors(). It is
// expected to FAIL against main — that failure is the discussion
// point. A fix likely needs both ENODEV demotion and a bounded retry
// (the netlink watcher dedupes on (name, ifindex) and will not
// re-emit EventAdded for an interface that survives the race), e.g.
// mirroring doIgnoreNoDev (netlinkmanager.go) on the attach side and
// scheduling a short backoff retry guarded by a name+ifindex check.
func TestTCXManagerVethRaceENODEV(t *testing.T) {
	progs := loadProgs(t)

	im := NewInterfaceManager()
	tcx := NewTCXManager()
	tcx.SetInterfaceManager(im)

	// MonitorWatch (the default) is the netlink path that fails in
	// production. Bigger buffer than default so a burst of events
	// can't block the netlink reader.
	im.SetChannelBufferLen(1024)

	im.Start(t.Context())

	// Drain the error channel. tcxManager.errorCh is unbuffered and
	// emitError blocks on it (tcxmanager.go), so without a reader
	// the manager would deadlock on the first failure.
	var (
		errMu  sync.Mutex
		errs   []error
		drainW sync.WaitGroup
	)
	drainW.Add(1)
	go func() {
		defer drainW.Done()
		for err := range tcx.Errors() {
			errMu.Lock()
			errs = append(errs, err)
			errMu.Unlock()
		}
	}()

	tcx.AddProgram("obi_ingress", progs.Ingress, AttachmentIngress)

	// Track every veth name we create so we can clean up survivors.
	var (
		createdMu sync.Mutex
		created   []string
	)
	addCreated := func(name string) {
		createdMu.Lock()
		created = append(created, name)
		createdMu.Unlock()
	}

	const (
		workers           = 4
		iterationsPerWork = 100
	)
	var counter atomic.Uint32

	var workW sync.WaitGroup
	for w := 0; w < workers; w++ {
		workW.Add(1)
		go func() {
			defer workW.Done()
			for i := 0; i < iterationsPerWork; i++ {
				// IFNAMSIZ = 16, including NUL → 15 char ceiling.
				n := counter.Add(1)
				name := fmt.Sprintf("tcxr-%x", n)
				peer := fmt.Sprintf("tcxr-p%x", n)

				veth := &netlink.Veth{
					LinkAttrs: netlink.LinkAttrs{Name: name},
					PeerName:  peer,
				}
				if err := netlink.LinkAdd(veth); err != nil {
					// EEXIST is fine, anything else is unexpected.
					if !errors.Is(err, unix.EEXIST) {
						t.Errorf("LinkAdd %s: %v", name, err)
						return
					}
					continue
				}
				addCreated(name)

				link, err := netlink.LinkByName(name)
				if err != nil {
					// Already gone — this iteration just produced
					// extra churn; keep going.
					continue
				}

				if err := netlink.LinkSetUp(link); err != nil {
					// ENODEV here just means the race already won;
					// don't fail the test on it.
					if !errors.Is(err, unix.ENODEV) {
						t.Logf("LinkSetUp %s: %v", name, err)
					}
					continue
				}

				// Race the watcher → AttachTCX path. Jitter spans
				// "almost immediately" (smaller than typical netlink
				// dispatch latency) up to ~500µs (long enough for
				// some attaches to land, exercising the success path
				// and the failure path).
				delay := time.Duration(rand.IntN(500)) * time.Microsecond
				time.AfterFunc(delay, func() {
					_ = netlink.LinkDel(link)
				})
			}
		}()
	}

	workW.Wait()

	// Give the watcher / InterfaceManager / TCXManager pipeline time
	// to drain any backlog of EventAdded events for veths that have
	// already been deleted — this is where ENODEV bubbles up.
	time.Sleep(2 * time.Second)

	// Stop producing further errors and shut things down so the
	// drain goroutine can return.
	tcx.Shutdown()
	im.Stop()
	im.Wait()
	drainW.Wait()

	// Best-effort cleanup of any veths the deferred LinkDel didn't
	// catch (e.g. deletes that landed before SetUp, or panicked
	// timers).
	createdMu.Lock()
	survivors := append([]string(nil), created...)
	createdMu.Unlock()
	for _, n := range survivors {
		if l, err := netlink.LinkByName(n); err == nil {
			_ = netlink.LinkDel(l)
		}
	}

	// Inspect collected errors. We want at least one that matches
	// the production message: "Error attaching tcx" wrapping ENODEV
	// ("no such device").
	errMu.Lock()
	defer errMu.Unlock()

	var matched int
	for _, err := range errs {
		s := err.Error()
		if strings.Contains(s, "Error attaching tcx") &&
			strings.Contains(s, "no such device") {
			matched++
		}
	}

	t.Logf("collected %d errors from tcx.Errors(); %d match the ENODEV-on-attach signature",
		len(errs), matched)

	require.Zerof(t, matched,
		"expected zero 'Error attaching tcx: no such device' errors on the "+
			"TCXManager error channel; got %d (of %d total). Each one is an "+
			"interface that won the lifecycle race against AttachTCX and is "+
			"now permanently uninstrumented (the netlink watcher dedupes "+
			"and will not re-emit EventAdded). All errors: %v",
		matched, len(errs), errs)
}
