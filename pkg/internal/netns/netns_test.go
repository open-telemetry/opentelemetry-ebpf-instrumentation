// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netns

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// threadNetNS reports the network namespace of the thread the caller is pinned to.
func threadNetNS(t *testing.T) string {
	t.Helper()
	link, err := os.Readlink(selfNetNS)
	require.NoError(t, err)
	return link
}

func TestWithNetNSRunsFnInSameNamespace(t *testing.T) {
	outer := threadNetNS(t)

	ran := false
	inner := ""
	require.NoError(t, WithNetNS(os.Getpid(), func() error {
		ran = true
		var err error
		inner, err = os.Readlink(selfNetNS)
		return err
	}))

	assert.True(t, ran, "fn must run when the target namespace is already the current one")
	assert.Equal(t, outer, inner, "the fast path must not switch namespace")
	assert.Equal(t, outer, threadNetNS(t), "caller namespace must be unchanged")
}

func TestWithNetNSPropagatesFnError(t *testing.T) {
	sentinel := errors.New("boom")
	err := WithNetNS(os.Getpid(), func() error { return sentinel })
	require.ErrorIs(t, err, sentinel)
}

// A process that exits between discovery and the switch is the common case in the backfill
// path, and callers key their retry behavior on it being distinguishable.
func TestWithNetNSMissingProcessIsNotExist(t *testing.T) {
	// pid_max is 2^22 on 64-bit, so this can never be live
	err := WithNetNS(1<<23, func() error {
		t.Error("fn must not run when the target namespace cannot be resolved")
		return nil
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestWithNetNSDoesNotLeakTheCallerThreadLock(t *testing.T) {
	// if WithNetNS locked the caller's thread rather than its own, this would deadlock or
	// leave the caller pinned; asserting the goroutine can still be descheduled is the
	// closest observable proxy
	for range 20 {
		require.NoError(t, WithNetNS(os.Getpid(), func() error { return nil }))
		runtime.Gosched()
	}
}

func TestWithNetNSConcurrentCallsAllComplete(t *testing.T) {
	const callers = 32

	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = WithNetNS(os.Getpid(), func() error { return nil })
		}()
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "caller %d", i)
	}
}

func TestSameNetNSDetectsOwnNamespace(t *testing.T) {
	same, err := sameNetNS(netNSPath(os.Getpid()))
	require.NoError(t, err)
	assert.True(t, same)
}

func TestSameNetNSReportsMissingTarget(t *testing.T) {
	_, err := sameNetNS(netNSPath(1 << 23))
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}
